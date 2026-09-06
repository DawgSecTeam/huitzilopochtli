"""Tests for the hardening pass:
fail-closed manifest verification, identity-file validation, collector
timeout classification, enrollment marker semantics, ranked-loop resilience,
next_checkin_s cadence, rubric matcher-tag validation, schema/agent version
enforcement, and SLA DOWN->UP crediting.
"""
import base64
import json
from unittest.mock import patch

import pytest

import agent.__main__ as agent_main
import agent.identity
from common.canon import canonicalize
from common.crypto import signing
from common.schema import SCHEMA_VERSION


# --- fixtures ----------------------------------------------------------------

@pytest.fixture()
def keypair():
    priv, pub = signing.keypair()
    return priv, pub


def _signed_manifest(priv, tmp_path, **overrides):
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "scenario_name": "sc",
        "scenario_version": 1,
        "mode": "honor",
        "hosts": [],
        "checks": [],
    }
    manifest.update(overrides)
    sig = signing.sign(priv, canonicalize(manifest))
    manifest["_signature"] = base64.b64encode(sig).decode("ascii")
    path = tmp_path / "manifest.signed.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return str(path)


def _key_file(pub, tmp_path):
    path = tmp_path / "authoring_public_key.b64"
    path.write_text(base64.b64encode(pub).decode("ascii"), encoding="utf-8")
    return str(path)


# --- fail-closed manifest verification ----------------------------------------

def test_load_manifest_fails_closed_without_key(tmp_path, keypair):
    priv, pub = keypair
    path = _signed_manifest(priv, tmp_path)
    with pytest.raises(ValueError, match="UNVERIFIED"):
        agent_main._load_manifest(path, None)


def test_load_manifest_allows_unsigned_opt_out(tmp_path, keypair, capsys):
    priv, pub = keypair
    path = _signed_manifest(priv, tmp_path)
    manifest = agent_main._load_manifest(path, None, allow_unsigned=True)
    assert manifest.scenario_name == "sc"
    assert "SKIPPED" in capsys.readouterr().err


def test_load_manifest_verifies_signature(tmp_path, keypair):
    priv, pub = keypair
    path = _signed_manifest(priv, tmp_path)
    manifest = agent_main._load_manifest(path, _key_file(pub, tmp_path))
    assert manifest.scenario_name == "sc"


def test_load_manifest_rejects_tampered_body(tmp_path, keypair):
    priv, pub = keypair
    path = _signed_manifest(priv, tmp_path, scenario_name="original")
    # Tamper after signing.
    data = json.loads(open(path).read())
    data["scenario_name"] = "evil"
    open(path, "w").write(json.dumps(data))
    with pytest.raises(ValueError, match="FAILED signature verification"):
        agent_main._load_manifest(path, _key_file(pub, tmp_path))


def test_load_manifest_rejects_malformed_base64_signature(tmp_path, keypair):
    priv, pub = keypair
    path = _signed_manifest(priv, tmp_path)
    data = json.loads(open(path).read())
    data["_signature"] = "!!!not-base64!!!"
    open(path, "w").write(json.dumps(data))
    with pytest.raises(ValueError):
        agent_main._load_manifest(path, _key_file(pub, tmp_path))


# --- identity file validation ---------------------------------------------------

def _identity_file(tmp_path, priv=None, pub=None, box_id="box-1", last_seq=0):
    if priv is None:
        priv, pub0 = signing.keypair()
    if pub is None:
        pub = signing.public_key_from_private(priv) if priv else b"x" * 32
    data = {
        "box_id": box_id,
        "private_key": base64.b64encode(priv).decode("ascii"),
        "public_key": base64.b64encode(pub).decode("ascii"),
        "last_seq": last_seq,
    }
    path = tmp_path / "identity.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_identity_load_accepts_consistent_file(tmp_path):
    priv, pub = signing.keypair()
    path = _identity_file(tmp_path, priv, pub)
    ident = agent.identity.load_or_create(path)
    assert ident.box_id == "box-1"
    assert ident.last_seq == 0


def test_identity_load_rejects_key_mismatch(tmp_path):
    priv, pub = signing.keypair()
    _priv2, pub2 = signing.keypair()
    path = _identity_file(tmp_path, priv, pub2)
    with pytest.raises(ValueError, match="does not match the private key"):
        agent.identity.load_or_create(path)


def test_identity_load_rejects_bad_length_keys(tmp_path):
    priv, _pub = signing.keypair()
    short = b"x" * 16
    path = _identity_file(tmp_path, priv, short)
    with pytest.raises(ValueError, match="malformed key material"):
        agent.identity.load_or_create(path)


def test_identity_load_rejects_bad_last_seq(tmp_path):
    priv, pub = signing.keypair()
    path = _identity_file(tmp_path, priv, pub, last_seq=-1)
    with pytest.raises(ValueError, match="malformed"):
        agent.identity.load_or_create(path)


# --- collector: a slow-but-finished check keeps its result ---------------------

def test_collector_keeps_result_of_check_that_finishes_after_own_timeout():
    import agent.collector as collector
    import time
    from common.schema import CheckSpec, Category, CollectorStatus, Evidence

    class SlowCheck:
        def collect(self, spec, ctx):
            time.sleep(0.2)  # exceeds its 0.05s timeout_s, finishes anyway
            return Evidence(
                check_id=spec.id, check_type=spec.type, host_id=spec.host_id,
                status=CollectorStatus.OK, raw={"ok": True}, reason="done",
                collected_monotonic=time.monotonic(), collected_wall_claim=time.time(),
            )

    spec = CheckSpec(id="c1", type="_slow", category=Category.VULN, host_id="h",
                     collect_params={}, display_title="t", display_max_points=1,
                     timeout_s=0.05)
    with patch.dict(collector.CHECKS, {"_slow": SlowCheck}):
        results = collector.run_all([spec], ctx=None)
    assert len(results) == 1
    assert results[0].status == CollectorStatus.OK
    assert results[0].raw == {"ok": True}


# --- enrollment marker semantics ------------------------------------------------

class _FakeConfig:
    def __init__(self, tmp_path, token="tok"):
        self.identity_path = str(tmp_path / "identity.json")
        self.enrollment_token = token


class _FakeManifest:
    engine_url = "http://engine.example"
    scenario_name = "sc"
    scenario_version = 1


def test_ensure_enrolled_does_not_write_marker_on_consumed_409(tmp_path, monkeypatch):
    def _consumed(*a, **k):
        raise agent.identity.EnrollmentTokenConsumed("token already consumed")

    monkeypatch.setattr(agent.identity, "enroll", _consumed)
    config = _FakeConfig(tmp_path)
    identity = agent.identity.Identity(
        box_id="b", private_key=b"x" * 32, public_key=b"y" * 32, last_seq=0)

    confirmed = agent_main._ensure_enrolled(config, _FakeManifest(), identity)

    assert confirmed is False
    import os
    assert not os.path.exists(agent_main._enrolled_marker_path(config.identity_path))


def test_ensure_enrolled_reports_fresh_enrollment(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.identity, "enroll", lambda *a, **k: {})
    config = _FakeConfig(tmp_path)
    identity = agent.identity.Identity(
        box_id="b", private_key=b"x" * 32, public_key=b"y" * 32, last_seq=0)

    assert agent_main._ensure_enrolled(config, _FakeManifest(), identity) is True
    # Marker is still deferred until the first CONFIRMED check-in.
    import os
    assert not os.path.exists(agent_main._enrolled_marker_path(config.identity_path))


def test_marker_written_after_confirmed_checkin(tmp_path, monkeypatch):
    import os
    config = _FakeConfig(tmp_path)
    # Simulate the _run_ranked success path: response arrives -> marker.
    agent_main._mark_enrolled(config.identity_path)
    assert os.path.exists(agent_main._enrolled_marker_path(config.identity_path))
    # Idempotent.
    agent_main._mark_enrolled(config.identity_path)


# --- ranked loop resilience + next_checkin_s cadence -----------------------------

class _FakeResponse:
    def __init__(self, directives=(), next_checkin_s=None, server_time=0.0):
        from common.schema import ScoreBreakdown
        self.score = ScoreBreakdown(
            scenario_name="sc", scenario_version=1, total=0,
            results=[], sla_status=[], computed_at=0.0)
        self.directives = list(directives)
        self.next_checkin_s = next_checkin_s
        self.server_time = server_time


class _FakeDirective:
    def __init__(self, action):
        self.event_id = "e1"
        self.action = action


class _FakeClient:
    calls = 0

    def __init__(self, *a, **k):
        pass

    def checkin(self, bundle):
        type(self).calls += 1
        return _FakeResponse(
            directives=[_FakeDirective(action="not_a_real_action")],
            next_checkin_s=123,
        )


class _StopLoop(Exception):
    pass


def test_ranked_loop_survives_bad_directive_and_honors_next_checkin_s(
        tmp_path, monkeypatch):
    """A malformed directive must not kill the loop (§9.1), and the engine's
    next_checkin_s must drive the sleep interval."""
    from common.schema import Mode

    config = _FakeConfig(tmp_path)
    config.report_path = str(tmp_path / "report.html")
    config.checkin_interval_s = 7
    config.mode = Mode.RANKED
    manifest = _FakeManifest()
    manifest.checks = []
    manifest.theme = None

    sleeps = []

    def _fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) >= 2:
            raise _StopLoop  # two cycles are enough

    monkeypatch.setattr(agent_main.agent.transport, "TransportClient", _FakeClient)
    monkeypatch.setattr(agent_main.time, "sleep", _fake_sleep)
    monkeypatch.setattr(agent_main.agent.collector, "run_all", lambda checks, ctx: [])
    monkeypatch.setattr(agent_main, "_ensure_enrolled", lambda *a: False)

    identity = agent.identity.Identity(
        box_id="b", private_key=b"x" * 32, public_key=b"y" * 32, last_seq=0)
    monkeypatch.setattr(agent_main.agent.identity, "load_or_create",
                        lambda path: identity)

    with pytest.raises(_StopLoop):
        agent_main._run_ranked(config, manifest, ctx=None)

    # Cycle 1 slept the engine's next_checkin_s=123, not config's 7.
    assert sleeps[0] == 123
    # A bad directive did not crash the loop (we got to cycle 2), and the
    # report was still rendered.
    assert (tmp_path / "report.html").exists()


# --- transport: parse failure must not queue an accepted bundle ------------------

def _mk_bundle():
    from common.schema import Bundle
    return Bundle(
        box_id="b", seq=8, boot_id="boot", agent_version="0.1.0",
        scenario_name="sc", scenario_version=1, evidence=[],
        created_wall_claim=0.0,
    )


def _queued_line():
    import dataclasses
    from common.canon import canonicalize as c
    return c(dataclasses.asdict(_mk_bundle())).decode("utf-8")


class _FakeIdent:
    box_id = "b"
    private_key = b"x" * 32
    public_key = b"y" * 32
    last_seq = 0


def test_parse_failure_of_new_bundle_not_queued(tmp_path):
    from agent.transport import TransportClient, _ResponseParseFailure

    client = TransportClient("http://engine.example", _FakeIdent(),
                             queue_path=str(tmp_path / "q"))
    with patch.object(client, "_send_canonical",
                      side_effect=_ResponseParseFailure("bad body")):
        result = client.checkin(_mk_bundle())
    assert result is None
    assert not (tmp_path / "q").exists()


def test_flush_response_from_queued_bundle_is_returned(tmp_path):
    """The response to a successfully flushed QUEUED bundle is authoritative:
    it is returned when the new bundle itself can't be sent (network down)."""
    from agent.transport import TransportClient, _NetworkFailure

    q = tmp_path / "q"
    q.write_text(_queued_line())
    client = TransportClient("http://engine.example", _FakeIdent(), queue_path=str(q))

    responses = iter([_FakeResponse(next_checkin_s=123), _NetworkFailure("down")])

    def _send(_bytes):
        r = next(responses)
        if isinstance(r, _NetworkFailure):
            raise r
        return r

    with patch.object(client, "_send_canonical", side_effect=_send):
        result = client.checkin(_mk_bundle())
    assert result is not None
    assert result.next_checkin_s == 123


# --- rubric matcher-tag validation ------------------------------------------------

def test_validate_rubric_rejects_unknown_matcher_tag():
    from common.schema import validate_rubric
    rubric = {
        "schema_version": 1, "scenario_name": "sc", "scenario_version": 1,
        "entries": [
            {"check_id": "c1", "category": "vuln", "points": 5,
             "matcher": {"tag": "no_such_tag", "field": "x", "value": 1}},
        ],
    }
    errors = validate_rubric(rubric)
    assert any("unknown tag" in e for e in errors)


def test_validate_rubric_rejects_ambiguous_shorthand_matcher():
    from common.schema import validate_rubric
    rubric = {
        "schema_version": 1, "scenario_name": "sc", "scenario_version": 1,
        "entries": [
            {"check_id": "c1", "category": "vuln", "points": 5,
             "matcher": {"equals": "no", "contains": "x"}},
        ],
    }
    errors = validate_rubric(rubric)
    assert any("ambiguous" in e for e in errors)


def test_validate_rubric_accepts_resolvable_shorthand_matcher():
    from common.schema import validate_rubric
    rubric = {
        "schema_version": 1, "scenario_name": "sc", "scenario_version": 1,
        "entries": [
            {"check_id": "c1", "category": "vuln", "points": 5,
             "matcher": {"equals": "no"}},
        ],
    }
    assert validate_rubric(rubric) == []


def test_validate_rubric_rejects_sign_inconsistency():
    from common.schema import validate_rubric
    base = {"schema_version": 1, "scenario_name": "sc", "scenario_version": 1}
    bad_vuln = dict(base, entries=[
        {"check_id": "c1", "category": "vuln", "points": -5, "matcher": {"equals": "x"}}])
    bad_penalty = dict(base, entries=[
        {"check_id": "c2", "category": "penalty", "points": 5, "matcher": {"equals": "x"}}])
    assert any("vuln" in e for e in validate_rubric(bad_vuln))
    assert any("penalty" in e for e in validate_rubric(bad_penalty))


# --- bundle version enforcement -----------------------------------------------------

def test_handle_checkin_rejects_incompatible_schema_version():
    from unittest.mock import MagicMock
    from engine.checkin import CheckinError, handle_checkin
    from common.schema import Bundle, Rubric

    store = MagicMock()
    store.get_box.return_value = MagicMock(
        public_key=base64.b64encode(b"y" * 32).decode(),
        scenario_name="sc", scenario_version=1, last_seq=0, t0=None)
    bundle = Bundle(
        box_id="b", seq=1, boot_id="boot", agent_version="0.1.0",
        scenario_name="sc", scenario_version=1, evidence=[],
        created_wall_claim=0.0, schema_version=SCHEMA_VERSION + 1)
    with pytest.raises(CheckinError) as e:
        handle_checkin(store, bundle, b"sig",
                       Rubric(schema_version=1, scenario_name="sc",
                              scenario_version=1, entries=[]),
                       b"secret", [])
    assert "schema_version" in e.value.message


def test_handle_checkin_rejects_incompatible_agent_major_version():
    from unittest.mock import MagicMock
    from engine.checkin import CheckinError, handle_checkin
    from common.schema import Bundle, Rubric

    store = MagicMock()
    store.get_box.return_value = MagicMock(
        public_key=base64.b64encode(b"y" * 32).decode(),
        scenario_name="sc", scenario_version=1, last_seq=0, t0=None)
    bundle = Bundle(
        box_id="b", seq=1, boot_id="boot", agent_version="999.0.0",
        scenario_name="sc", scenario_version=1, evidence=[],
        created_wall_claim=0.0)
    with pytest.raises(CheckinError) as e:
        handle_checkin(store, bundle, b"sig",
                       Rubric(schema_version=1, scenario_name="sc",
                              scenario_version=1, entries=[]),
                       b"secret", [])
    assert "agent_version" in e.value.message


# --- SLA: no credit for the DOWN window on the UP transition -----------------------

def _sla_store(tmp_path):
    from engine.store import Store
    return Store(str(tmp_path / "engine.db"))


def test_sla_no_credit_for_down_window_on_transition_to_up(tmp_path):
    from common.schema import SlaParams
    from engine import sla

    store = _sla_store(tmp_path)
    params = SlaParams(interval_s=10, points_per_interval=1,
                       hysteresis_fail_n=1, hysteresis_ok_n=1)
    # UP at t=0.
    sla.update_sla(store, "b", "c", params, True, 0.0)
    # DOWN at t=100 (50 intervals' worth of wall time must NOT accrue).
    rec = sla.update_sla(store, "b", "c", params, False, 100.0)
    assert rec.state == "DOWN"
    assert rec.accrued_points == 0
    # UP again at t=110: the DOWN window (100s) must not be credited.
    rec = sla.update_sla(store, "b", "c", params, True, 110.0)
    assert rec.state == "UP"
    assert rec.accrued_points == 0  # transition check-in re-anchors, credits nothing
    # From then on, normal accrual resumes.
    rec = sla.update_sla(store, "b", "c", params, True, 130.0)
    assert rec.accrued_points == 2  # (130-110)/10 = 2 intervals
