"""Over-the-wire ranked-protocol error-path tests: a real engine subprocess
on 127.0.0.1 probed with hand-crafted signed (and hostile, unsigned) HTTP
requests, the same wire surface agent/identity.py and agent/transport.py use.

Unit tests (tests/unit/test_agent_hardening.py, test_review_hardening.py)
pin the handler logic in-process; this tier pins what actually crosses the
socket -- status codes, last_seq echoes, redaction of rubric expected values
in real response bodies, and the fail-closed check order.

Crypto cost note: every signed enroll/check-in costs ~2s of vendored-Ed25519
CPU on the client plus ~2s of server-side verify, so one engine + one
enrolled box are shared module-wide and seqs are handed out from a single
monotonic counter (engine rejects seq <= last_seq, so every /checkin needs a
fresh seq even when the request is designed to fail later in the chain).
"""
import base64
import http.client
import itertools
import json
import time

import pytest

import test_ranked_loopback as lb
from common import canon
from common.crypto import signing
from common.schema import SCHEMA_VERSION
from common.version import AGENT_VERSION

SECRET = "SECRET_DONT_LEAK_ME_7f3a"


# --------------------------------------------------------------------------
# module-scoped engine + scenario
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    eng = lb._EngineProc(tmp_path_factory.mktemp("proto-engine"))
    yield eng
    eng.stop()


@pytest.fixture(scope="module")
def scenario(engine):
    """Upload one scenario whose second entry's expected value is a greppable
    SECRET marker; returns (name, version)."""
    name = "proto-main"
    engine.upload_scenario(lb._base_rubric(name, [
        {
            "check_id": "backdoor-absent",
            "category": "vuln",
            "matcher": {"tag": "equals", "field": "matched", "value": "no"},
            "points": 10,
        },
        {
            "check_id": "secret-eq",
            "category": "vuln",
            "matcher": {"tag": "equals", "field": "matched", "value": SECRET},
            "points": 5,
        },
    ]))
    return name, 1


@pytest.fixture(scope="module")
def seqs():
    """Monotonic seq source: seq 1 is consumed by the enrolled_box fixture."""
    return itertools.count(start=2)


# --------------------------------------------------------------------------
# raw-request helpers (mirror agent/identity.py + agent/transport.py)
# --------------------------------------------------------------------------

def _post(engine, path, body_bytes, sig=None, headers=None):
    """POST raw bytes; returns (status, parsed_json_or_None, raw_body_text)."""
    hdrs = {"Content-Type": "application/json"}
    if sig is not None:
        hdrs["X-HUITZILOPOCHTLI-Sig"] = base64.b64encode(sig).decode("ascii")
    if headers:
        hdrs.update(headers)
    conn = http.client.HTTPConnection("127.0.0.1", engine.port, timeout=10)
    try:
        conn.request("POST", path, body=body_bytes, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        try:
            return resp.status, json.loads(raw), raw
        except ValueError:
            return resp.status, None, raw
    finally:
        conn.close()


def _post_json(engine, path, obj, **kw):
    return _post(engine, path, json.dumps(obj).encode("utf-8"), **kw)


def _enroll_body(token, box_id, pub, scenario_name, scenario_version):
    return {
        "enrollment_token": token,
        "box_id": box_id,
        "public_key": base64.b64encode(pub).decode("ascii"),
        "agent_version": AGENT_VERSION,
        "scenario_name": scenario_name,
        "scenario_version": scenario_version,
    }


def _enroll(engine, token, scenario_name, scenario_version, keys=None,
            box_id=None, sig=None):
    """Enroll a fresh (or injected) identity; returns (status, parsed, priv)."""
    priv, pub = keys or signing.keypair()
    box_id = box_id or f"proto-{base64.b64encode(pub).decode()[:10]}"
    body = _enroll_body(token, box_id, pub, scenario_name, scenario_version)
    default_sig = signing.sign(priv, canon.canonicalize(body))
    status, parsed, _ = _post_json(engine, "/enroll", body,
                                   sig=sig or default_sig)
    return status, parsed, priv, box_id


def _bundle_dict(box_id, seq, scenario_name, scenario_version, evidence_raw,
                 agent_version=AGENT_VERSION, schema_version=SCHEMA_VERSION,
                 extra_evidence=None):
    """The dict shape of a Bundle (the engine re-hydrates exactly this)."""
    evidence = [
        {
            "check_id": "backdoor-absent",
            "check_type": "file_regex",
            "host_id": "host-1",
            "status": "ok",
            "raw": evidence_raw,
            "reason": "collected by test",
            "collected_monotonic": 0.0,
            "collected_wall_claim": 0.0,
        },
    ]
    if extra_evidence:
        evidence.extend(extra_evidence)
    return {
        "box_id": box_id,
        "seq": seq,
        "boot_id": "boot-proto",
        "agent_version": agent_version,
        "scenario_name": scenario_name,
        "scenario_version": scenario_version,
        "evidence": evidence,
        "created_wall_claim": 0.0,
        "schema_version": schema_version,
    }


def _signed_checkin(engine, priv, body):
    return _post_json(engine, "/checkin", body,
                      sig=signing.sign(priv, canon.canonicalize(body)))


def _secret_evidence():
    return {
        "check_id": "secret-eq",
        "check_type": "file_regex",
        "host_id": "host-1",
        "status": "ok",
        "raw": {"matched": "something-innocuous"},
        "reason": "collected by test",
        "collected_monotonic": 0.0,
        "collected_wall_claim": 0.0,
    }


# --------------------------------------------------------------------------
# enrollment error paths
# --------------------------------------------------------------------------

def test_enroll_unknown_token_400(engine, scenario):
    name, version = scenario
    status, body, _, _ = _enroll(engine, "no-such-token", name, version)
    assert status == 400
    assert "unknown token" in body["error"]


def test_enroll_consumed_token_409(engine, scenario):
    name, version = scenario
    token = engine.mint_token(name)
    status, _, _, _ = _enroll(engine, token, name, version)
    assert status == 200
    status, body, _, _ = _enroll(engine, token, name, version)
    assert status == 409
    assert "consumed" in body["error"]


def test_enroll_expired_token_410(engine, scenario):
    name, version = scenario
    token = engine.mint_token(name, ttl_s=1)
    time.sleep(1.5)
    status, body, _, _ = _enroll(engine, token, name, version)
    assert status == 410
    assert "expired" in body["error"]


def test_enroll_scenario_mismatch_400(engine, scenario):
    name, version = scenario
    status, body, _, _ = _enroll(engine, engine.mint_token(name),
                                 "some-other-scenario", version)
    assert status == 400
    assert "scenario" in body["error"]


def test_enroll_duplicate_box_409(engine, scenario):
    name, version = scenario
    keys = signing.keypair()
    fixed_box_id = "proto-duplicate-box"
    status1, _, _, _ = _enroll(engine, engine.mint_token(name), name, version,
                               keys=keys, box_id=fixed_box_id)
    assert status1 == 200
    status2, body, _, _ = _enroll(engine, engine.mint_token(name), name, version,
                                  keys=keys, box_id=fixed_box_id)
    assert status2 == 409
    assert "already enrolled" in body["error"]


def test_enroll_bad_signature_403(engine, scenario):
    name, version = scenario
    status, body, _, _ = _enroll(engine, engine.mint_token(name), name, version,
                                 sig=b"\x00" * 64)
    assert status == 403
    assert "bad signature" in body["error"]


# --------------------------------------------------------------------------
# the enrolled box: seq 1 confirmed before the check-in cases below
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def enrolled_box(engine, scenario):
    name, version = scenario
    status, _, priv, box_id = _enroll(engine, engine.mint_token(name),
                                      name, version, box_id="proto-main-box")
    assert status == 200
    body = _bundle_dict(box_id, 1, name, version, {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 200, parsed
    assert parsed["last_seq"] == 1
    return priv, box_id


# --------------------------------------------------------------------------
# check-in verification order + replay protection
# --------------------------------------------------------------------------

def test_checkin_unknown_box_403(engine, scenario, seqs):
    name, version = scenario
    priv, _ = signing.keypair()
    body = _bundle_dict("proto-never-enrolled", next(seqs), name, version,
                        {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 403
    assert "unknown box" in parsed["error"]


def test_checkin_unknown_scenario_400(engine, enrolled_box, seqs):
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), "proto-no-such-scenario", 1,
                        {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 400
    assert "unknown scenario" in parsed["error"]


def test_checkin_malformed_bundle_400(engine, enrolled_box):
    priv, box_id = enrolled_box
    status, parsed, _ = _post_json(engine, "/checkin",
                                   {"box_id": box_id, "seq": 1})
    assert status == 400
    assert "malformed bundle" in parsed["error"]


def test_checkin_bad_signature_403(engine, scenario, enrolled_box, seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), name, version, {"matched": "no"})
    status, parsed, _ = _post_json(engine, "/checkin", body, sig=b"\x00" * 64)
    assert status == 403
    assert "bad signature" in parsed["error"]


def test_checkin_replay_409_echoes_last_seq(engine, scenario, enrolled_box,
                                            seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    seq = next(seqs)
    body = _bundle_dict(box_id, seq, name, version, {"matched": "no"})
    canonical = canon.canonicalize(body)
    sig = signing.sign(priv, canonical)
    status, parsed, _ = _post(engine, "/checkin", canonical, sig=sig)
    assert status == 200, parsed
    # Exact replay of the same signed bytes -> 409 with the engine's last_seq.
    status, parsed, _ = _post(engine, "/checkin", canonical, sig=sig)
    assert status == 409
    assert parsed["last_seq"] == seq
    # Stale-but-unseen seq -> same rejection.
    stale = _bundle_dict(box_id, 1, name, version, {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, stale)
    assert status == 409
    assert parsed["last_seq"] == seq


def test_checkin_schema_version_mismatch_400(engine, scenario, enrolled_box,
                                             seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), name, version, {"matched": "no"},
                        schema_version=SCHEMA_VERSION + 999)
    # schema check runs before signature verification, so no valid sig needed.
    status, parsed, _ = _post_json(engine, "/checkin", body, sig=b"\x00" * 64)
    assert status == 400
    assert "schema_version" in parsed["error"]


def test_checkin_agent_major_mismatch_400(engine, scenario, enrolled_box, seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), name, version, {"matched": "no"},
                        agent_version=f"{int(AGENT_VERSION.split('.')[0]) + 1}.9.9")
    status, parsed, _ = _post_json(engine, "/checkin", body, sig=b"\x00" * 64)
    assert status == 400
    assert "agent_version" in parsed["error"]


def test_checkin_scenario_name_mismatch_400(engine, scenario, enrolled_box,
                                            seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), "proto-not-my-scenario", version,
                        {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 400
    assert "scenario" in parsed["error"]


def test_checkin_scenario_version_mismatch_409(engine, scenario, enrolled_box,
                                               seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), name, version + 1,
                        {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 409
    assert "scenario_version" in parsed["error"]


# --------------------------------------------------------------------------
# scoring + answer-key redaction over the wire
# --------------------------------------------------------------------------

def test_checkin_scores_and_redacts_expected_values(engine, scenario,
                                                    enrolled_box, seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), name, version, {"matched": "no"},
                        extra_evidence=[_secret_evidence()])
    status, parsed, raw = _signed_checkin(engine, priv, body)
    assert status == 200, parsed

    results = {r["check_id"]: r for r in parsed["score"]["results"]}
    assert results["backdoor-absent"]["awarded_points"] == 10
    assert results["backdoor-absent"]["passed"] is True
    assert results["secret-eq"]["awarded_points"] == 0
    assert results["secret-eq"]["passed"] is False
    # The failing matcher's reason must be the box's own evidence reason --
    # never the rubric's expected value (§2.4).
    assert results["secret-eq"]["reason"] == "collected by test"
    assert SECRET not in raw, (
        f"engine leaked a rubric expected value over the wire: {raw!r}"
    )
    assert parsed["last_seq"] == body["seq"]
    assert parsed["next_checkin_s"] > 0

    rows = engine.leaderboard(name)
    assert any(r["box_id"] == box_id and r["total"] == 10 for r in rows), rows


# --------------------------------------------------------------------------
# hostile / malformed payloads (no signatures -- must fail cheap and clean)
# --------------------------------------------------------------------------

def test_checkin_oversized_body_400(engine, enrolled_box):
    # Declare a 2 MiB body but send almost nothing: the engine must reject
    # on Content-Length before reading the bytes.
    conn = http.client.HTTPConnection("127.0.0.1", engine.port, timeout=10)
    try:
        conn.request("POST", "/checkin", body=b"x" * 16,
                     headers={"Content-Length": str((1 << 20) + 1)})
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
    finally:
        conn.close()
    assert resp.status == 400
    assert "malformed JSON body" in raw


def test_checkin_non_json_body_400(engine, enrolled_box):
    status, parsed, _ = _post(engine, "/checkin", b"this is not json{{")
    assert status == 400
    assert "malformed JSON body" in parsed["error"]


def test_checkin_json_array_body_400(engine, enrolled_box):
    status, parsed, _ = _post(engine, "/checkin", b"[1, 2, 3]")
    assert status == 400


def test_enroll_non_json_body_400(engine):
    status, parsed, _ = _post(engine, "/enroll", b"{{{not json")
    assert status == 400


def test_checkin_string_seq_is_rejected_cleanly(engine, scenario, enrolled_box,
                                                seqs):
    # PROBE: a JSON seq that isn't an int must be rejected as a 400 malformed
    # bundle, not fall out of the handler as a 500 (or corrupt last_seq
    # semantics with a float). Pre-validation lives in the wire layer.
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, str(next(seqs)), name, version,
                        {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 400, (status, parsed)
    assert "malformed bundle" in parsed["error"]


def test_checkin_float_seq_is_rejected_cleanly(engine, scenario, enrolled_box,
                                               seqs):
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs) + 0.5, name, version,
                        {"matched": "no"})
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 400, (status, parsed)
    assert "malformed bundle" in parsed["error"]


def test_checkin_nan_wall_claim_is_rejected(engine, scenario, enrolled_box,
                                            seqs):
    # PROBE: json.loads accepts NaN and json.dumps emits it, so a NaN in a
    # bundle field sails through canonicalize(). It must never be scored or
    # stored: reject at the wire layer.
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), name, version, {"matched": "no"})
    body["created_wall_claim"] = float("nan")
    status, parsed, _ = _signed_checkin(engine, priv, body)
    assert status == 400, (status, parsed)


def test_box_header_mismatch_rejected(engine, scenario, enrolled_box, seqs):
    """X-HUITZILOPOCHTLI-Box naming a different box than the body is never
    legitimate; the engine rejects it before any signature work."""
    name, version = scenario
    priv, box_id = enrolled_box
    body = _bundle_dict(box_id, next(seqs), name, version, {"matched": "no"})
    status, parsed, _ = _post_json(
        engine, "/checkin", body, sig=b"\x00" * 64,
        headers={"X-HUITZILOPOCHTLI-Box": "some-other-box"})
    assert status == 400
    assert "does not match" in parsed["error"]

    # The matching header (what the real agent sends) is fine -- the request
    # now fails later, at the deliberately-bad signature, not here.
    status, parsed, _ = _post_json(
        engine, "/checkin", body, sig=b"\x00" * 64,
        headers={"X-HUITZILOPOCHTLI-Box": box_id})
    assert status == 403
    assert "bad signature" in parsed["error"]


def test_box_header_mismatch_rejected_on_enroll(engine, scenario):
    name, version = scenario
    priv, pub = signing.keypair()
    body = _enroll_body(engine.mint_token(name), "proto-header-box", pub,
                        name, version)
    status, parsed, _ = _post_json(
        engine, "/enroll", body,
        sig=signing.sign(priv, canon.canonicalize(body)),
        headers={"X-HUITZILOPOCHTLI-Box": "someone-else"})
    assert status == 400
    assert "does not match" in parsed["error"]


# --------------------------------------------------------------------------
# admin surface + GET routing
# --------------------------------------------------------------------------

def test_admin_bad_token_403(engine):
    status, body, _ = _post_json(engine, "/admin/tokens",
                                 {"scenario_name": "proto-main"},
                                 headers={"X-HUITZILOPOCHTLI-Admin-Token": "wrong"})
    assert status == 403


def test_admin_non_ascii_token_403_not_crash(engine):
    # Non-ASCII but latin-1-encodable: http.client refuses CJK header values
    # client-side; the engine's guard is for header bytes it latin-1-decodes.
    status, body, _ = _post_json(engine, "/admin/tokens",
                                 {"scenario_name": "proto-main"},
                                 headers={"X-HUITZILOPOCHTLI-Admin-Token":
                                          "tökén-éè-ü"})
    assert status == 403
    assert "bad admin token" in body["error"]


def test_admin_missing_token_403(engine):
    status, body, _ = _post_json(engine, "/admin/tokens",
                                 {"scenario_name": "proto-main"})
    assert status == 403


def test_admin_nan_ttl_400(engine):
    status, body, _ = _post_json(
        engine, "/admin/tokens",
        {"scenario_name": "proto-main", "ttl_s": float("nan")},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": engine.admin_token})
    assert status == 400


def test_admin_infinite_ttl_400(engine):
    status, body, _ = _post_json(
        engine, "/admin/tokens",
        {"scenario_name": "proto-main", "ttl_s": float("inf")},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": engine.admin_token})
    assert status == 400


def test_admin_zero_ttl_400(engine):
    status, body, _ = _post_json(
        engine, "/admin/tokens", {"scenario_name": "proto-main", "ttl_s": 0},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": engine.admin_token})
    assert status == 400


def test_admin_upload_invalid_rubric_400(engine):
    status, body, _ = _post_json(
        engine, "/admin/scenarios",
        {"rubric": {"schema_version": 1, "scenario_name": "proto-bad",
                    "scenario_version": 1,
                    "entries": [{"check_id": "x", "category": "vuln",
                                 "matcher": {"tag": "no-such-matcher"},
                                 "points": 1}]},
         "adversary": {}},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": engine.admin_token})
    assert status == 400


def test_leaderboard_routing(engine):
    status, body, _ = _post(engine, "/leaderboard", b"")  # wrong verb shape
    assert status in (400, 404, 501)
    conn = http.client.HTTPConnection("127.0.0.1", engine.port, timeout=10)
    try:
        conn.request("GET", "/leaderboard")
        resp = conn.getresponse()
        assert resp.status == 400  # missing scenario param
        conn.request("GET", "/leaderboard?scenario=proto-unknown")
        resp = conn.getresponse()
        assert resp.status == 200
        assert json.loads(resp.read()) == []
        conn.request("GET", "/no-such-path")
        resp = conn.getresponse()
        assert resp.status == 404
    finally:
        conn.close()


def test_admin_disabled_without_token_env(tmp_path_factory):
    eng = lb._EngineProc(tmp_path_factory.mktemp("proto-noadmin"),
                         admin_token="")
    try:
        status, body, _ = _post_json(eng, "/admin/tokens",
                                     {"scenario_name": "x"},
                                     headers={"X-HUITZILOPOCHTLI-Admin-Token":
                                              "whatever"})
        assert status == 503
        assert "disabled" in body["error"]
    finally:
        eng.stop()
