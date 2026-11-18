"""Post-run box lifecycle: the run-over wall directive (engine.checkin), the
sweeper's timed release after the access window, Extend skipping released
boxes, and auto-end waiting for the last window to close."""
import base64 as b64
import dataclasses
import time
from unittest.mock import patch

import pytest

from common import canon
from common.crypto import signing
from common.schema import Bundle, CollectorStatus, Directive, Evidence, \
    SCHEMA_VERSION
from common.version import AGENT_VERSION
from engine import claims, competition, scenario as scenario_mod
from engine.checkin import handle_checkin, _run_over_message
from engine.store import Store

# One wall-clock anchor all fixtures/tests derive their timestamps from.
T0 = time.time()


# --- fixtures -----------------------------------------------------------------

def _rubric():
    return {
        "schema_version": SCHEMA_VERSION,
        "scenario_name": "PostRun", "scenario_version": 1,
        "entries": [
            {"check_id": "banner", "category": "vuln",
             "matcher": {"tag": "equals", "value": "ok"}, "points": 10,
             "sla": None},
        ],
    }


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _rubric(), {}, [])
    return s


def _comp(store, auto_end=False):
    c = competition.create_competition(
        store, slug="post-run", name="Post Run", scenario_name="PostRun",
        scenario_version=1, max_players=4, duration_s=3600,
        workshop_pool_code=None, auto_end=auto_end)
    store.start_competition(c.id)
    return store.get_competition(c.id)


def _join(store, comp, name="Ada", secret=b"secret"):
    player, code, err = competition.create_player_with_code(
        store, comp, name, secret)
    assert err is None
    priv, pub = signing.keypair()
    body = {
        "join_code": code, "box_id": "box-" + name,
        "public_key": b64.b64encode(pub).decode("ascii"),
        "agent_version": AGENT_VERSION, "scenario_name": "PostRun",
        "scenario_version": 1,
    }
    sig = signing.sign(priv, canon.canonicalize(body))
    status, payload = competition.handle_join(store, body, sig, secret)
    assert status == 200, payload
    return priv, body["box_id"]


def _bundle(box_id, seq, banner="ok"):
    return Bundle(
        box_id=box_id, seq=seq, boot_id="boot", agent_version=AGENT_VERSION,
        scenario_name="PostRun", scenario_version=1,
        evidence=[
            Evidence(check_id="banner", check_type="file_regex",
                     host_id="localhost", status=CollectorStatus.OK,
                     raw={"matched": banner, "present": True}, reason="banner",
                     collected_monotonic=0.0, collected_wall_claim=0.0),
        ],
        created_wall_claim=0.0, schema_version=SCHEMA_VERSION,
    )


def _checkin(store, priv, bundle, now, secret=b"secret"):
    sig = signing.sign(priv, canon.canonicalize(dataclasses.asdict(bundle)))
    with patch("engine.checkin.time.time", return_value=now):
        return handle_checkin(store, bundle, sig, None, secret, None,
                              next_checkin_s=60)


def _bound_player(store, comp, name="Ada", *, status="running",
                  ends_at=None, finished_at=None):
    """A bound player shaped like a bound run at the end of its clock.

    A 'finished' row mirrors the expiry flip: the clock ended 10 minutes
    before the confirming check-in frozen it at T0.
    """
    _priv, box_id = _join(store, comp, name=name)
    if status == "finished" and ends_at is None:
        ends_at = T0 - 600
    elif ends_at is None:
        ends_at = T0 + 3600
    if status == "finished" and finished_at is None:
        finished_at = T0
    store.update_player(store.get_player_by_box(box_id).player_id,
                        status=status, ends_at=ends_at,
                        finished_at=finished_at)
    # handle_join binds the box but does not mint claim bookkeeping; the
    # claim flow leaves claim_uid on the row, which is what a release
    # targets. Put the claim fields on, exactly as the portal claim leaves
    # them for a bound box.
    store.set_player_claim(store.get_player_by_box(box_id).player_id,
                           "http://vm/link", uid="uid-1")
    return store.get_player_by_box(box_id)


# --- run-over wall directive ---------------------------------------------------

def test_first_expired_checkin_walls_the_box(store):
    comp = _comp(store)
    priv, box_id = _join(store, comp)
    player = store.get_player_by_box(box_id)
    r1 = _checkin(store, priv, _bundle(box_id, 1), player.ends_at + 5)
    assert r1.run_status == "finished"
    assert len(r1.directives) == 1
    wall = r1.directives[0]
    assert wall.action == "wall_message"
    assert wall.event_id == f"run-over-{player.player_id}"
    assert "30 more minutes" in wall.params["message"]
    assert "scoring has stopped" in wall.params["message"].lower()
    assert wall.params["access_ends_at"] == pytest.approx(
        player.ends_at + 1800, abs=6)
    fresh = store.get_player_by_box(box_id)
    assert fresh.status == "finished"


def test_wall_never_reissues_and_rides_issued_directives(store):
    comp = _comp(store)
    priv, box_id = _join(store, comp)
    player = store.get_player_by_box(box_id)
    r1 = _checkin(store, priv, _bundle(box_id, 1), player.ends_at + 5)
    assert len(r1.directives) == 1
    # A further check-in on the finished run gets no new wall, but the
    # notice rides issued_directives so a lost first response cannot lose
    # it either (the agent dedups by event_id).
    r2 = _checkin(store, priv, _bundle(box_id, 2), player.ends_at + 10)
    assert r2.directives == []
    assert [d.event_id for d in r2.issued_directives] == \
        [f"run-over-{player.player_id}"]


def test_ended_competition_does_not_wall(store):
    comp = _comp(store)
    priv, box_id = _join(store, comp)
    store.end_competition(comp.id)
    r = _checkin(store, priv, _bundle(box_id, 1), time.time())
    assert r.run_status == "ended"
    assert r.directives == []
    assert r.issued_directives == []


def test_grace_env_visible_in_the_message(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_POST_RUN_GRACE_S", "600")
    comp = _comp(store)
    priv, box_id = _join(store, comp)
    player = store.get_player_by_box(box_id)
    r = _checkin(store, priv, _bundle(box_id, 1), player.ends_at + 5)
    assert "10 more minutes" in r.directives[0].params["message"]


def test_run_over_message_tiny_grace():
    assert "shortly" in _run_over_message(10.0)
    assert "30" in _run_over_message(1800.0)


# --- agent action: wall_message -------------------------------------------------

def test_wall_message_action_executes_wall(monkeypatch):
    import agent.adversary.actions as actions
    from agent.adversary.executor import execute
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)

        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr(actions.shutil, "which", lambda _: "/usr/bin/wall")
    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    execute(Directive(event_id="e", action="wall_message",
                              params={"message": "Scoring has stopped."}),
                    ctx=None)
    assert calls[0] == ["wall", "-n"]


def test_wall_message_action_strips_control_chars(monkeypatch):
    import agent.adversary.actions as actions
    from agent.adversary.executor import execute
    seen = []

    def fake_run(argv, **kw):
        seen.append(kw["input"])

        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr(actions.shutil, "which", lambda _: "/usr/bin/wall")
    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    execute(Directive(event_id="e", action="wall_message",
                              params={"message": "a\x1b[31mb\n\x7fc"}),
                    ctx=None)
    assert "\x1b" not in seen[0] and "\x7f" not in seen[0]
    assert "c" in seen[0]


def test_wall_message_action_tolerates_missing_wall(monkeypatch):
    import agent.adversary.actions as actions
    from agent.adversary.executor import execute
    monkeypatch.setattr(actions.shutil, "which", lambda _: None)
    # No wall binary on the box: stderr notice, never an exception.
    execute(Directive(event_id="e", action="wall_message",
                              params={"message": "Scoring has stopped."}),
                    ctx=None)


def test_wall_message_is_not_scenario_authored():
    from common.adversary import ADVERSARY_ACTIONS
    from agent.adversary.actions import ACTIONS
    # Engine-reserved: the agent accepts it, the compiler forbids it.
    assert "wall_message" in ACTIONS
    assert "wall_message" not in ADVERSARY_ACTIONS


# --- sweeper: timed release ------------------------------------------------------

@pytest.fixture()
def portal_env(monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_SECRET", "s3cret")


@pytest.fixture()
def released_vm(monkeypatch):
    calls = []
    monkeypatch.setattr(claims.workshop, "release_vm",
                        lambda base, uid, timeout=10.0: calls.append(uid))
    return calls


def test_sweep_releases_box_after_grace(store, portal_env, released_vm):
    comp = _comp(store)
    p = _bound_player(store, comp, status="finished")
    # The check-in confirming expiry never arrived in this test; the fixture
    # stamped finished_at = T0 (receipt time of the truthful flip is T0).
    early = claims.sweep(store, b"k", now=T0 + 1200)
    assert released_vm == []
    assert early["released_boxes"] == 0
    ontime = claims.sweep(store, b"k", now=T0 + 1801)
    assert ontime["released_boxes"] == 1
    assert released_vm == ["uid-1"]
    fresh = store.get_player(p.player_id)
    assert fresh.box_released_at is not None
    assert fresh.claim_uid is None and fresh.claim_url is None
    assert fresh.box_id == p.box_id  # binding/history survives the release
    # Idempotent: a later sweep at the same clock does not release again.
    again = claims.sweep(store, b"k", now=T0 + 1900)
    assert again["released_boxes"] == 0
    assert released_vm == ["uid-1"]


def test_sweep_uses_ends_at_for_a_never_confirmed_expiry(
        store, portal_env, released_vm, monkeypatch):
    comp = _comp(store)
    p = _bound_player(store, comp, name="Grace", status="running",
                      ends_at=T0 - 3600, finished_at=None)
    # The check-in confirming expiry never arrived; the clock is the truth.
    monkeypatch.setenv("HUITZILOPOCHTLI_POST_RUN_GRACE_S", "60")
    claims.sweep(store, b"k", now=T0 - 3500)
    assert released_vm == ["uid-1"]
    assert store.get_player(p.player_id).box_released_at is not None


def test_sweep_releases_disqualified_run_after_its_clock(
        store, portal_env, released_vm):
    comp = _comp(store)
    # §7.1: disqualified keeps the box and its clock; after the clock and
    # the window, the box goes back like any other finished run.
    p = _bound_player(store, comp, name="Dq", status="disqualified",
                      finished_at=None)
    claims.sweep(store, b"k", now=p.ends_at + 1801)
    assert released_vm == ["uid-1"]
    assert store.get_player(p.player_id).box_released_at is not None


def test_sweep_release_retries_after_a_portal_error(
        store, portal_env, released_vm, monkeypatch):
    comp = _comp(store)
    p = _bound_player(store, comp, name="Retry", status="finished")
    from engine import workshop as workshop_mod

    def flaky(base, uid, timeout=10.0):
        raise workshop_mod.WorkshopError("portal down")

    monkeypatch.setattr(claims.workshop, "release_vm", flaky)
    borked = claims.sweep(store, b"k", now=T0 + 1801)
    assert borked["release_errors"] == 1
    assert store.get_player(p.player_id).box_released_at is None
    monkeypatch.setattr(claims.workshop, "release_vm",
                        lambda base, uid, timeout=10.0: released_vm.append(uid))
    claims.sweep(store, b"k", now=T0 + 1802)
    assert store.get_player(p.player_id).box_released_at is not None
    assert released_vm == ["uid-1"]


def test_running_with_live_clock_is_not_released(store, portal_env,
                                                 released_vm):
    comp = _comp(store)
    _bound_player(store, comp, name="Live", status="running",
                  ends_at=T0 + 3600, finished_at=None)
    claims.sweep(store, b"k", now=T0 + 61)
    assert released_vm == []


def test_released_player_audit_trail(store, portal_env, released_vm):
    comp = _comp(store)
    p = _bound_player(store, comp, name="Audited", status="finished")
    claims.sweep(store, b"k", now=T0 + 1801)
    audits = [a for a in store.list_audit(limit=50)
              if a.player_id == p.player_id]
    assert any(a.action == "player_box_released" for a in audits)


# --- Extend skips released boxes --------------------------------------------------

def test_extend_skips_a_released_box(store, portal_env, released_vm):
    comp = _comp(store)
    p = _bound_player(store, comp, status="finished")
    store.release_player_box(p.player_id, T0 + 10)
    report = competition.extend_runs(store, comp, 600, now=T0 + 20)
    assert report["skipped"] == [
        {"name": "Ada", "status": "finished", "reason": "box released"}]
    fresh = store.get_player(p.player_id)
    assert fresh.status == "finished"  # never resurrected
    assert fresh.ends_at == p.ends_at  # deadline untouched


def test_extend_still_resumes_an_unreleased_finished_run(store, portal_env):
    comp = _comp(store)
    p = _bound_player(store, comp, status="finished")
    report = competition.extend_runs(store, comp, 600, now=T0 + 20)
    assert [r["player_id"] for r in report["resumed"]] == [p.player_id]
    fresh = store.get_player(p.player_id)
    assert fresh.status == "running"
    assert fresh.finished_at is None


# --- auto-end waits for the window --------------------------------------------------

def test_auto_end_waits_for_the_access_window(store, portal_env, released_vm,
                                              monkeypatch):
    comp = _comp(store, auto_end=True)
    p = _bound_player(store, comp, status="finished")
    store.update_competition(comp.id, join_open=False)
    closed = store.get_competition(comp.id)

    torn = []
    monkeypatch.setattr(claims, "cleanup_pool",
                        lambda s, c: torn.append(c.slug) or
                        {"released": 0, "destroyed": 0, "deleted": True})

    # 5 min after the finish (the historical default grace): the window is
    # still open, so the competition must NOT auto-end and destroy it.
    claims.sweep(store, b"k", now=T0 + 400)
    assert store.get_competition(comp.id).status == "live"
    assert torn == []

    # Past the last window's close (+60s margin): auto-end fires.
    claims.sweep(store, b"k", now=T0 + 1900)
    assert store.get_competition(comp.id).status == "ended"
    assert torn == ["post-run"]
