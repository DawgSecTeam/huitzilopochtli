import base64
import dataclasses
import json
import time

import pytest

from common import canon
from common.crypto import signing
from common.schema import Bundle, CollectorStatus, Evidence, SCHEMA_VERSION
from common.version import AGENT_VERSION
from engine import competition, scenario as scenario_mod
from engine.checkin import handle_checkin
from engine.store import Store


def _rubric():
    return {
        "schema_version": SCHEMA_VERSION,
        "scenario_name": "TestComp",
        "scenario_version": 1,
        "entries": [
            {"check_id": "banner", "category": "vuln",
             "matcher": {"tag": "equals", "value": "ok"}, "points": 10,
             "sla": None},
            {"check_id": "svc_web", "category": "vuln",
             "matcher": {"tag": "equals", "value": True, "field": "open"},
             "points": 0,
             "sla": {"interval_s": 1, "points_per_interval": 1,
                     "hysteresis_fail_n": 1, "hysteresis_ok_n": 1,
                     "max_intervals_per_checkin": 3}},
        ],
    }


def _services():
    return [{"id": "web", "check_id": "svc_web", "display": "Web",
             "type": "tcp_port", "interval_s": 1, "points_per_interval": 1}]


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _rubric(), {}, _services())
    return s


def _comp(store):
    c = competition.create_competition(
        store, slug="test-comp", name="Test Comp",
        scenario_name="TestComp", scenario_version=1,
        max_players=2, duration_s=3600, workshop_pool_code=None,
    )
    store.start_competition(c.id)
    return store.get_competition(c.id)


def _join(store, comp, name="Ada", code=None, secret=b"secret"):
    player, code, err = competition.create_player_with_code(
        store, comp, name, secret)
    assert err is None
    priv, pub = signing.keypair()
    body = {
        "join_code": code, "box_id": "box-" + name,
        "public_key": base64.b64encode(pub).decode("ascii"),
        "agent_version": AGENT_VERSION, "scenario_name": "TestComp",
        "scenario_version": 1,
    }
    sig = signing.sign(priv, canon.canonicalize(body))
    status, payload = competition.handle_join(store, body, sig, secret)
    assert status == 200, payload
    return priv, body["box_id"], payload


def _bundle(box_id, seq, banner="ok", web=True):
    return Bundle(
        box_id=box_id, seq=seq, boot_id="boot", agent_version=AGENT_VERSION,
        scenario_name="TestComp", scenario_version=1,
        evidence=[
            Evidence(check_id="banner", check_type="file_regex",
                     host_id="localhost", status=CollectorStatus.OK,
                     raw={"matched": banner, "present": True}, reason="banner",
                     collected_monotonic=0.0, collected_wall_claim=0.0),
            Evidence(check_id="svc_web", check_type="tcp_port",
                     host_id="localhost", status=CollectorStatus.OK,
                     raw={"open": web, "error": None}, reason="web",
                     collected_monotonic=0.0, collected_wall_claim=0.0),
        ],
        created_wall_claim=0.0, schema_version=SCHEMA_VERSION,
    )


def _checkin(store, priv, bundle, now, secret=b"secret"):
    from unittest.mock import patch
    sig = signing.sign(priv, canon.canonicalize(dataclasses.asdict(bundle)))
    with patch("engine.checkin.time.time", return_value=now):
        return handle_checkin(store, bundle, sig, None, secret, None,
                              next_checkin_s=60)


def test_join_score_services_and_end(store, monkeypatch):
    comp = _comp(store)
    priv, box_id, payload = _join(store, comp)
    assert payload["player_name"] == "Ada"
    assert payload["run_ends_at"] > time.time()

    r1 = _checkin(store, priv, _bundle(box_id, 1), 1000.0)
    assert r1.score.total == 10
    assert r1.run_status == "running"
    # The ranked report's top bar gets a live position + the event's end.
    assert (r1.rank, r1.rank_total) == (1, 1)
    assert r1.run_ends_at is not None
    # One tick of uptime history rides along with every service status.
    assert r1.score.sla_status[0].history == ["UP"]
    r2 = _checkin(store, priv, _bundle(box_id, 2), 1062.0)
    assert r2.score.total == 13  # 10 hardening + 3 capped service intervals
    assert r2.score.sla_status[0].history == ["UP", "UP"]

    board = competition.leaderboard_payload(store, comp, now=1062.0)
    row = board["leaderboard"][0]
    assert row["name"] == "Ada"
    assert row["hardening_points"] == 10
    assert row["service_points"] == 3
    assert row["services"][0]["state"] == "UP"

    assert store.end_competition(comp.id)
    r3 = _checkin(store, priv, _bundle(box_id, 3), 1063.0)
    assert r3.run_status == "ended"
    assert r3.score.total == 13  # frozen
    # The frozen score keeps the safe SLA state/history (so the report's
    # uptime tab survives the end) but never replays point-in-time results,
    # whose reasons are the answer key.
    assert r3.score.results == []
    assert r3.score.sla_status[0].state == "UP"
    assert r3.score.sla_status[0].history == ["UP", "UP"]
    assert store.get_player_by_box(box_id).status == "finished"


def test_checkin_reports_live_scoreboard_position(store):
    comp = _comp(store)
    priv_a, box_a, _ = _join(store, comp, "Ada")
    priv_b, box_b, _ = _join(store, comp, "Grace")

    # First check-ins: Ada has the banner point, Grace does not. Ada's service
    # is down, so she cannot accrue uptime points and Grace can overtake.
    ra = _checkin(store, priv_a, _bundle(box_a, 1, banner="ok", web=False), 1000.0)
    rb = _checkin(store, priv_b, _bundle(box_b, 1, banner="bad"), 1001.0)
    assert (ra.rank, ra.rank_total) == (1, 2)
    assert (rb.rank, rb.rank_total) == (2, 2)

    # Grace overtakes on a later tick; each response's rank follows the board.
    rb2 = _checkin(store, priv_b, _bundle(box_b, 2, banner="ok"), 1062.0)
    ra2 = _checkin(store, priv_a, _bundle(box_a, 2, banner="ok", web=False), 1063.0)
    assert rb2.rank == 1 and ra2.rank == 2
    assert rb2.rank_total == ra2.rank_total == 2


def test_equal_totals_share_a_rank(store):
    """A tie is a tie: equal totals share a rank, not start-time order."""
    comp = _comp(store)
    priv_a, box_a, _ = _join(store, comp, "Ada")
    priv_b, box_b, _ = _join(store, comp, "Grace")

    ra = _checkin(store, priv_a, _bundle(box_a, 1, web=False), 1000.0)
    rb = _checkin(store, priv_b, _bundle(box_b, 1, web=False), 1001.0)
    assert ra.score.total == rb.score.total == 10
    assert (ra.rank, ra.rank_total) == (1, 2)
    assert (rb.rank, rb.rank_total) == (1, 2)

    board = competition.leaderboard_payload(store, comp, now=1002.0)
    assert [row["rank"] for row in board["leaderboard"]] == [1, 1]
    assert [row["total"] for row in board["leaderboard"]] == [10, 10]


def test_run_expiry_freezes_and_marks_finished(store):
    comp = _comp(store)
    priv, box_id, payload = _join(store, comp)
    store.update_player(store.get_player_by_box(box_id).player_id, ends_at=1000.0)
    r = _checkin(store, priv, _bundle(box_id, 1), 1001.0)
    assert r.run_status == "finished"
    assert store.get_player_by_box(box_id).status == "finished"
    row = competition.leaderboard_payload(store, comp, now=1002.0)["leaderboard"][0]
    assert row["status"] == "finished" and row["remaining_s"] == 0


def test_duplicate_name_and_max_players(store):
    comp = _comp(store)
    p1, _code, err = competition.create_player_with_code(store, comp, "Ada", b"s")
    assert err is None
    p2, _code, err = competition.create_player_with_code(store, comp, "ada", b"s")
    assert p2 is None and "taken" in err
    p3, _code, err = competition.create_player_with_code(store, comp, "Grace", b"s")
    assert err is None
    p4, _code, err = competition.create_player_with_code(store, comp, "Linus", b"s")
    assert p4 is None and "full" in err


def test_join_rejects_bad_and_expired_code(store):
    comp = _comp(store)
    player, code, err = competition.create_player_with_code(store, comp, "Ada", b"s")
    assert err is None
    priv, pub = signing.keypair()
    body = {
        "join_code": "WRONG123", "box_id": "box-x",
        "public_key": base64.b64encode(pub).decode("ascii"),
        "agent_version": AGENT_VERSION, "scenario_name": "TestComp",
        "scenario_version": 1,
    }
    sig = signing.sign(priv, canon.canonicalize(body))
    status, payload = competition.handle_join(store, body, sig, b"s")
    assert status == 403
    body["join_code"] = code
    store.update_player(player.player_id, join_code_expires_at=1.0)
    sig = signing.sign(priv, canon.canonicalize(body))
    status, payload = competition.handle_join(store, body, sig, b"s")
    assert status == 410


def test_active_player_lookup_only_sees_live_competitions(store):
    comp = _comp(store)
    player, _code, err = competition.create_player_with_code(store, comp, "Ada", b"s")
    assert err is None
    found = store.find_active_player_by_name("ada")
    assert found is not None and found.player_id == player.player_id
    assert competition.is_active_player(found, comp)

    store.end_competition(comp.id)
    assert store.find_active_player_by_name("ada") is None
    ended = store.get_player(player.player_id)
    assert not competition.is_active_player(ended, store.get_competition(comp.id))


def test_delete_competition_is_ended_only_and_keeps_boxes(store):
    comp = _comp(store)
    _priv, box_id, _payload = _join(store, comp)
    player = store.get_player_by_box(box_id)
    assert player is not None

    # A live competition cannot be deleted out from under its players.
    assert store.delete_competition(comp.id) is False
    assert store.get_competition(comp.id) is not None

    store.end_competition(comp.id)
    assert store.delete_competition(comp.id) is True
    assert store.get_competition(comp.id) is None
    assert store.get_player(player.player_id) is None
    # Boxes/scores are history and survive a competition removal.
    assert store.get_box(box_id) is not None
