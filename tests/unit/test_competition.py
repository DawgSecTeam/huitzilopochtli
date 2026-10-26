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
    r2 = _checkin(store, priv, _bundle(box_id, 2), 1062.0)
    assert r2.score.total == 13  # 10 hardening + 3 capped service intervals

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
    assert store.get_player_by_box(box_id).status == "finished"


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
