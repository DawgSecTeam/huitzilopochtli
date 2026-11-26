"""Multi-box board aggregation (phase 2b).

Seats are assembled at store level (the join-path fan-out lands in 2d);
what is pinned here is that the board's arithmetic, shape and ranks are
exactly the old single-box behavior when the lineup has one entry, and the
sum of the seat's boxes when it has more.
"""
import time

import pytest

from engine import competition
from engine import scenario as scenario_mod
from engine.store import Store
from common.schema import SCHEMA_VERSION


def _rubric(name, points):
    return {
        "schema_version": SCHEMA_VERSION, "scenario_name": name,
        "scenario_version": 1,
        "entries": [{"check_id": "banner", "category": "vuln",
                     "matcher": {"tag": "equals", "value": "ok"},
                     "points": points, "sla": None},
                    {"check_id": "svc_web", "category": "vuln",
                     "matcher": {"tag": "equals", "value": True,
                                 "field": "open"},
                     "points": 0,
                     "sla": {"interval_s": 1, "points_per_interval": 1,
                             "hysteresis_fail_n": 1, "hysteresis_ok_n": 1,
                             "max_intervals_per_checkin": 3}}],
    }


def _services():
    return [{"id": "web", "check_id": "svc_web", "display": "Web",
             "type": "tcp_port", "interval_s": 1, "points_per_interval": 1}]


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _rubric("BoxA", 10), {}, _services())
    scenario_mod.save_scenario_record(s, _rubric("BoxB", 20), {}, _services())
    return s


def _comp(store, lineup):
    c = competition.create_competition(
        store, slug="mb", name="Multi Box",
        scenario_name=lineup[0][0], scenario_version=lineup[0][1],
        max_players=4, duration_s=3600, scenarios=lineup)
    store.start_competition(c.id)
    return store.get_competition(c.id)


def _seat(store, comp, name, boxes):
    """Seat a player and bind (scenario -> box_id) directly at store level:
    slots + mirrors, like a join/bind fan-out would leave them (2d)."""
    player, _code, err = competition.create_player_with_code(
        store, comp, name, b"secret")
    assert err is None
    lineup = {n: v for n, v in store.get_competition_scenarios(comp.id)}
    store.create_run_slots(player.player_id, comp.id,
                           store.get_competition_scenarios(comp.id))
    primary = None
    for slot in store.list_run_slots(player.player_id):  # lineup order
        box_id = boxes.get(slot.scenario_name)
        if box_id:
            store.create_box(box_id, "pk", slot.scenario_name,
                             scenario_version=lineup[slot.scenario_name])
            store.update_run_slot(slot.slot_id, box_id=box_id,
                                  status="running", bound_at=time.time())
            store.upsert_score(box_id, slot.scenario_name,
                               10 if slot.scenario_name == "BoxA" else 20,
                               hardening_points=9 if slot.scenario_name == "BoxA" else 19,
                               service_points=1)
            if primary is None:
                primary = box_id
    if primary:
        store.update_player(player.player_id, status="running",
                            started_at=time.time(), box_id=primary)
    return store.get_player(player.player_id)


def test_single_box_row_keeps_the_v1_1_shape(store):
    comp = _comp(store, [("BoxA", 1)])
    _seat(store, comp, "Solo", {"BoxA": "bA1"})
    rows = competition.leaderboard_payload(store, comp)["leaderboard"]
    assert len(rows) == 1
    row = rows[0]
    assert "boxes" not in row, "single-box rows must not grow new keys"
    assert row["total"] == 10
    assert row["hardening_points"] == 9 and row["service_points"] == 1
    assert not any("scenario" in s for s in row["services"]), \
        "single-box service rows keep their old shape too"


def test_multi_box_row_totals_are_sums(store):
    comp = _comp(store, [("BoxA", 1), ("BoxB", 1)])
    _seat(store, comp, "Alpha", {"BoxA": "bA1", "BoxB": "bB1"})
    rows = competition.leaderboard_payload(store, comp)["leaderboard"]
    row = rows[0]
    assert row["total"] == 30
    assert row["hardening_points"] == 28 and row["service_points"] == 2
    assert row["forensics_points"] == 0
    # Per-box breakdown appears only for a real lineup.
    assert {b["scenario_name"]: b["total"] for b in row["boxes"]} == \
        {"BoxA": 10, "BoxB": 20}
    # Services fan out over the lineup, labeled, in lineup order.
    scenarios = [s["scenario"] for s in row["services"]]
    assert scenarios == ["BoxA", "BoxB"]
    assert all(s["state"] == "PENDING" for s in row["services"])


def test_partially_bound_seat_counts_only_bound_boxes(store):
    comp = _comp(store, [("BoxA", 1), ("BoxB", 1)])
    _seat(store, comp, "Half", {"BoxA": "bA1"})
    rows = competition.leaderboard_payload(store, comp)["leaderboard"]
    assert rows[0]["total"] == 10
    assert "boxes" in rows[0] and len(rows[0]["boxes"]) == 1
    # The unbound scenario's services still show as PENDING.
    assert [s["scenario"] for s in rows[0]["services"]] == ["BoxA", "BoxB"]


def test_unbound_seat_stays_off_the_board(store):
    comp = _comp(store, [("BoxA", 1), ("BoxB", 1)])
    _seat(store, comp, "Waiting", {})
    rows = competition.leaderboard_payload(store, comp)["leaderboard"]
    assert rows == []


def test_rank_is_the_seat_total_across_both_teams(store):
    comp = _comp(store, [("BoxA", 1), ("BoxB", 1)])
    _seat(store, comp, "Full", {"BoxA": "bA1", "BoxB": "bB1"})       # 30
    _seat(store, comp, "Half", {"BoxB": "bB2"})                      # 20
    rows = competition.leaderboard_payload(store, comp)["leaderboard"]
    by_name = {r["name"]: r for r in rows}
    assert by_name["Full"]["rank"] == 1
    assert by_name["Half"]["rank"] == 2
    # An exact team-total tie shares a rank, per the standard rule.
    _seat(store, comp, "Also", {"BoxA": "bA3", "BoxB": "bB4"})       # 30
    rows = competition.leaderboard_payload(store, comp)["leaderboard"]
    by_name = {r["name"]: r for r in rows}
    assert by_name["Full"]["rank"] == 1 == by_name["Also"]["rank"]
    assert by_name["Half"]["rank"] == 3


def test_rank_for_player_aggregates_for_the_checkin_response(store):
    comp = _comp(store, [("BoxA", 1), ("BoxB", 1)])
    p = _seat(store, comp, "Alpha", {"BoxA": "bA1", "BoxB": "bB1"})
    rank, total = competition.rank_for_player(store, comp, p)
    assert (rank, total) == (1, 1)
