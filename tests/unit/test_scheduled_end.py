"""Scheduled competition ends: scheduling, the sweeper's auto-End, and the
run clocks / boards that must obey the same wall time.

A scheduled end is engine metadata until the moment fires; the sweeper then
runs the exact admin-End path (every still-running player stops at the
receipt clock, pool torn down). Check-ins between the moment and the sweep
are covered in test_checkin_run_state.py.
"""
import datetime
import json
import time

import pytest

from engine import competition
from engine import scenario as scenario_mod
from engine.store import Store


_RUBRIC = {
    "schema_version": 1,
    "scenario_name": "SchedComp",
    "scenario_version": 1,
    "entries": [{"check_id": "banner", "category": "vuln",
                 "matcher": {"tag": "equals", "value": "ok"}, "points": 10,
                 "sla": None}],
}


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _RUBRIC, {}, [])
    return s


def _comp(store, *, slug="sched-comp", start=True):
    c = competition.create_competition(
        store, slug=slug, name="Sched Comp", scenario_name="SchedComp",
        scenario_version=1, max_players=8, duration_s=3600)
    if start:
        store.start_competition(c.id)
        c = store.get_competition(c.id)
    return c


def _player(store, comp, name="Ada", *, running=True, ends_in=3600, now=None):
    now = time.time() if now is None else now
    player = store.create_player(comp.id, name, name.lower(), f"hash-{name}",
                                 now + 1800)
    if running:
        store.update_player(player.player_id, status="running",
                            started_at=now, ends_at=now + ends_in,
                            box_id=f"box-{name}")
    return store.get_player(player.player_id)


# --- parse + schedule ---------------------------------------------------------


def test_parse_accepts_datetime_local_and_space_forms():
    now = time.time()
    naive = datetime.datetime.now().replace(second=0, microsecond=0)
    expected = naive.timestamp() + 3600
    for raw in ((naive + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
                (naive + datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M"),
                (naive + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")):
        parsed = competition.parse_scheduled_end(raw, now)
        # Same wall-clock minute (the seconds field is not always carried).
        assert abs(parsed - expected) < 60


def test_parse_rejects_garbage_past_and_far_future():
    now = time.time()
    with pytest.raises(competition.ScheduleRefused):
        competition.parse_scheduled_end("", now)
    with pytest.raises(competition.ScheduleRefused):
        competition.parse_scheduled_end("not-a-time", now)
    past = (datetime.datetime.now() - datetime.timedelta(hours=1)
            ).strftime("%Y-%m-%dT%H:%M")
    with pytest.raises(competition.ScheduleRefused):
        competition.parse_scheduled_end(past, now)
    far = (datetime.datetime.now() + datetime.timedelta(days=40)
           ).strftime("%Y-%m-%dT%H:%M")
    with pytest.raises(competition.ScheduleRefused):
        competition.parse_scheduled_end(far, now)


def test_schedule_end_sets_and_clears(store):
    comp = _comp(store)
    when = time.time() + 7200
    updated = competition.schedule_end(store, comp, when)
    assert updated.scheduled_end_at == when
    cleared = competition.schedule_end(store, updated, None)
    assert cleared.scheduled_end_at is None


def test_schedule_end_refuses_ended_and_past(store):
    comp = _comp(store)
    with pytest.raises(competition.ScheduleRefused):
        competition.schedule_end(store, comp, time.time() - 10)
    store.end_competition(comp.id)
    comp = store.get_competition(comp.id)
    with pytest.raises(competition.ScheduleRefused):
        competition.schedule_end(store, comp, time.time() + 7200)


# --- the sweeper's auto-End ---------------------------------------------------


def test_sweep_ends_due_competition_and_stops_its_runs(store):
    now = time.time()
    comp = _comp(store)
    running = _player(store, comp, "Ada", now=now)
    _player(store, comp, "Bob", now=now, running=False)  # invited: no clock
    comp = competition.schedule_end(store, comp, now + 60)

    cleanups = []
    ended = competition.sweep_scheduled_ends(
        store, now=now + 30, cleanup=lambda s, c: cleanups.append(c) or {})
    assert ended == []  # not due yet
    assert store.get_competition(comp.id).status == "live"

    ended = competition.sweep_scheduled_ends(
        store, now=now + 120, cleanup=lambda s, c: cleanups.append(c) or {})
    assert [e["slug"] for e in ended] == [comp.slug]
    assert [c.id for c in cleanups] == [comp.id]

    done = store.get_competition(comp.id)
    assert done.status == "ended" and done.ended_at is not None
    ada = store.get_player(running.player_id)
    assert ada.status == "finished" and ada.finished_at is not None
    assert ada.ends_at <= now + 120  # run stopped at the receipt clock
    actions = [r.action for r in store.list_audit()]
    assert "competition_scheduled_end" in actions


def test_sweep_leaves_future_draft_and_ended_alone(store):
    now = time.time()
    live = competition.schedule_end(store, _comp(store, slug="live-one"),
                                    now + 7200)
    draft = _comp(store, slug="draft-one", start=False)
    # A stale schedule on a never-started draft (planted directly: the API
    # refuses past times).
    store.update_competition(draft.id, scheduled_end_at=now - 10)
    ended = _comp(store, slug="ended-one")
    store.end_competition(ended.id)
    store.update_competition(ended.id, scheduled_end_at=now - 10)

    assert competition.sweep_scheduled_ends(store, now=now + 3600) == []
    assert store.get_competition(live.id).status == "live"
    assert store.get_competition(draft.id).status == "draft"
    assert store.get_competition(ended.id).status == "ended"


def test_sweep_survives_a_failing_cleanup(store):
    now = time.time()
    comp = _comp(store)
    store.update_competition(comp.id, scheduled_end_at=now - 10)

    def boom(store_, comp_):
        raise RuntimeError("portal down")

    ended = competition.sweep_scheduled_ends(store, now=now, cleanup=boom)
    assert [e["slug"] for e in ended] == [comp.slug]
    assert "pool_error" in ended[0]
    # The competition itself is still ended: the VM work retries elsewhere.
    assert store.get_competition(comp.id).status == "ended"


# --- boards and payloads obey the same wall time ------------------------------


def test_leaderboard_caps_remaining_and_flips_status_at_scheduled_end(store):
    now = time.time()
    comp = _comp(store)
    player = _player(store, comp, "Ada", now=now, ends_in=3600)
    comp = competition.schedule_end(store, comp, now + 600)

    board = competition.leaderboard_payload(store, comp, now=now + 60)
    row = board["leaderboard"][0]
    assert row["player_id"] == player.player_id
    assert row["status"] == "running"
    assert row["remaining_s"] == 540  # capped at the scheduled end

    # Past the scheduled moment (before the sweep persisted the end) the run
    # reads as finished with nothing left on the clock.
    board = competition.leaderboard_payload(store, comp, now=now + 700)
    row = board["leaderboard"][0]
    assert row["status"] == "finished" and row["remaining_s"] == 0


def test_public_payload_carries_the_schedule(store):
    comp = _comp(store)
    assert competition.public_competition_payload(store, comp)[
        "scheduled_end_at"] is None
    when = time.time() + 600
    comp = competition.schedule_end(store, comp, when)
    assert competition.public_competition_payload(store, comp)[
        "scheduled_end_at"] == when


def test_effective_run_end_prefers_the_earlier_deadline(store):
    now = time.time()
    comp = _comp(store)
    player = _player(store, comp, "Ada", now=now, ends_in=3600)
    assert competition.effective_run_end(comp, player) == now + 3600
    comp = competition.schedule_end(store, comp, now + 600)
    assert competition.effective_run_end(comp, player) == now + 600
    # An ended competition no longer reschedules anything: the freeze won.
    store.end_competition(comp.id)
    comp = store.get_competition(comp.id)
    player = store.get_player(player.player_id)
    assert competition.effective_run_end(comp, player) == comp.ended_at
