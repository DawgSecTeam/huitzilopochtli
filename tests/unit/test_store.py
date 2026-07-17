"""Tests for engine/store.py's Store class: round-trip behavior of every
public method, backed by a real sqlite3 file per test."""
import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from engine.store import SlaStateRecord, Store


@pytest.fixture
def store():
    path = tempfile.mktemp(suffix=".sqlite3")
    s = Store(path)
    yield s
    try:
        os.remove(path)
    except OSError:
        pass


# --- boxes ------------------------------------------------------------------


def test_create_box_get_box_round_trip(store):
    store.create_box("box-1", "pubkey-abc", "scenario-a")
    rec = store.get_box("box-1")
    assert rec is not None
    assert rec.box_id == "box-1"
    assert rec.public_key == "pubkey-abc"
    assert rec.scenario_name == "scenario-a"
    assert rec.enrolled_at is not None and rec.enrolled_at > 0
    assert rec.last_seq == 0
    assert rec.last_boot_id is None
    assert rec.t0 is None


def test_get_box_unknown_returns_none(store):
    assert store.get_box("does-not-exist") is None


def test_update_box_seq(store):
    store.create_box("box-1", "pubkey", "scenario-a")
    store.update_box_seq("box-1", 5, "boot-123")
    rec = store.get_box("box-1")
    assert rec.last_seq == 5
    assert rec.last_boot_id == "boot-123"


def test_set_t0_if_unset_does_not_overwrite(store):
    store.create_box("box-1", "pubkey", "scenario-a")
    assert store.get_box("box-1").t0 is None

    store.set_t0_if_unset("box-1", 100.0)
    rec = store.get_box("box-1")
    assert rec.t0 == 100.0

    # Second call with a different value must NOT overwrite the first.
    store.set_t0_if_unset("box-1", 200.0)
    rec = store.get_box("box-1")
    assert rec.t0 == 100.0


# --- checkins -----------------------------------------------------------


def test_save_checkin_inserts_audit_row(store):
    store.create_box("box-1", "pubkey", "scenario-a")
    store.save_checkin("box-1", 1, 12345.0, '{"foo": "bar"}')

    cur = store._conn.execute(
        "SELECT box_id, seq, received_at, bundle_json FROM checkins WHERE box_id = ?",
        ("box-1",),
    )
    rows = cur.fetchall()
    assert len(rows) == 1
    assert rows[0]["box_id"] == "box-1"
    assert rows[0]["seq"] == 1
    assert rows[0]["received_at"] == 12345.0
    assert rows[0]["bundle_json"] == '{"foo": "bar"}'


def test_save_checkin_multiple_seqs(store):
    store.create_box("box-1", "pubkey", "scenario-a")
    store.save_checkin("box-1", 1, 1.0, "{}")
    store.save_checkin("box-1", 2, 2.0, "{}")

    cur = store._conn.execute(
        "SELECT seq FROM checkins WHERE box_id = ? ORDER BY seq", ("box-1",)
    )
    seqs = [row["seq"] for row in cur.fetchall()]
    assert seqs == [1, 2]


# --- scores / leaderboard ----------------------------------------------


def test_upsert_score_insert_and_update(store):
    store.upsert_score("box-1", "scenario-a", 50)
    scores = store.get_scores("scenario-a")
    assert len(scores) == 1
    assert scores[0].box_id == "box-1"
    assert scores[0].total == 50

    # Update same box's score: should not create a duplicate row.
    store.upsert_score("box-1", "scenario-a", 75)
    scores = store.get_scores("scenario-a")
    assert len(scores) == 1
    assert scores[0].total == 75


def test_get_scores_ordering_descending(store):
    store.upsert_score("box-low", "scenario-a", 10)
    store.upsert_score("box-high", "scenario-a", 90)
    store.upsert_score("box-mid", "scenario-a", 50)

    scores = store.get_scores("scenario-a")
    assert [s.box_id for s in scores] == ["box-high", "box-mid", "box-low"]
    assert [s.total for s in scores] == [90, 50, 10]


def test_get_scores_ties_break_deterministically_by_updated_at_then_box_id(store):
    # BUG-E4: ORDER BY total DESC alone left tied totals in unspecified order.
    # Ties must now break by earliest updated_at, then box_id, so the
    # leaderboard is reproducible across runs/DB vacuums.
    # Insert so that box_id ascending != updated_at ascending, to prove BOTH
    # tiebreak keys are exercised and neither dominates incorrectly.
    store.upsert_score("box-b", "scenario-a", 50)   # updated_at ~ t0
    store.upsert_score("box-a", "scenario-a", 50)   # updated_at ~ t0 + tiny
    store.upsert_score("box-c", "scenario-a", 50)   # updated_at ~ t0 + 2 tiny

    scores = store.get_scores("scenario-a")
    # All tied on total; earliest updated_at first -> box-b (inserted first).
    assert [s.box_id for s in scores] == ["box-b", "box-a", "box-c"]
    assert [s.total for s in scores] == [50, 50, 50]


def test_get_scores_scoped_to_scenario(store):
    store.upsert_score("box-1", "scenario-a", 10)
    store.upsert_score("box-2", "scenario-b", 20)

    scores_a = store.get_scores("scenario-a")
    assert len(scores_a) == 1
    assert scores_a[0].box_id == "box-1"


def test_get_scores_empty_scenario(store):
    assert store.get_scores("no-such-scenario") == []


# --- sla_state ------------------------------------------------------------


def test_get_sla_state_unknown_returns_none(store):
    assert store.get_sla_state("box-1", "check-1") is None


def test_save_sla_state_round_trip(store):
    rec = SlaStateRecord(
        box_id="box-1",
        check_id="check-1",
        state="UP",
        consec_ok=3,
        consec_fail=0,
        last_credited_at=100.0,
        accrued_points=30,
    )
    store.save_sla_state(rec)

    fetched = store.get_sla_state("box-1", "check-1")
    assert fetched == rec


def test_save_sla_state_updates_not_duplicates(store):
    rec = SlaStateRecord(
        box_id="box-1",
        check_id="check-1",
        state="UP",
        consec_ok=1,
        consec_fail=0,
        last_credited_at=100.0,
        accrued_points=10,
    )
    store.save_sla_state(rec)

    updated = SlaStateRecord(
        box_id="box-1",
        check_id="check-1",
        state="DOWN",
        consec_ok=0,
        consec_fail=2,
        last_credited_at=200.0,
        accrued_points=10,
    )
    store.save_sla_state(updated)

    fetched = store.get_sla_state("box-1", "check-1")
    assert fetched == updated

    cur = store._conn.execute(
        "SELECT COUNT(*) as c FROM sla_state WHERE box_id = ? AND check_id = ?",
        ("box-1", "check-1"),
    )
    assert cur.fetchone()["c"] == 1


def test_save_sla_state_distinct_check_ids_coexist(store):
    rec_a = SlaStateRecord("box-1", "check-a", "UP", 1, 0, 1.0, 5)
    rec_b = SlaStateRecord("box-1", "check-b", "DOWN", 0, 1, 2.0, 0)
    store.save_sla_state(rec_a)
    store.save_sla_state(rec_b)

    assert store.get_sla_state("box-1", "check-a") == rec_a
    assert store.get_sla_state("box-1", "check-b") == rec_b


# --- update_sla_atomic: no lost updates under concurrency (BUG-E3) ----------


def test_update_sla_atomic_concurrent_increments_all_land(store):
    # BUG-E3: the old get_sla_state -> mutate -> save_sla_state sequence held no
    # lock across the read-modify-write, so N concurrent updaters each read the
    # same base value and the last writer clobbered the rest. update_sla_atomic
    # holds the lock for the whole RMW, so every increment must land.
    store.save_sla_state(SlaStateRecord("box-1", "check-a", "UP", 0, 0, 0.0, 0))
    barrier = threading.Barrier(20)

    def bump(rec):
        # NOTE: do NOT wait on the barrier here -- bump runs INSIDE the locked
        # critical section of update_sla_atomic. If it blocked here, the
        # lock-holding thread would wait for 19 others that are themselves
        # blocked acquiring the lock -> deadlock. The barrier is hit before the
        # submit below, outside any lock.
        assert rec is not None
        rec.consec_ok += 1
        rec.accrued_points += 1
        return rec

    def race():
        barrier.wait()  # line up BEFORE entering the locked RMW
        return store.update_sla_atomic("box-1", "check-a", bump)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(race) for _ in range(20)]
        for f in futures:
            f.result()

    rec = store.get_sla_state("box-1", "check-a")
    # If the RMW were non-atomic, lost updates would leave this well below 20.
    assert rec.consec_ok == 20
    assert rec.accrued_points == 20


def test_update_sla_atomic_first_observation_initializes(store):
    # apply_fn receives None for a first-ever (box, check_id) observation.
    seen = []
    def bump(rec):
        seen.append(rec)
        if rec is None:
            return SlaStateRecord("box-new", "check-x", "UP", 1, 0, 99.0, 0)
        rec.consec_ok += 1
        return rec

    out = store.update_sla_atomic("box-new", "check-x", bump)
    assert seen == [None]
    assert out.consec_ok == 1
    assert store.get_sla_state("box-new", "check-x").accrued_points == 0


# --- adversary_log --------------------------------------------------------


def test_get_issued_event_ids_empty(store):
    assert store.get_issued_event_ids("box-1") == set()


def test_log_adversary_event_round_trip(store):
    store.log_adversary_event("box-1", "evt-1", "kill_process", 10.0, {"pid": 42})
    ids = store.get_issued_event_ids("box-1")
    assert ids == {"evt-1"}


def test_log_adversary_event_multiple_per_box(store):
    store.log_adversary_event("box-1", "evt-1", "kill_process", 10.0, {})
    store.log_adversary_event("box-1", "evt-2", "corrupt_file", 20.0, {"path": "/tmp/x"})
    store.log_adversary_event("box-2", "evt-3", "reboot", 30.0, {})

    assert store.get_issued_event_ids("box-1") == {"evt-1", "evt-2"}
    assert store.get_issued_event_ids("box-2") == {"evt-3"}


# --- enrollment_tokens ------------------------------------------------------


def test_get_token_unknown_returns_none(store):
    assert store.get_token("nope") is None


def test_create_token_get_token_round_trip(store):
    store.create_token("tok-1", "scenario-a", 9999.0)
    tok = store.get_token("tok-1")
    assert tok == {
        "scenario_name": "scenario-a",
        "expires_at": 9999.0,
        "consumed_at": None,
    }


def test_consume_token_sets_consumed_at(store):
    store.create_token("tok-1", "scenario-a", 9999.0)
    store.consume_token("tok-1")
    tok = store.get_token("tok-1")
    assert tok is not None
    assert tok["consumed_at"] is not None
    assert tok["consumed_at"] > 0


# --- scenarios ---------------------------------------------------------------


def test_get_scenario_unknown_returns_none(store):
    assert store.get_scenario("no-such-scenario") is None


def test_save_scenario_get_scenario_round_trip(store):
    store.save_scenario("scenario-a", '{"rubric": true}', '{"adversary": true}')
    scen = store.get_scenario("scenario-a")
    assert scen == {
        "rubric_json": '{"rubric": true}',
        "adversary_json": '{"adversary": true}',
        "uploaded_at": scen["uploaded_at"],
    }
    assert scen["uploaded_at"] > 0


def test_save_scenario_updates_not_duplicates(store):
    store.save_scenario("scenario-a", '{"v": 1}', '{"a": 1}')
    store.save_scenario("scenario-a", '{"v": 2}', '{"a": 2}')

    scen = store.get_scenario("scenario-a")
    assert scen["rubric_json"] == '{"v": 2}'
    assert scen["adversary_json"] == '{"a": 2}'

    cur = store._conn.execute(
        "SELECT COUNT(*) as c FROM scenarios WHERE scenario_name = ?", ("scenario-a",)
    )
    assert cur.fetchone()["c"] == 1


# --- engine_meta ---------------------------------------------------------


def test_get_meta_unknown_returns_none(store):
    assert store.get_meta("no-such-key") is None


def test_set_meta_get_meta_round_trip(store):
    store.set_meta("server_secret", "abc123")
    assert store.get_meta("server_secret") == "abc123"


def test_set_meta_updates_not_duplicates(store):
    store.set_meta("k", "v1")
    store.set_meta("k", "v2")
    assert store.get_meta("k") == "v2"

    cur = store._conn.execute(
        "SELECT COUNT(*) as c FROM engine_meta WHERE key = ?", ("k",)
    )
    assert cur.fetchone()["c"] == 1


# --- concurrency smoke test ------------------------------------------------


def test_concurrent_upsert_score_no_deadlock_no_lost_writes(store):
    n_workers = 8

    def write_score(i):
        store.upsert_score(f"box-{i}", "scenario-a", i * 10)
        return i

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        results = list(pool.map(write_score, range(n_workers)))

    assert sorted(results) == list(range(n_workers))

    scores = store.get_scores("scenario-a")
    assert len(scores) == n_workers
    by_box = {s.box_id: s.total for s in scores}
    for i in range(n_workers):
        assert by_box[f"box-{i}"] == i * 10
