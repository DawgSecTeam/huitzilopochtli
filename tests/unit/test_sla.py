"""Tests for engine/sla.py: update_sla hysteresis + accrual logic."""
import os
import tempfile

import pytest

from common.schema import SlaParams
from engine.sla import update_sla
from engine.store import Store


@pytest.fixture
def store():
    path = tempfile.mktemp(suffix=".db")
    s = Store(path)
    yield s
    try:
        os.remove(path)
    except OSError:
        pass


def make_params(interval_s=60, points_per_interval=1, hysteresis_fail_n=2,
                hysteresis_ok_n=2, max_intervals_per_checkin=3):
    return SlaParams(
        interval_s=interval_s,
        points_per_interval=points_per_interval,
        hysteresis_fail_n=hysteresis_fail_n,
        hysteresis_ok_n=hysteresis_ok_n,
        max_intervals_per_checkin=max_intervals_per_checkin,
    )


def test_first_call_up_initializes_no_accrual(store):
    params = make_params()
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)

    assert rec.box_id == "box1"
    assert rec.check_id == "check1"
    assert rec.state == "UP"
    assert rec.consec_ok == 1
    assert rec.consec_fail == 0
    assert rec.last_credited_at == 1000.0
    assert rec.accrued_points == 0


def test_first_call_down_initializes_no_accrual(store):
    params = make_params()
    rec = update_sla(store, "box1", "check1", params, is_up=False, received_at=1000.0)

    assert rec.state == "DOWN"
    assert rec.consec_ok == 0
    assert rec.consec_fail == 1
    assert rec.last_credited_at == 1000.0
    assert rec.accrued_points == 0


def test_sequential_up_accrues_points_per_interval(store):
    params = make_params(interval_s=60, points_per_interval=5,
                          max_intervals_per_checkin=100)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)

    # 60s later -> exactly 1 interval elapsed.
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1060.0)
    assert rec.state == "UP"
    assert rec.accrued_points == 5
    assert rec.last_credited_at == 1060.0

    # another 120s later -> 2 more intervals elapsed.
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1180.0)
    assert rec.state == "UP"
    assert rec.accrued_points == 5 + 2 * 5
    assert rec.last_credited_at == 1180.0


def test_single_flap_does_not_flip_state(store):
    params = make_params(hysteresis_fail_n=2, hysteresis_ok_n=2)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1060.0)
    assert rec.state == "UP"

    # A single failure should not flip UP -> DOWN since hysteresis_fail_n=2.
    rec = update_sla(store, "box1", "check1", params, is_up=False, received_at=1120.0)
    assert rec.state == "UP"
    assert rec.consec_fail == 1
    assert rec.consec_ok == 0


def test_two_consecutive_fails_flip_to_down_and_stop_accrual(store):
    params = make_params(interval_s=60, points_per_interval=5,
                          hysteresis_fail_n=2, max_intervals_per_checkin=100)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1060.0)

    rec = update_sla(store, "box1", "check1", params, is_up=False, received_at=1120.0)
    assert rec.state == "UP"  # only one fail so far
    points_before_down = rec.accrued_points

    rec = update_sla(store, "box1", "check1", params, is_up=False, received_at=1180.0)
    assert rec.state == "DOWN"
    assert rec.consec_fail == 2
    # No further accrual should have happened on the transitioning call, nor
    # since — state now uses the *new* state (DOWN) for accrual decisions.
    assert rec.accrued_points == points_before_down

    # Even with a big time jump while still failing, no accrual while DOWN.
    rec = update_sla(store, "box1", "check1", params, is_up=False, received_at=10000.0)
    assert rec.state == "DOWN"
    assert rec.accrued_points == points_before_down
    # watermark jumps straight to received_at while DOWN.
    assert rec.last_credited_at == 10000.0


def test_recovery_after_hysteresis_ok_n_resumes_accrual(store):
    params = make_params(interval_s=60, points_per_interval=5,
                          hysteresis_fail_n=2, hysteresis_ok_n=2,
                          max_intervals_per_checkin=100)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)
    update_sla(store, "box1", "check1", params, is_up=False, received_at=1060.0)
    rec = update_sla(store, "box1", "check1", params, is_up=False, received_at=1120.0)
    assert rec.state == "DOWN"

    # First OK observation while DOWN: not enough to recover yet (ok_n=2).
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1180.0)
    assert rec.state == "DOWN"
    assert rec.consec_ok == 1
    down_points = rec.accrued_points
    # last_credited_at should have been advanced to this received_at (still DOWN).
    assert rec.last_credited_at == 1180.0

    # Second consecutive OK observation: recovers to UP, but no elapsed
    # interval to credit yet since last_credited_at was just reset to 1180.
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1200.0)
    assert rec.state == "UP"
    assert rec.consec_ok == 2
    assert rec.accrued_points == down_points  # only 20s elapsed, < interval_s
    assert rec.last_credited_at == 1180.0

    # Now accrual resumes normally while UP.
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1240.0)
    assert rec.state == "UP"
    # elapsed = 1240 - 1180 = 60s -> exactly 1 interval.
    assert rec.accrued_points == down_points + 5
    assert rec.last_credited_at == 1240.0


def test_max_intervals_per_checkin_caps_credit(store):
    params = make_params(interval_s=60, points_per_interval=5,
                          max_intervals_per_checkin=3)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)

    # Huge jump: 1000 intervals' worth of elapsed time, but capped at 3.
    rec = update_sla(store, "box1", "check1", params, is_up=True,
                      received_at=1000.0 + 1000 * 60)
    assert rec.state == "UP"
    assert rec.accrued_points == 3 * 5
    # watermark only advances by the credited (capped) intervals, not all
    # the way to received_at.
    assert rec.last_credited_at == 1000.0 + 3 * 60


def test_watermark_carries_fractional_leftover_while_up(store):
    params = make_params(interval_s=60, points_per_interval=5,
                          max_intervals_per_checkin=100)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)

    # 90s elapsed -> only 1 full interval credited; 30s leftover carries over.
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1090.0)
    assert rec.accrued_points == 5
    assert rec.last_credited_at == 1060.0  # 1000 + 1*60, not 1090

    # Another 30s (total 60s since last_credited_at=1060) -> 1 more interval.
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1120.0)
    assert rec.accrued_points == 10
    assert rec.last_credited_at == 1120.0


def test_watermark_jumps_to_received_at_while_down(store):
    params = make_params(interval_s=60, points_per_interval=5,
                          hysteresis_fail_n=1, max_intervals_per_checkin=100)
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)

    # hysteresis_fail_n=1, so a single fail flips state to DOWN immediately.
    rec = update_sla(store, "box1", "check1", params, is_up=False, received_at=1500.0)
    assert rec.state == "DOWN"
    assert rec.last_credited_at == 1500.0

    # Later, recover to UP (ok_n default 2) — the DOWN period must not be
    # retroactively credited.
    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1550.0)
    assert rec.state == "DOWN"  # only 1 consecutive ok so far
    assert rec.last_credited_at == 1550.0

    rec = update_sla(store, "box1", "check1", params, is_up=True, received_at=1600.0)
    assert rec.state == "UP"
    # elapsed since last_credited_at (1550) is only 50s < interval_s -> no credit yet.
    assert rec.accrued_points == 0
    assert rec.last_credited_at == 1550.0


# --- concurrency: update_sla must not lose updates (BUG-E3) ----------------


def test_update_sla_consecutive_counter_survives_concurrent_updaters(store):
    """Two threads calling update_sla for the same (box, check) concurrently
    must both increment consec_ok -- the old unlocked get/mutate/save sequence
    lost one update under this exact race. update_sla now delegates to
    Store.update_sla_atomic, which holds the lock across the whole RMW."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    params = SlaParams(interval_s=100, points_per_interval=1)
    # First observation seeds consec_ok=1.
    update_sla(store, "box1", "check1", params, is_up=True, received_at=1000.0)

    barrier = threading.Barrier(8)

    def one_up():
        barrier.wait()  # line up BEFORE entering the locked RMW (else deadlock)
        update_sla(store, "box1", "check1", params, is_up=True, received_at=1001.0)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: one_up(), range(8)))

    # If the RMW were non-atomic, lost updates would leave this below 9.
    rec = store.get_sla_state("box1", "check1")
    assert rec.consec_ok == 9
