"""SLA ledger & hysteresis. See architecture.md §11.3.

PHASE 1 TASK: implement. Depends only on engine.store.Store's signature.
"""
import math

from common.schema import SlaParams
from engine.store import SlaStateRecord, Store


def update_sla(store: Store, box_id: str, check_id: str, sla_params: SlaParams,
                is_up: bool, received_at: float) -> SlaStateRecord:
    """Advance the per-(box_id, check_id) hysteresis state machine:

        UP   --(consec_fail >= fail_n)--> DOWN
        DOWN --(consec_ok   >= ok_n)  --> UP

    Consecutive counters reset on the opposite observation; a single flap
    does not change state.

    Accrual (engine clock only): on entering/continuing UP, credit points for
    floor(elapsed / interval_s) intervals since last_credited_at, capped at
    max_intervals_per_checkin. No credit accrues while DOWN or during gaps;
    while DOWN, last_credited_at is advanced to received_at so a later UP
    transition does not retroactively credit the DOWN period.

    Persists the updated SlaStateRecord via store.save_sla_state and returns
    it.

    Invariant: only `received_at` (the engine's receipt timestamp) is ever
    used for timing; the box's self-reported clock never influences accrual.
    """
    def _apply(rec):
        if rec is None:
            # First-ever observation for this (box, check_id): initialize state
            # from the single observation, no elapsed interval to credit yet.
            return SlaStateRecord(
                box_id=box_id,
                check_id=check_id,
                state="UP" if is_up else "DOWN",
                consec_ok=1 if is_up else 0,
                consec_fail=0 if is_up else 1,
                last_credited_at=received_at,
                accrued_points=0,
            )

        # Update consecutive counters.
        if is_up:
            rec.consec_ok += 1
            rec.consec_fail = 0
        else:
            rec.consec_fail += 1
            rec.consec_ok = 0

        # Hysteresis transition.
        if rec.state == "UP" and rec.consec_fail >= sla_params.hysteresis_fail_n:
            rec.state = "DOWN"
        elif rec.state == "DOWN" and rec.consec_ok >= sla_params.hysteresis_ok_n:
            rec.state = "UP"

        # Accrual, using the (possibly just-transitioned) new state.
        if rec.state == "UP" and sla_params.interval_s > 0:
            # interval_s <= 0 is a malformed rubric (validate_rubric rejects it at
            # authoring/upload time); guard here too so a bad record already in the
            # DB can't divide-by-zero mid-check-in and crash after partial state has
            # been persisted. No accrual for a non-positive interval.
            elapsed = received_at - rec.last_credited_at
            intervals = math.floor(elapsed / sla_params.interval_s)
            if intervals < 0:
                intervals = 0
            intervals = min(intervals, sla_params.max_intervals_per_checkin)
            rec.accrued_points += intervals * sla_params.points_per_interval
            rec.last_credited_at += intervals * sla_params.interval_s
        else:
            rec.last_credited_at = received_at
        return rec

    # The whole read-modify-write runs under Store's lock (update_sla_atomic),
    # so two concurrent check-ins for the same (box_id, check_id) cannot
    # interleave their get/mutate/save and clobber each other's accrual or
    # consecutive counters.
    return store.update_sla_atomic(box_id, check_id, _apply)
