"""SLA ledger & hysteresis. See architecture.md §11.3.

PHASE 1 TASK: implement. Depends only on engine.store.Store's signature.
"""
from common.schema import RubricEntry, SlaStatus
from engine.store import Store


def update_sla(store: Store, box_id: str, received_at: float,
               sla_entry: "RubricEntry", check_passed: bool) -> "SlaStatus":
    """Advance the per-(box_id, check_id) hysteresis state machine:

        UP   --(consec_fail >= fail_n)--> DOWN
        DOWN --(consec_ok   >= ok_n)  --> UP

    Consecutive counters reset on the opposite observation; a single flap
    does not change state.

    Accrual (engine clock only): on entering/continuing UP, credit points for
    floor(elapsed / interval_s) intervals since last_credited_at, capped at
    max_intervals_per_checkin. No credit accrues while DOWN or during gaps.

    Persists the updated SlaStateRecord via store.save_sla_state and returns
    a SlaStatus for inclusion in the ScoreBreakdown.
    """
    raise NotImplementedError
