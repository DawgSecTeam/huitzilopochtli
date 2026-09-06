"""SLA ledger & hysteresis. See architecture.md §11.3."""
import math

from common.schema import SlaParams
from engine.store import SlaStateRecord, Store


def update_sla(store: Store, box_id: str, check_id: str, sla_params: SlaParams,
                 is_up: bool, received_at: float) -> SlaStateRecord:
    """Advance hysteresis state and accrue points (engine clock only)."""
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
            # §11.3: no credit accrues while DOWN. The DOWN window sits in
            # (last_credited_at, received_at), so on the transition back to UP
            # we re-anchor crediting at now instead of crediting the outage.
            rec.last_credited_at = received_at

        if rec.state == "UP" and sla_params.interval_s > 0:
            elapsed = received_at - rec.last_credited_at
            intervals = math.floor(elapsed / sla_params.interval_s)
            if intervals < 0:
                intervals = 0
            intervals = min(intervals, sla_params.max_intervals_per_checkin)
            rec.accrued_points += intervals * sla_params.points_per_interval
            rec.last_credited_at += intervals * sla_params.interval_s
        elif rec.state == "DOWN":
            # Freeze the anchor while DOWN so a future UP stretch is only
            # credited from the moment UP actually resumes.
            rec.last_credited_at = received_at
        return rec

    return store.update_sla_atomic(box_id, check_id, _apply)
