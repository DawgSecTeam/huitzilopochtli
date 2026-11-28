"""SLA ledger & hysteresis. See architecture.md §11.3."""
import math

from common.schema import SlaParams
from engine.store import SlaStateRecord, Store


def update_sla(store: Store, box_id: str, check_id: str, sla_params: SlaParams,
                 is_up: bool, received_at: float,
                 force_down: bool = False) -> SlaStateRecord:
    """Advance hysteresis state and accrue points (engine clock only).

    ``force_down`` is the adversary outage floor (§12.1): the engine caused the
    outage and knows it started, so hysteresis cannot hold the box UP while an
    issued directive that names this SLA check is still unrestored.
    """
    def _apply(rec):
        if rec is None:
            return SlaStateRecord(
                box_id=box_id,
                check_id=check_id,
                state="DOWN" if (force_down or not is_up) else "UP",
                consec_ok=0 if (force_down or not is_up) else 1,
                consec_fail=(
                    max(1, sla_params.hysteresis_fail_n) if force_down
                    else (0 if is_up else 1)
                ),
                last_credited_at=received_at,
                accrued_points=0,
            )

        if force_down:
            rec.state = "DOWN"
            rec.consec_ok = 0
            rec.consec_fail = max(rec.consec_fail, sla_params.hysteresis_fail_n, 1)
            rec.last_credited_at = received_at
            return rec

        if is_up:
            rec.consec_ok += 1
            rec.consec_fail = 0
        else:
            rec.consec_fail += 1
            rec.consec_ok = 0

        if rec.state == "UP" and rec.consec_fail >= sla_params.hysteresis_fail_n:
            rec.state = "DOWN"
        elif rec.state == "DOWN" and rec.consec_ok >= sla_params.hysteresis_ok_n:
            rec.state = "UP"
            # §11.3: no credit accrues while DOWN — the DOWN window sits in
            # (last_credited_at, received_at), so returning UP re-anchors
            # crediting at now instead of crediting the outage.
            rec.last_credited_at = received_at

        if rec.state == "UP" and sla_params.interval_s > 0:
            elapsed = received_at - rec.last_credited_at
            if elapsed <= 0:
                # The engine clock stepped backwards, or the same instant:
                # never credit and never move the anchor backwards.
                return rec
            eligible = math.floor(elapsed / sla_params.interval_s)
            intervals = min(eligible, sla_params.max_intervals_per_checkin)
            rec.accrued_points += intervals * sla_params.points_per_interval
            if eligible > intervals:
                # §11.3: the cap forfeits a long silence, not merely defers
                # it — keep only the sub-interval remainder, drop the backlog.
                remainder = elapsed - (eligible * sla_params.interval_s)
                rec.last_credited_at = received_at - remainder
            else:
                # Carry the fractional remainder: a cadence that does not
                # divide interval_s still credits fairly.
                rec.last_credited_at += intervals * sla_params.interval_s
        elif rec.state == "DOWN":
            # Freeze the anchor while DOWN so a future UP stretch is credited
            # only from the moment UP resumes.
            rec.last_credited_at = received_at
        return rec

    return store.update_sla_atomic(box_id, check_id, _apply, observed_at=received_at)
