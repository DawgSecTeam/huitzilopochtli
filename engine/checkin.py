"""POST /checkin handler logic. See architecture.md §14.2.

PHASE 1 TASK: implement handle_checkin(). Depends only on the frozen
signatures of engine.store.Store, common.evaluator.evaluate,
engine.sla (task 21), engine.adversary_oracle (task 22), common.crypto.signing,
and common.canon — not necessarily their bodies (they may still raise
NotImplementedError while built in parallel).
"""
import base64
import dataclasses
import json
import time

import engine.sla as sla
import engine.adversary_oracle as adversary_oracle
from common import canon
from common.crypto import signing
from common.evaluator import evaluate
from common.matchers import evaluate_matcher
from common.schema import Bundle, CheckinResponse, Rubric, SlaStatus
from engine.store import Store


class CheckinError(Exception):
    """Raised by handle_checkin() on any fail-closed verification step.

    The HTTP layer is expected to catch this and map status_code/message
    (and last_seq, when present) onto the wire response.
    """

    def __init__(self, status_code, message, last_seq=None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.last_seq = last_seq


class _Clock:
    """Trivial Clock (see common.evaluator.Clock protocol) fixed to the
    engine's authoritative received_at for this check-in."""

    def __init__(self, received_at: float):
        self._received_at = received_at

    def now(self) -> float:
        return self._received_at


def handle_checkin(store: Store, bundle: Bundle, sig: bytes, rubric: Rubric,
                    server_secret: bytes, event_pool: list) -> CheckinResponse:
    """Fail-closed handler order (§14.2):
      1. Look up box_id -> public key. Unknown box -> 403.
      2. Verify signature over the canonical body. Bad signature -> 403.
      3. Reject seq <= last_seq (replay/dedup) -> 409 with last_seq.
      4. Stamp received_at = engine_now(). First check-in for this box sets T0.
      5. Persist the check-in (audit log) via store.save_checkin.
      6. Evaluate point-in-time evidence against the engine-held rubric
         (common.evaluator.evaluate).
      7. Update SLA ledger (engine.sla).
      8. Run adversary scheduler; collect any due directives (engine.adversary_oracle).
      9. Update scores.total (store.upsert_score); return the CheckinResponse.
    """
    # 1. Look up box_id -> public key. Unknown box -> 403.
    box = store.get_box(bundle.box_id)
    if box is None:
        raise CheckinError(403, "unknown box")

    # 2. Verify signature over the canonical body. Bad signature -> 403.
    canonical_bytes = canon.canonicalize(dataclasses.asdict(bundle))
    public_key = base64.b64decode(box.public_key)
    if not signing.verify(public_key, canonical_bytes, sig):
        raise CheckinError(403, "bad signature")

    # 3. Reject seq <= last_seq (replay/dedup) -> 409 with last_seq.
    if bundle.seq <= box.last_seq:
        raise CheckinError(409, "replay/stale seq", last_seq=box.last_seq)

    # 4. Stamp received_at = engine_now(). First check-in for this box sets T0.
    received_at = time.time()
    if box.t0 is None:
        store.set_t0_if_unset(bundle.box_id, received_at)
        t0_to_use = received_at
    else:
        t0_to_use = box.t0
    store.update_box_seq(bundle.box_id, bundle.seq, bundle.boot_id)

    # 5. Persist the check-in (audit log).
    store.save_checkin(
        bundle.box_id,
        bundle.seq,
        received_at,
        json.dumps(dataclasses.asdict(bundle), default=str),
    )

    # 6. Evaluate point-in-time evidence against the engine-held rubric.
    clock = _Clock(received_at)
    score = evaluate(bundle.evidence, rubric, clock)

    # 7. Update SLA ledger (§11.3) for every rubric entry that has SLA params.
    evidence_by_check_id = {e.check_id: e for e in bundle.evidence}
    sla_statuses = []
    sla_accrued_total = 0
    for entry in rubric.entries:
        if entry.sla is None:
            continue
        ev = evidence_by_check_id.get(entry.check_id)
        raw = ev.raw if ev is not None else {}
        is_up, _reason = evaluate_matcher(entry.matcher, raw)
        sla_rec = sla.update_sla(
            store, bundle.box_id, entry.check_id, entry.sla, is_up, received_at
        )
        sla_statuses.append(
            SlaStatus(
                check_id=sla_rec.check_id,
                state=sla_rec.state,
                accrued_points=sla_rec.accrued_points,
            )
        )
        sla_accrued_total += sla_rec.accrued_points
    score.sla_status = sla_statuses

    # 8. Run adversary scheduler; collect any due directives (§12.1).
    directives = adversary_oracle.due_directives(
        store, bundle.box_id, server_secret, event_pool, t0_to_use, received_at
    )

    # 9. Update scores.total; return the response.
    #
    # Per §11.4, "Point-in-time totals + accrued SLA points + adversary
    # penalties are summed". This v1 build has no separate adversary
    # penalty ledger beyond the rubric itself: adversary directives change
    # the box's real-world state, and any resulting penalty is expected to
    # be picked up by ordinary rubric matchers (PENALTY/PROHIBITED entries)
    # observing that state on a later check-in's evaluate() pass (step 6
    # above) — NOT as a separate additive term here. So the only explicit
    # addition beyond evaluate()'s point-in-time total is accrued SLA points.
    final_total = score.total + sla_accrued_total
    score.total = final_total

    store.upsert_score(bundle.box_id, rubric.scenario_name, final_total)

    return CheckinResponse(
        server_time=received_at,
        score=score,
        directives=directives,
        next_checkin_s=60,
        last_seq=bundle.seq,
    )
