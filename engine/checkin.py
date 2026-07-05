"""POST /checkin handler logic. See architecture.md §14.2.

PHASE 1 TASK: implement handle_checkin(). Depends only on the frozen
signatures of engine.store.Store, common.evaluator.evaluate,
engine.sla (task 21), engine.adversary_oracle (task 22) — not their bodies.
"""
from engine.store import Store
from common.schema import Bundle, CheckinResponse


def handle_checkin(store: Store, rubric_by_scenario: dict, box_id: str,
                    signature: bytes, body: dict) -> CheckinResponse:
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
    raise NotImplementedError
