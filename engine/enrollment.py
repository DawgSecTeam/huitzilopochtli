"""POST /enroll handler logic. See architecture.md §9.6, §14.1.

PHASE 1 TASK: implement handle_enroll(). Depends only on engine.store.Store's
signature (task 18) and common.crypto.signing (task 1) — build alongside them.
"""
from engine.store import Store


def handle_enroll(store: Store, body: dict, signature: bytes) -> dict:
    """Verify the request is signed by the public_key it carries (proof of
    private-key possession), look up the token via store.get_token, and:
      - unknown/malformed token -> raise Http400
      - already consumed -> raise Http409
      - expired -> raise Http410
      - else: store.create_box(...), store.consume_token(token), and return
        an EnrollResponse-shaped dict {"ok": True, "box_id": ..., "checkin_interval_s": ...}.
    """
    raise NotImplementedError
