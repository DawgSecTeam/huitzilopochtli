"""POST /enroll handler logic. See architecture.md §9.6, §14.1.

PHASE 1 TASK: implement handle_enroll(). Depends only on engine.store.Store's
signature (task 18) and common.crypto.signing (task 1) — build alongside them.
"""
import base64

from common import canon
from common.crypto import signing
from engine.store import Store


#: Default check-in interval advertised to newly-enrolled boxes. Kept as a
#: module-level constant so engine/server.py (or future config plumbing) can
#: override it without touching this module's logic.
DEFAULT_CHECKIN_INTERVAL_S = 60

#: Required top-level keys in the /enroll request body, per §14.1, and the
#: type each must be.
_REQUIRED_FIELDS = {
    "enrollment_token": str,
    "box_id": str,
    "public_key": str,
    "agent_version": str,
    "scenario_name": str,
}


class EnrollError(Exception):
    """Raised by handle_enroll for any request that must be rejected.

    The HTTP layer (engine/server.py) is expected to catch this and respond
    with `status_code` and `message`. Status codes used here follow §14.1's
    documented error table (400 malformed, 409 already consumed, 410
    expired). An unknown/nonexistent token is also reported as 400 (the
    table lists only 400/409/410 for /enroll; 400 is the natural bucket for
    "the token in the request doesn't correspond to anything valid"), while
    403 is used for a signature that fails verification (proof-of-possession
    failure), consistent with how §14.2 uses 403 for bad signatures.
    """

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def handle_enroll(store: Store, body: dict, sig: bytes) -> dict:
    """Verify the request is signed by the public_key it carries (proof of
    private-key possession), look up the token via store.get_token, and:
      - malformed/unknown token -> raise EnrollError(400, ...)
      - bad signature -> raise EnrollError(403, ...)
      - already consumed -> raise EnrollError(409, ...)
      - expired -> raise EnrollError(410, ...)
      - else: store.create_box(...), store.consume_token(token), and return
        an EnrollResponse-shaped dict {"ok": True, "box_id": ..., "checkin_interval_s": ...}.
    """
    # 1. Validate shape.
    for key, expected_type in _REQUIRED_FIELDS.items():
        if key not in body:
            raise EnrollError(400, f"malformed body: missing {key}")
        if not isinstance(body[key], expected_type):
            raise EnrollError(400, f"malformed body: {key} has wrong type")

    # 2. Verify the signature proves possession of the private key matching
    # the claimed public_key. The signature covers the canonical body.
    try:
        public_key = base64.b64decode(body["public_key"], validate=True)
    except Exception:
        raise EnrollError(400, "malformed body: public_key is not valid base64")

    canonical_bytes = canon.canonicalize(body)
    try:
        signature_ok = signing.verify(public_key, canonical_bytes, sig)
    except Exception:
        signature_ok = False
    if not signature_ok:
        raise EnrollError(403, "bad signature")

    # 3-7. Validate the token, bind box_id -> public_key -> scenario, and
    # consume the token — all atomically inside the Store under a single lock
    # hold. Doing the check-and-mutate in one place closes the TOCTOU where two
    # concurrent /enroll calls with the same one-time token both pass the
    # consumed-check and both create a box (§14.1). The box is bound to the
    # *token's* scenario; a body claiming a different scenario is rejected.
    status = store.enroll_box_atomic(
        body["enrollment_token"],
        body["box_id"],
        body["public_key"],
        body["scenario_name"],
    )
    if status == "unknown_token":
        raise EnrollError(400, "unknown token")
    if status == "scenario_mismatch":
        raise EnrollError(400, "scenario_name does not match the token's scenario")
    if status == "already_consumed":
        raise EnrollError(409, "token already consumed")
    if status == "duplicate_box":
        raise EnrollError(409, "box_id already enrolled")
    if status == "expired":
        raise EnrollError(410, "token expired")
    if status != "ok":
        raise EnrollError(400, f"enrollment failed: {status}")

    # 8. EnrollResponse-shaped confirmation.
    return {
        "ok": True,
        "box_id": body["box_id"],
        "checkin_interval_s": DEFAULT_CHECKIN_INTERVAL_S,
    }
