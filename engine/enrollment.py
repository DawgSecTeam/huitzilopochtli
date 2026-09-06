"""POST /enroll handler logic. See architecture.md §9.6, §14.1."""
import base64

from common import canon
from common.crypto import signing
from engine.store import Store


DEFAULT_CHECKIN_INTERVAL_S = 60

_REQUIRED_FIELDS = {
    "enrollment_token": str,
    "box_id": str,
    "public_key": str,
    "agent_version": str,
    "scenario_name": str,
    "scenario_version": int,
}


class EnrollError(Exception):
    """Raised for rejected enroll requests; carries HTTP status and message."""

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
    # 1. Validate shape. (isinstance(x, int) accepts bool, so scenario_version
    # needs an explicit bool guard like the rest of the codebase.)
    for key, expected_type in _REQUIRED_FIELDS.items():
        if key not in body:
            raise EnrollError(400, f"malformed body: missing {key}")
        if key == "scenario_version":
            if isinstance(body[key], bool) or not isinstance(body[key], int):
                raise EnrollError(400, "malformed body: scenario_version has wrong type")
        elif not isinstance(body[key], expected_type):
            raise EnrollError(400, f"malformed body: {key} has wrong type")
    if not body["box_id"] or len(body["box_id"]) > 128:
        raise EnrollError(400, "malformed body: box_id length out of range")

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

    status = store.enroll_box_atomic(
        body["enrollment_token"],
        body["box_id"],
        body["public_key"],
        body["scenario_name"],
        body["scenario_version"],
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
