"""Bounded-concurrency signature verification for the engine.

The vendored pure-Python Ed25519 (common/crypto/ed25519.py) spends seconds
of GIL-held CPU per verify, and /enroll and /checkin must verify before they
can authenticate the caller. Without a cap, a flood of well-formed but bogus
requests pins every worker thread. Callers map a saturated gate (None) to 503,
which the agent treats as transient and retries (agent/transport.py).
"""
import os
import threading
from typing import Optional

from common.crypto import signing

_GATE = threading.BoundedSemaphore(
    int(os.environ.get("HUITZILOPOCHTLI_MAX_VERIFY", "4"))
)


def verify(public_key: bytes, msg: bytes, sig: bytes) -> Optional[bool]:
    """signing.verify, or None when too many verifies are already running."""
    if not _GATE.acquire(blocking=False):
        return None
    try:
        return signing.verify(public_key, msg, sig)
    finally:
        _GATE.release()
