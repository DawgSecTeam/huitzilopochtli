"""Bounded-concurrency signature verification for the engine.

Vendored pure-Python Ed25519 spends seconds of GIL-held CPU per verify, so an
uncapped flood of well-formed but bogus requests pins every worker. A
saturated gate returns None: callers map it to 503, which agents treat as
transient and retry (agent/transport.py).
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
