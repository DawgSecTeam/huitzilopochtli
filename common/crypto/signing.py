"""Thin sign/verify wrapper over the vendored Ed25519 impl. See architecture.md §7.

Callers (agent identity, transport, engine enrollment/checkin, authoring
sign_scenario) should import ONLY this module, never common.crypto.ed25519
directly, so the vendored implementation can be swapped without touching
callers.
"""


def keypair() -> tuple:
    """Return (private_key: bytes, public_key: bytes)."""
    raise NotImplementedError


def sign(private_key: bytes, msg_bytes: bytes) -> bytes:
    """Sign canonical message bytes (see common.canon.canonicalize)."""
    raise NotImplementedError


def verify(public_key: bytes, msg_bytes: bytes, sig: bytes) -> bool:
    """Verify a signature over canonical message bytes."""
    raise NotImplementedError
