"""Thin sign/verify wrapper over the vendored Ed25519 impl. See architecture.md §7.

Callers (agent identity, transport, engine enrollment/checkin, authoring
sign_scenario) should import ONLY this module, never common.crypto.ed25519
directly, so the vendored implementation can be swapped without touching
callers.
"""


from common.crypto import ed25519


def keypair() -> tuple:
    """Return (private_key: bytes, public_key: bytes)."""
    return ed25519.keypair()


def sign(private_key: bytes, msg_bytes: bytes) -> bytes:
    """Sign canonical message bytes (see common.canon.canonicalize)."""
    return ed25519.sign(private_key, msg_bytes)


def verify(public_key: bytes, msg_bytes: bytes, sig: bytes) -> bool:
    """Verify a signature over canonical message bytes."""
    return ed25519.verify(public_key, msg_bytes, sig)


def public_key_from_private(private_key: bytes) -> bytes:
    """Re-derive the public key from a private key. Used by the authoring
    toolchain to emit a distributable verification artifact without having
    to separately generate/track public key material."""
    return ed25519.public_key_from_private(private_key)
