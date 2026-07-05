"""Vendored pure-Python Ed25519. See architecture.md §7.

PHASE 1 TASK: vendor a pinned, well-known reference Ed25519 implementation
(e.g. the djb/ref10-derived pure-Python implementations commonly vendored for
this purpose). Record the exact source URL/commit and license at the top of
this file as a comment. Do not hand-roll field arithmetic (§7).

Required surface (used only by signing.py — nothing else should import this
module directly):

    def keypair() -> tuple[bytes, bytes]: ...        # (private_key, public_key)
    def sign(private_key: bytes, msg: bytes) -> bytes: ...
    def verify(public_key: bytes, msg: bytes, sig: bytes) -> bool: ...

CI (§19, deferred) will run this against published Ed25519 known-answer test
vectors — keep the implementation self-contained enough to be tested in
isolation.
"""


def keypair() -> tuple:
    raise NotImplementedError


def sign(private_key: bytes, msg: bytes) -> bytes:
    raise NotImplementedError


def verify(public_key: bytes, msg: bytes, sig: bytes) -> bool:
    raise NotImplementedError
