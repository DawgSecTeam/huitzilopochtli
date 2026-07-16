"""Canonical serialization for signed payloads. See architecture.md §7.

Signatures must be computed over identical bytes on both sides of the wire.
"""
import json
import unicodedata


def canonicalize(obj) -> bytes:
    """Deterministic JSON encoding used for every signed payload.

    Sorted keys, minimal separators, UTF-8, no trailing newline. `obj` must
    already be a plain JSON-serializable structure (e.g. via dataclasses.asdict).

    NFC normalization ensures Unicode strings are in a canonical composed form
    before encoding, preventing signature mismatches due to different Unicode
    representation of the same abstract string on wire vs. agent.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=lambda o: unicodedata.normalize("NFC", o) if isinstance(o, str) else o,
    ).encode("utf-8")
