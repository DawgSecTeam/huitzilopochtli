"""Canonical serialization for signed payloads. See architecture.md §7.

Signatures must be computed over identical bytes on both sides of the wire.
"""
import json


def canonicalize(obj) -> bytes:
    """Deterministic JSON encoding used for every signed payload.

    Sorted keys, minimal separators, UTF-8, no trailing newline. `obj` must
    already be a plain JSON-serializable structure (e.g. via dataclasses.asdict).
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
