"""Canonical serialization for signed payloads. See architecture.md §7.

Signatures must be computed over identical bytes on both sides of the wire.
"""
import json
import unicodedata


def _normalize_strings(obj):
    """Recursively NFC-normalize every string in a JSON-serializable structure.

    json.dumps' `default` hook only fires for values it can't natively
    serialize, and str is natively serializable — so passing a
    normalizing `default=` callback silently never runs. Walking the
    structure ourselves is the only way to actually touch every string.
    """
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        # Normalize keys AND values: a decomposed vs composed Unicode dict key
        # (e.g. a user-supplied key in raw evidence / collect_params) must
        # canonicalize identically on both sides of the wire, or the §7
        # byte-identical-signature contract silently breaks.
        return {
            _normalize_strings(k): _normalize_strings(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_normalize_strings(v) for v in obj]
    return obj


def canonicalize(obj) -> bytes:
    """Deterministic JSON encoding used for every signed payload.

    Sorted keys, minimal separators, UTF-8, no trailing newline. `obj` must
    already be a plain JSON-serializable structure (e.g. via dataclasses.asdict).

    NFC normalization ensures Unicode strings are in a canonical composed form
    before encoding, preventing signature mismatches due to different Unicode
    representation of the same abstract string on wire vs. agent.
    """
    return json.dumps(
        _normalize_strings(obj), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
