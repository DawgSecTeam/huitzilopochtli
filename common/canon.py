"""Canonical serialization for signed payloads. See architecture.md §7.

Signatures must be computed over identical bytes on both sides of the wire.
"""
import json
import unicodedata


def _normalize_strings(obj):
    """Recursively NFC-normalize every string value.

    ``json.dumps(default=...)`` never fires for native ``str``, so walk the
    structure explicitly.
    """
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        # Normalize keys and values so decomposed vs composed forms match.
        return {
            _normalize_strings(k): _normalize_strings(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_normalize_strings(v) for v in obj]
    return obj


def canonicalize(obj) -> bytes:
    """Deterministic JSON encoding for signed payloads.

    Sorted keys, minimal separators, UTF-8, no trailing newline. NFC-normalizes
    strings to avoid signature mismatches from composed vs decomposed forms.
    """
    return json.dumps(
        _normalize_strings(obj), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
