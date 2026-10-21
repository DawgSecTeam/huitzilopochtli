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
        # Refuse two keys that normalize to the same string: silently keeping
        # one would make canonical bytes verify for a body whose parsed keys
        # differ (signature semantics ambiguity).
        normalized = {}
        for key, value in obj.items():
            norm_key = _normalize_strings(key)
            if norm_key in normalized:
                raise ValueError(
                    f"canonicalization key collision: {key!r} normalizes to "
                    f"the same string as another key")
            normalized[norm_key] = _normalize_strings(value)
        return normalized
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
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
