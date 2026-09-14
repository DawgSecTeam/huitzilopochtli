"""Unit tests for common/rubric_codec.py (on-box honor-rubric obfuscation)."""
import json

import pytest

from common import rubric_codec


def test_roundtrip():
    rubric = {"schema_version": 1, "entries": [{"id": "a", "max_points": 10}]}
    encoded = rubric_codec.encode_rubric(rubric)
    assert rubric_codec.decode_rubric(encoded) == rubric


def test_encoded_is_ascii_without_plaintext():
    """cat/grep drive-bys see an opaque ASCII blob: no check ids, no JSON keys."""
    rubric = {"entries": [{"id": "ssh-root-login-disabled",
                           "display": "Root login is disabled"}]}
    raw = rubric_codec.encode_rubric(rubric)
    raw.decode("ascii")  # base64 -> safe to cat anywhere
    for needle in (b"ssh-root-login", b"Root login", b'"entries"', b"{"):
        assert needle not in raw


def test_looks_encoded_sniff():
    assert not rubric_codec.looks_encoded(b'{"entries": []}')
    assert not rubric_codec.looks_encoded(b'  \n {"entries": []}')
    assert rubric_codec.looks_encoded(b"aGVsbG8=")
    assert rubric_codec.looks_encoded(b"")


def test_decode_rejects_garbage_and_tampering():
    with pytest.raises((ValueError, OSError, EOFError)):
        rubric_codec.decode_rubric(b"not-a-thing")
    good = rubric_codec.encode_rubric({"a": 1})
    with pytest.raises((ValueError, OSError, EOFError)):
        rubric_codec.decode_rubric(good[:-8] + b"AAAAAAAA")


def test_deterministic_encoding():
    """Same input, same bytes -- re-installs don't churn the on-box file."""
    rubric = {"b": 2, "a": 1}
    assert rubric_codec.encode_rubric(rubric) == rubric_codec.encode_rubric(rubric)
    # Key order is canonicalized.
    assert rubric_codec.encode_rubric(rubric) == rubric_codec.encode_rubric(
        json.loads(json.dumps(rubric)))
