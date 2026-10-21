"""Unit tests for common/crypto/signing.py (the sanctioned Ed25519 wrapper).

Vector-sourcing approach: real published Ed25519 known-answer test vectors
(RFC 8032 Section 7.1) are used, loaded from
tests/vectors/ed25519_rfc8032.json. Those vectors were fetched from the RFC
text and independently cross-checked against this repo's vendored
implementation before being committed to the fixture file (see the "_source"
note in that JSON file for details on how a transcription glitch from the
fetch was caught and corrected). A self-generated regression fixture was not
needed since real vectors were available and verified.
"""

import json
import os

import pytest

from common.crypto.signing import keypair, public_key_from_private, sign, verify

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "vectors", "ed25519_rfc8032.json"
)


def _load_vectors():
    with open(VECTORS_PATH) as f:
        data = json.load(f)
    return data["vectors"]


def test_keypair_shape():
    private_key, public_key = keypair()
    assert isinstance(private_key, bytes)
    assert isinstance(public_key, bytes)
    assert len(private_key) == 32
    assert len(public_key) == 32


def test_keypair_is_random():
    priv1, pub1 = keypair()
    priv2, pub2 = keypair()
    assert priv1 != priv2
    assert pub1 != pub2


def test_sign_verify_round_trip():
    private_key, public_key = keypair()
    msg = b"the quick brown fox jumps over the lazy dog"
    sig = sign(private_key, msg)
    assert isinstance(sig, bytes)
    assert len(sig) == 64
    assert verify(public_key, msg, sig) is True


def test_verify_rejects_tampered_message():
    private_key, public_key = keypair()
    msg = b"transfer 10 to alice"
    sig = sign(private_key, msg)
    tampered = b"transfer 90 to alice"
    assert verify(public_key, tampered, sig) is False


def test_verify_rejects_tampered_signature_byte():
    private_key, public_key = keypair()
    msg = b"payload"
    sig = sign(private_key, msg)
    tampered_sig = bytearray(sig)
    tampered_sig[0] ^= 0x01
    assert verify(public_key, msg, bytes(tampered_sig)) is False


def test_verify_rejects_wrong_public_key():
    priv_a, _pub_a = keypair()
    _priv_b, pub_b = keypair()
    msg = b"payload"
    sig = sign(priv_a, msg)
    assert verify(pub_b, msg, sig) is False


def test_verify_returns_bool_not_raises_on_garbage_signature():
    _priv, pub = keypair()
    msg = b"payload"
    # Wrong-length / malformed signature bytes must produce False, not an
    # exception, since verify() is used on attacker-controlled input.
    assert verify(pub, msg, b"\x00" * 64) is False
    assert verify(pub, msg, b"\x00" * 10) is False
    assert verify(pub, msg, b"") is False


def test_public_key_from_private_matches_generated_public_key():
    private_key, public_key = keypair()
    assert public_key_from_private(private_key) == public_key


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["name"])
def test_rfc8032_known_answer_vectors(vector):
    private_key = bytes.fromhex(vector["secret_key"])
    expected_public_key = bytes.fromhex(vector["public_key"])
    message = bytes.fromhex(vector["message"])
    expected_signature = bytes.fromhex(vector["signature"])

    assert public_key_from_private(private_key) == expected_public_key

    produced_signature = sign(private_key, message)
    assert produced_signature == expected_signature

    assert verify(expected_public_key, message, expected_signature) is True


# --- 1.0: reject small-order / non-canonical points -------------------------

def _identity_encoding():
    return bytes([1]) + bytes(31)


def _order_two_encoding():
    from common.crypto import ed25519
    return ed25519.encodepoint([0, ed25519.q - 1])


def test_identity_point_public_key_cannot_forge_a_signature():
    from common.crypto import ed25519
    # The classic small-order forgery: A = identity, R = B, S = 1.
    pk = _identity_encoding()
    sig = ed25519.encodepoint(ed25519.B) + ed25519.encodeint(1)
    assert verify(pk, b"any message", sig) is False


def test_order_two_public_key_is_rejected():
    from common.crypto import ed25519
    pk = _order_two_encoding()
    sig = ed25519.encodepoint(ed25519.B) + ed25519.encodeint(1)
    assert verify(pk, b"any message", sig) is False


def test_non_canonical_public_key_encoding_is_rejected():
    from common.crypto import ed25519
    # y == q is not a canonical field encoding.
    raw = ed25519.q.to_bytes(32, "little")
    pk = bytes([raw[0] & 0x7F]) + raw[1:]
    sig = ed25519.encodepoint(ed25519.B) + ed25519.encodeint(1)
    assert verify(pk, b"any message", sig) is False


def test_enrollment_rejects_small_order_public_key():
    import time
    from common.crypto import ed25519
    from engine.enrollment import EnrollError, handle_enroll
    from engine.store import Store
    import base64

    store = Store(":memory:")
    store.create_token("tok", "scenario", time.time() + 3600)
    pk = _identity_encoding()
    body = {
        "enrollment_token": "tok",
        "box_id": "evil",
        "public_key": base64.b64encode(pk).decode("ascii"),
        "agent_version": "1.0.0",
        "scenario_name": "scenario",
        "scenario_version": 1,
    }
    sig = ed25519.encodepoint(ed25519.B) + ed25519.encodeint(1)
    try:
        handle_enroll(store, body, sig)
    except EnrollError as e:
        assert e.status_code == 403
    else:
        raise AssertionError("small-order public key was accepted at enrollment")
