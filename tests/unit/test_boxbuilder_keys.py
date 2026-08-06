"""Unit tests for boxbuilder.keys (authoring keypair load-or-generate)."""
import os
import stat

import pytest

from boxbuilder import keys
from common.crypto import signing


def test_generate_and_persist(tmp_path):
    priv, path = keys.load_authoring_key(None, str(tmp_path))
    assert len(priv) == 32
    assert os.path.isfile(path)
    # Permissions are 0600 (key signs manifests).
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    # Re-loading returns the SAME key (stable across rebuilds).
    priv2, path2 = keys.load_authoring_key(None, str(tmp_path))
    assert priv2 == priv
    assert path2 == path


def test_load_existing_key_path(tmp_path):
    seed = b"\x01" * 32
    keyfile = tmp_path / "my.key"
    keyfile.write_text(seed.hex())  # hex-encoded, matching _write_key
    priv, path = keys.load_authoring_key(str(keyfile), str(tmp_path / "artifacts"))
    assert priv == seed
    assert path == str(keyfile)
    # Did not create an auto key alongside.
    assert not (tmp_path / "artifacts" / "authoring.key").exists()


def test_missing_explicit_key_path_errors(tmp_path):
    with pytest.raises(FileNotFoundError, match="authoring key not found"):
        keys.load_authoring_key(str(tmp_path / "absent.key"), str(tmp_path))


def test_wrong_size_key_rejected(tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text((b"\x01" * 10).hex())  # valid hex, wrong length
    with pytest.raises(ValueError, match="32-byte"):
        keys.load_authoring_key(str(bad), str(tmp_path))


def test_non_hex_key_rejected(tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text("not-hex-at-all!!")
    with pytest.raises(ValueError, match="not valid hex"):
        keys.load_authoring_key(str(bad), str(tmp_path))


def test_seed_ending_in_whitespace_byte_round_trips(tmp_path):
    """Regression: a raw-bytes key format broke on seeds whose last byte is a
    whitespace char (\\n/\\t/space, ~2.3% of random seeds) because bytes.strip()
    ate it. The hex format is immune; confirm a seed ending in \\x20 round-trips."""
    seed = b"\x01" * 31 + b"\x20"  # last byte is space
    priv, path = keys.load_authoring_key(None, str(tmp_path))
    # Overwrite with our specific seed, then re-read.
    import os
    os.remove(path)
    from boxbuilder.keys import _write_key
    _write_key(path, seed)
    priv2, _ = keys.load_authoring_key(None, str(tmp_path))
    assert priv2 == seed, "seed ending in a whitespace byte must round-trip exactly"


def test_generated_key_signs_and_verifies(tmp_path):
    """Sanity: a keys.py-generated key is a valid Ed25519 keypair."""
    priv, _ = keys.load_authoring_key(None, str(tmp_path))
    msg = b"manifest-canonical-bytes"
    sig = signing.sign(priv, msg)
    pub = signing.public_key_from_private(priv)
    assert signing.verify(pub, msg, sig) is True
