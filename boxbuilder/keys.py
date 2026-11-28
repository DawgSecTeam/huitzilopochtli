"""Authoring keypair handling: load the hex-encoded 32-byte Ed25519 seed at
a given path, or generate one and persist it (0600) in the artifacts dir so
rebuilds keep a stable manifest signature. Key custody stays with the build
machine, never on the box. Hex, not raw bytes: a raw seed can end in a
whitespace byte, so a naive strip() would corrupt it.
"""
import os
from typing import Optional

from common.crypto import signing

_KEY_FILE = "authoring.key"


def load_authoring_key(
    key_path: Optional[str], artifacts_dir: str
) -> tuple:
    """Return (private_key_bytes, key_path_used). A given-but-missing path is
    an error; None generates + persists authoring.key in artifacts_dir so
    rebuilds stay signature-stable."""
    if key_path is not None:
        if not os.path.isfile(key_path):
            raise FileNotFoundError(f"authoring key not found: {key_path}")
        priv = _read_key(key_path)
        return priv, key_path

    os.makedirs(artifacts_dir, exist_ok=True)
    path = os.path.join(artifacts_dir, _KEY_FILE)
    if os.path.isfile(path):
        return _read_key(path), path

    priv, _pub = signing.keypair()
    _write_key(path, priv)
    return priv, path


def _read_key(path: str) -> bytes:
    """Read a hex-encoded 32-byte Ed25519 seed."""
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise ValueError(f"{path}: authoring key must be a regular file, not a symlink")
    if os.name != "nt" and st.st_uid != os.geteuid():
        raise ValueError(f"{path}: authoring key is owned by another user")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError as e:
        raise ValueError(
            f"{path}: authoring key is not valid hex ({e})"
        ) from e
    if len(raw) != 32:
        raise ValueError(
            f"{path}: expected a 32-byte (64 hex char) Ed25519 seed, got {len(raw)} bytes"
        )
    return raw


def _write_key(path: str, priv: bytes) -> None:
    # Atomic temp-file + rename, then lock down perms. 0600 because this
    # signs manifests; a leaked key lets an attacker forge manifests for
    # any box trusting the matching public key.
    import tempfile
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".huitz-key-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(priv.hex())
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
