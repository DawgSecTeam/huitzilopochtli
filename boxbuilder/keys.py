"""Authoring keypair handling for boxbuilder.

compile_scenario (authoring/compile.py:96) requires authoring_private_key:
bytes. Policy here:

  - if a key path is supplied, load it (hex-encoded 32-byte Ed25519 seed);
  - else generate one (common.crypto.signing.keypair()), persist it to the
    artifacts dir as `authoring.key` (mode 0600) so a box rebuilds with a
    stable manifest signature.

Key custody stays with the build (author/CI), never on the box -- matching
the invariant noted at compile.py:111-115. The .key file is gitignored at
the repo root (*.key pattern added alongside this module).

On-disk format: 64 hex characters (lowercase) encoding the 32-byte seed. Hex
is used -- not raw bytes -- because a raw 32-byte seed may itself end in a
whitespace byte (\\n/\\t/space), which makes a naive bytes.strip() corrupt the
key. Hex is text, so strip() is safe, and the file is human-readable/editable.
"""
import os
from typing import Optional

from common.crypto import signing

_KEY_FILE = "authoring.key"


def load_authoring_key(
    key_path: Optional[str], artifacts_dir: str
) -> tuple:
    """Return (private_key_bytes, key_path_used).

    If `key_path` is given and exists, load it. If given but missing, that is
    an error (the caller asked for a specific file). If None, generate a new
    keypair and persist it under `artifacts_dir/authoring.key` so subsequent
    rebuilds of the same box stay signature-stable.
    """
    if key_path is not None:
        if not os.path.isfile(key_path):
            raise FileNotFoundError(f"authoring key not found: {key_path}")
        priv = _read_key(key_path)
        return priv, key_path

    # Auto-generate + persist into the artifacts dir.
    os.makedirs(artifacts_dir, exist_ok=True)
    path = os.path.join(artifacts_dir, _KEY_FILE)
    if os.path.isfile(path):
        return _read_key(path), path

    priv, _pub = signing.keypair()
    _write_key(path, priv)
    return priv, path


def _read_key(path: str) -> bytes:
    """Read a hex-encoded 32-byte Ed25519 seed."""
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
    # Write atomically-ish, then lock down perms. 0600 because this signs
    # manifests; a leaked key lets an attacker forge manifests for any box
    # trusting the matching public key.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(priv.hex())
    finally:
        os.chmod(path, 0o600)
