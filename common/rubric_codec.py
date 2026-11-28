"""Light obfuscation for the on-box honor-mode rubric file.

An honor box holds its own rubric to score offline (§2.4/§6.1), so the key
lives on the box it grades. Format: canonical JSON -> gzip -> static-XOR ->
base64 — opaque to `cat`/`grep -r`, not to a reader.

This is obfuscation, NOT a security boundary: the XOR key ships in plaintext
inside agent.pyz on the same box. Ranked mode is the actual secrecy fix.
Both sides import this module (boxbuilder encodes, agent decodes) so the
format cannot drift; stdlib-only (zipapp invariant).
"""
import base64
import gzip
import json

# Static XOR key, deliberately not secret: defeats base64 -d / strings drive-bys,
# not anyone who reads this file.
_KEY = b"huitzilopochtli-rubric"


def _xor(data: bytes) -> bytes:
    return bytes(b ^ _KEY[i % len(_KEY)] for i, b in enumerate(data))


def encode_rubric(rubric: dict) -> bytes:
    """Serialize a rubric dict into its on-box obfuscated form (ASCII)."""
    raw = json.dumps(rubric, sort_keys=True).encode("utf-8")
    return base64.b64encode(_xor(gzip.compress(raw)))


def looks_encoded(data: bytes) -> bool:
    """True if `data` does not look like plain JSON. Sniff used by the
    agent's loader so boxes installed by older boxbuilders (plain
    rubric.json) keep scoring."""
    return not data.lstrip().startswith(b"{")


def decode_rubric(data: bytes) -> dict:
    """Invert encode_rubric. Raises on garbage/tampered input."""
    raw = gzip.decompress(_xor(base64.b64decode(data.strip(), validate=True)))
    return json.loads(raw.decode("utf-8"))
