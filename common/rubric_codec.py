"""Light obfuscation for the on-box honor-mode rubric file.

The honor-mode box must hold its rubric to score offline (architecture.md
§2.4/§6.1), so the answer key necessarily lives on the box it grades. This
module makes that file unrecognizable at a glance: the content is canonical
JSON -> gzip -> XOR with a static key -> base64, so `cat` shows an opaque
ASCII blob and `grep -r <check id> /opt` finds nothing.

This is obfuscation, NOT a security boundary -- the XOR key ships in
plaintext inside agent.pyz on the same box, so anyone willing to read the
agent source can decode the file. Ranked mode is the actual fix for rubric
secrecy (the rubric never leaves the engine).

Both sides import this module -- boxbuilder/artifacts.py encodes at build
time, agent/__main__.py decodes at run time -- so the format cannot drift.
stdlib-only (zipapp invariant).
"""
import base64
import gzip
import json

# Static XOR key, deliberately not derived from anything secret: the goal is
# defeating `base64 -d` / `strings` drive-bys, not concealing content from
# someone who reads this file.
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
