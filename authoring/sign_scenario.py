"""Sign a compiled manifest with the authoring private key. See architecture.md §7."""
import base64

from common.canon import canonicalize
from common.crypto.signing import sign


def sign_manifest(manifest_dict: dict, authoring_private_key: bytes) -> dict:
    """Returns the manifest dict with a "_signature" (base64) field attached,
    computed over canonicalize(manifest_dict) (signature field excluded from
    the signed bytes)."""
    # A caller re-signing an already-signed manifest must sign the same bytes
    # verification will reconstruct. The old code signed the stale
    # _signature field into the body, then replaced it, producing a manifest
    # that could never verify.
    unsigned = {k: v for k, v in manifest_dict.items() if k != "_signature"}
    canonical_bytes = canonicalize(unsigned)
    sig = sign(authoring_private_key, canonical_bytes)
    return {**unsigned, "_signature": base64.b64encode(sig).decode("ascii")}
