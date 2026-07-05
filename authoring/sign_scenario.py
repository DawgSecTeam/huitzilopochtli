"""Sign a compiled manifest with the authoring private key. See architecture.md §7.

PHASE 1 TASK: implement using common.canon.canonicalize + common.crypto.signing.
"""


def sign_manifest(manifest_dict: dict, authoring_private_key: bytes) -> dict:
    """Returns the manifest dict with a "_signature" (base64) field attached,
    computed over canonicalize(manifest_dict) (signature field excluded from
    the signed bytes)."""
    raise NotImplementedError
