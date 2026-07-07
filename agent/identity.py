"""Box identity & enrollment. Ranked mode only. See architecture.md §9.6.

PHASE 1 TASK: implement.
"""
import base64
import json
import os
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass

from common.crypto import signing
from common.canon import canonicalize


@dataclass
class Identity:
    box_id: str
    private_key: bytes
    public_key: bytes
    last_seq: int


def load_or_create(identity_path: str) -> Identity:
    """Load the identity file, or generate a new Ed25519 keypair + box_id
    (UUID) and persist it (mode 0600) if none exists yet.

    The private key never leaves the box.
    """
    if os.path.exists(identity_path):
        with open(identity_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return Identity(
            box_id=data["box_id"],
            private_key=base64.b64decode(data["private_key"]),
            public_key=base64.b64decode(data["public_key"]),
            last_seq=data["last_seq"],
        )

    private_key, public_key = signing.keypair()
    identity = Identity(
        box_id=str(uuid.uuid4()),
        private_key=private_key,
        public_key=public_key,
        last_seq=0,
    )
    save(identity_path, identity)
    return identity


def enroll(engine_url: str, enrollment_token: str, identity: Identity,
           agent_version: str, scenario_name: str) -> dict:
    """POST /enroll (signed by the box key) per §14.1. Returns the parsed
    EnrollResponse-shaped dict, or raises on 400/409/410."""
    body = {
        "enrollment_token": enrollment_token,
        "box_id": identity.box_id,
        "public_key": base64.b64encode(identity.public_key).decode("ascii"),
        "agent_version": agent_version,
        "scenario_name": scenario_name,
    }
    canonical_bytes = canonicalize(body)
    signature = signing.sign(identity.private_key, canonical_bytes)

    url = f"{engine_url}/enroll"
    request = urllib.request.Request(
        url,
        data=canonical_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(signature).decode("ascii"),
            "X-HUITZILOPOCHTLI-Box": identity.box_id,
        },
    )

    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(request, context=ctx) as resp:
            status = resp.getcode()
            response_bytes = resp.read()
    except urllib.error.HTTPError as e:
        status = e.code
        response_bytes = e.read()

    if status == 200:
        return json.loads(response_bytes.decode("utf-8"))

    reasons = {
        409: "enrollment token already consumed",
        410: "enrollment token expired",
        400: "malformed enrollment request",
    }
    reason = reasons.get(status, "unexpected response")
    raise Exception(f"enrollment failed: HTTP {status} ({reason})")


def save(identity_path: str, identity: Identity) -> None:
    """Persist identity (including updated last_seq) back to disk, 0600."""
    data = {
        "box_id": identity.box_id,
        "private_key": base64.b64encode(identity.private_key).decode("ascii"),
        "public_key": base64.b64encode(identity.public_key).decode("ascii"),
        "last_seq": identity.last_seq,
    }

    directory = os.path.dirname(os.path.abspath(identity_path)) or "."
    tmp_path = os.path.join(
        directory, f".{os.path.basename(identity_path)}.{uuid.uuid4().hex}.tmp"
    )

    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(tmp_path, 0o600)
        os.rename(tmp_path, identity_path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    os.chmod(identity_path, 0o600)
