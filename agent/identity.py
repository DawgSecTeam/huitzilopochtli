"""Box identity & enrollment. Ranked mode only. See architecture.md §9.6."""
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

_TIMEOUT_S = 10  # matches agent/transport.py


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
        if os.name != "nt":
            st = os.stat(identity_path)
            if st.st_mode & 0o077:
                # §16 requires 0600. Tighten it rather than silently running
                # with a world-readable private key; fail if we cannot.
                try:
                    os.chmod(identity_path, 0o600)
                except OSError as exc:
                    raise ValueError(
                        f"identity file {identity_path!r} is accessible by other "
                        f"users and could not be tightened to 0600: {exc}"
                    ) from exc
        try:
            with open(identity_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"identity file {identity_path!r} is unreadable or corrupt "
                f"({exc}); re-arm with --reset-identity only if a new box "
                f"identity is intended"
            ) from exc
        private_key = base64.b64decode(data["private_key"], validate=True)
        public_key = base64.b64decode(data["public_key"], validate=True)
        box_id = data["box_id"]
        last_seq = data["last_seq"]
        if (not isinstance(box_id, str) or not box_id
                or not isinstance(last_seq, int) or isinstance(last_seq, bool)
                or last_seq < 0):
            raise ValueError(
                f"identity file {identity_path!r} is malformed: box_id must be "
                f"a non-empty string and last_seq a non-negative integer"
            )
        if len(private_key) != 32 or len(public_key) != 32:
            raise ValueError(
                f"identity file {identity_path!r} has malformed key material "
                f"(expected 32-byte Ed25519 keys)"
            )
        if signing.public_key_from_private(private_key) != public_key:
            raise ValueError(
                f"identity file {identity_path!r} is inconsistent: the stored "
                f"public key does not match the private key"
            )
        return Identity(
            box_id=box_id,
            private_key=private_key,
            public_key=public_key,
            last_seq=last_seq,
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


class EnrollmentTokenConsumed(Exception):
    """Raised on HTTP 409 token-already-consumed: an idempotent retry of this
    same box's enrollment, not a fatal failure."""


class EnrollmentConflict(Exception):
    """Raised on HTTP 409 box-id-already-enrolled: the token was consumed by
    a different identity. Retrying cannot fix it; the box needs a new token
    (or the conflicting box must be removed)."""


class EnrollmentRejected(Exception):
    """A permanent enrollment rejection (400/410): reprovisioning is required."""


def enroll(engine_url: str, enrollment_token: str, identity: Identity,
           agent_version: str, scenario_name: str, scenario_version: int) -> dict:
    """POST /enroll (signed by the box key) per §14.1. Returns the parsed
    EnrollResponse-shaped dict, or raises on 400/409/410 (409 raises the more
    specific EnrollmentTokenConsumed)."""
    body = {
        "enrollment_token": enrollment_token,
        "box_id": identity.box_id,
        "public_key": base64.b64encode(identity.public_key).decode("ascii"),
        "agent_version": agent_version,
        "scenario_name": scenario_name,
        "scenario_version": scenario_version,
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
        with urllib.request.urlopen(request, context=ctx, timeout=_TIMEOUT_S) as resp:
            status = resp.getcode()
            response_bytes = resp.read()
    except urllib.error.HTTPError as e:
        status = e.code
        response_bytes = e.read()
    except urllib.error.URLError as e:
        if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
            raise EnrollmentRejected(
                f"enrollment failed: engine TLS certificate verification failed "
                f"({e.reason})"
            ) from e
        raise

    if status == 200:
        return json.loads(response_bytes.decode("utf-8"))

    reasons = {
        410: "enrollment token expired",
        400: "malformed enrollment request",
    }
    engine_error = ""
    try:
        parsed = json.loads(response_bytes.decode("utf-8"))
        if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
            engine_error = parsed["error"]
    except (ValueError, UnicodeDecodeError):
        pass
    if status == 409:
        if "already enrolled" in engine_error.lower():
            raise EnrollmentConflict(
                f"enrollment failed: HTTP {status} ({engine_error or 'box_id already enrolled'})"
            )
        raise EnrollmentTokenConsumed(
            f"enrollment failed: HTTP {status} "
            f"({engine_error or 'enrollment token already consumed'})"
        )
    reason = engine_error or reasons.get(status, "unexpected response")
    if status in (400, 410):
        raise EnrollmentRejected(f"enrollment failed: HTTP {status} ({reason})")
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
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, identity_path)
        # Persist the rename itself on POSIX. Best-effort: Windows has no
        # directory fsync.
        if os.name != "nt":
            try:
                dfd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    os.chmod(identity_path, 0o600)
