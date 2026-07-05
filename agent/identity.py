"""Box identity & enrollment. Ranked mode only. See architecture.md §9.6.

PHASE 1 TASK: implement.
"""
from dataclasses import dataclass


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
    raise NotImplementedError


def enroll(engine_url: str, enrollment_token: str, identity: Identity,
           agent_version: str, scenario_name: str) -> dict:
    """POST /enroll (signed by the box key) per §14.1. Returns the parsed
    EnrollResponse-shaped dict, or raises on 400/409/410."""
    raise NotImplementedError


def save(identity_path: str, identity: Identity) -> None:
    """Persist identity (including updated last_seq) back to disk, 0600."""
    raise NotImplementedError
