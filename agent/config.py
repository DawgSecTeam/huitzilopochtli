"""Local on-box config loader. See architecture.md §9.7. PHASE 2 (integration)."""
import json
from dataclasses import dataclass
from typing import Optional

from common.schema import Mode


@dataclass
class AgentConfig:
    mode: Mode
    manifest_path: str
    rubric_path: Optional[str]        # honor only
    identity_path: Optional[str]      # ranked only
    report_path: str
    checkin_interval_s: Optional[int]  # ranked only
    authoring_public_key_path: Optional[str] = None  # for manifest signature verification
    enrollment_token: Optional[str] = None  # ranked only; consumed once on first boot


def load_config(config_path: str) -> AgentConfig:
    """Read the on-box JSON config (§9.7) and return an AgentConfig.

    Shape: {"mode": "honor"|"ranked", "manifest_path": str,
            "rubric_path": str|null, "identity_path": str|null,
            "report_path": str, "checkin_interval_s": int|null,
            "authoring_public_key_path": str|null,
            "enrollment_token": str|null}

    authoring_public_key_path is optional for backwards compatibility with
    configs written before manifest signature verification existed; if
    omitted, the agent falls back to warn-and-proceed-unverified (see
    agent/__main__.py::_load_manifest).

    enrollment_token is read only on a box's first-ever ranked-mode boot
    (see agent/__main__.py::_run_ranked) -- once the box has an identity
    file, this field is never consulted again.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return AgentConfig(
        mode=Mode(data["mode"]),
        manifest_path=data["manifest_path"],
        rubric_path=data.get("rubric_path"),
        identity_path=data.get("identity_path"),
        report_path=data["report_path"],
        checkin_interval_s=data.get("checkin_interval_s"),
        authoring_public_key_path=data.get("authoring_public_key_path"),
        enrollment_token=data.get("enrollment_token"),
    )
