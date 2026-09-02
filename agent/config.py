"""Local on-box config loader. See architecture.md §9.7."""
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

    authoring_public_key_path is optional; if omitted, verification is
    skipped with a warning (see _load_manifest). enrollment_token is
    consumed only on first ranked boot.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    config = AgentConfig(
        mode=Mode(data["mode"]),
        manifest_path=data["manifest_path"],
        rubric_path=data.get("rubric_path"),
        identity_path=data.get("identity_path"),
        report_path=data["report_path"],
        checkin_interval_s=data.get("checkin_interval_s"),
        authoring_public_key_path=data.get("authoring_public_key_path"),
        enrollment_token=data.get("enrollment_token"),
    )

    if config.mode == Mode.RANKED:
        if not config.identity_path:
            raise ValueError(
                f"config {config_path!r}: ranked mode requires a non-empty "
                "'identity_path'"
            )
        interval = config.checkin_interval_s
        if isinstance(interval, bool) or not isinstance(interval, int) or interval <= 0:
            raise ValueError(
                f"config {config_path!r}: ranked mode requires "
                "'checkin_interval_s' to be a positive integer"
            )

    return config
