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


def load_config(config_path: str) -> AgentConfig:
    """Read the on-box JSON config (§9.7) and return an AgentConfig.

    Shape: {"mode": "honor"|"ranked", "manifest_path": str,
            "rubric_path": str|null, "identity_path": str|null,
            "report_path": str, "checkin_interval_s": int|null}
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
    )
