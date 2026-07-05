"""Local on-box config loader. See architecture.md §9.7. PHASE 2 (integration)."""
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
    raise NotImplementedError
