"""Data model shared by agent and engine. See architecture.md §6, §14.

Pure stdlib dataclasses. No Pydantic (breaks the pure-Python/zipapp constraint).
All schema objects are serialized as JSON; on-box parsing is stdlib json only.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

SCHEMA_VERSION = 1


class Mode(str, Enum):
    HONOR = "honor"
    RANKED = "ranked"


class Category(str, Enum):
    VULN = "vuln"
    PENALTY = "penalty"
    PROHIBITED = "prohibited"


class CollectorStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"


# --- §6.1 CheckSpec (in Manifest — safe to ship to box) ---------------------

@dataclass
class CheckSpec:
    id: str
    type: str
    category: Category
    host_id: str
    collect_params: dict
    display_title: str
    display_max_points: int
    timeout_s: float = 5.0
    is_sla: bool = False


# --- §6.2 Evidence (collector output — no verdict, no points) --------------

@dataclass
class Evidence:
    check_id: str
    check_type: str
    host_id: str
    status: CollectorStatus
    raw: dict
    reason: str
    collected_monotonic: float
    collected_wall_claim: float  # DIAGNOSTIC ONLY, never a scoring input


# --- §6.3 RubricEntry (engine-only in ranked; on-box in honor) -------------

@dataclass
class SlaParams:
    interval_s: int
    points_per_interval: int
    hysteresis_fail_n: int = 2
    hysteresis_ok_n: int = 2
    max_intervals_per_checkin: int = 3


@dataclass
class RubricEntry:
    check_id: str
    matcher: dict
    points: int  # SIGNED; negative for penalty/prohibited
    sla: Optional[SlaParams] = None


# --- §6.4 Manifest (signed, shipped to box) ---------------------------------

@dataclass
class Manifest:
    schema_version: int
    scenario_name: str
    scenario_version: int
    mode: Mode
    engine_url: Optional[str]
    hosts: list
    checks: list  # list[CheckSpec]
    # NOTE: no rubric, no adversary schedule, no seed.


# --- §6.5 Rubric -------------------------------------------------------------

@dataclass
class Rubric:
    schema_version: int
    scenario_name: str
    scenario_version: int
    entries: list  # list[RubricEntry]
    # Adversary schedule + seed live in the ENGINE's scenario record only (§12),
    # never in the manifest, never on a ranked box.


# --- §6.6 Scoring result types (evaluator output) ---------------------------

@dataclass
class CheckResult:
    check_id: str
    category: Category
    awarded_points: int
    passed: bool
    reason: str


@dataclass
class SlaStatus:
    check_id: str
    state: str  # "UP" | "DOWN"
    accrued_points: int


@dataclass
class ScoreBreakdown:
    scenario_name: str
    scenario_version: int
    total: int
    results: list  # list[CheckResult]
    sla_status: list  # list[SlaStatus] — empty in honor mode
    computed_at: float


# --- §9.4 Bundle (collector output assembled for transmission/evaluation) --

@dataclass
class Bundle:
    box_id: str
    seq: int
    boot_id: str
    agent_version: str
    scenario_name: str
    scenario_version: int
    evidence: list  # list[Evidence]
    created_wall_claim: float  # DIAGNOSTIC ONLY


# --- §12 / §14.2 Directive + protocol response envelopes -------------------
# Frozen for parallel build (not given dataclass form in architecture.md).

@dataclass
class Directive:
    event_id: str
    action: str
    params: dict


@dataclass
class CheckinResponse:
    server_time: float
    score: ScoreBreakdown
    directives: list  # list[Directive]
    next_checkin_s: int
    last_seq: int


@dataclass
class EnrollResponse:
    ok: bool
    box_id: str
    checkin_interval_s: int


# --- §6.7 Validation ---------------------------------------------------------

def validate_manifest(obj: dict) -> list:
    """Return a list of human-readable error strings; empty list = valid.

    Structural validation of a compiled/parsed manifest dict (not YAML source).
    Called by the authoring toolchain (fail the build) and by the agent on load
    (refuse to run on invalid/unsigned input). No silent coercion.
    """
    raise NotImplementedError


def validate_rubric(obj: dict) -> list:
    """Return a list of human-readable error strings; empty list = valid."""
    raise NotImplementedError
