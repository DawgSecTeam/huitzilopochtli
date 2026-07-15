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
    category: Category
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

_REQUIRED_CHECK_SPEC_KEYS = (
    "id", "type", "category", "host_id", "collect_params",
    "display_title", "display_max_points",
)
_REQUIRED_MANIFEST_KEYS = (
    "schema_version", "scenario_name", "scenario_version", "mode", "hosts", "checks",
)
_REQUIRED_RUBRIC_ENTRY_KEYS = ("check_id", "category", "matcher", "points")
_REQUIRED_RUBRIC_KEYS = (
    "schema_version", "scenario_name", "scenario_version", "entries",
)


def validate_manifest(obj: dict) -> list:
    """Return a list of human-readable error strings; empty list = valid.

    Structural validation of a compiled/parsed manifest dict (not YAML source).
    Called by the authoring toolchain (fail the build) and by the agent on load
    (refuse to run on invalid/unsigned input). No silent coercion.
    """
    errors = []
    if not isinstance(obj, dict):
        return ["manifest must be a JSON object"]

    for key in _REQUIRED_MANIFEST_KEYS:
        if key not in obj:
            errors.append(f"manifest missing required key '{key}'")

    if "schema_version" in obj and obj["schema_version"] != SCHEMA_VERSION:
        errors.append(
            f"manifest schema_version {obj['schema_version']!r} != "
            f"supported {SCHEMA_VERSION!r}"
        )

    if "mode" in obj and obj["mode"] not in (Mode.HONOR.value, Mode.RANKED.value):
        errors.append(f"manifest mode must be 'honor' or 'ranked', got {obj['mode']!r}")

    if obj.get("mode") == Mode.RANKED.value and not obj.get("engine_url"):
        errors.append("manifest mode is 'ranked' but engine_url is missing/empty")

    if "hosts" in obj and not isinstance(obj["hosts"], list):
        errors.append("manifest.hosts must be a list")

    checks = obj.get("checks")
    if checks is None:
        pass  # already reported as missing above
    elif not isinstance(checks, list):
        errors.append("manifest.checks must be a list")
    else:
        seen_ids = set()
        for idx, check in enumerate(checks):
            ref = f"manifest.checks[{idx}]"
            if not isinstance(check, dict):
                errors.append(f"{ref} must be an object")
                continue
            for key in _REQUIRED_CHECK_SPEC_KEYS:
                if key not in check:
                    errors.append(f"{ref} missing required key '{key}'")
            # Only validate the value when the key is present; otherwise the
            # "missing required key 'category'" error above already covers it and
            # this would add a redundant, misleading "got None" second error.
            if "category" in check and check["category"] not in (
                Category.VULN.value, Category.PENALTY.value, Category.PROHIBITED.value
            ):
                errors.append(
                    f"{ref}.category must be one of vuln/penalty/prohibited, "
                    f"got {check['category']!r}"
                )
            # Invariant (§6.1): collect_params must never carry expected/correct
            # values. Best-effort structural guard: reject an accidentally-leaked
            # "expect"/"points" key inside collect_params.
            collect_params = check.get("collect_params")
            if isinstance(collect_params, dict):
                for leaked_key in ("expect", "points", "matcher"):
                    if leaked_key in collect_params:
                        errors.append(
                            f"{ref}.collect_params must not contain '{leaked_key}' "
                            "(rubric data must never ship in the manifest)"
                        )
            cid = check.get("id")
            if cid is not None:
                if cid in seen_ids:
                    errors.append(f"{ref} duplicate check id '{cid}'")
                seen_ids.add(cid)

    return errors


def validate_rubric(obj: dict) -> list:
    """Return a list of human-readable error strings; empty list = valid."""
    errors = []
    if not isinstance(obj, dict):
        return ["rubric must be a JSON object"]

    for key in _REQUIRED_RUBRIC_KEYS:
        if key not in obj:
            errors.append(f"rubric missing required key '{key}'")

    if "schema_version" in obj and obj["schema_version"] != SCHEMA_VERSION:
        errors.append(
            f"rubric schema_version {obj['schema_version']!r} != "
            f"supported {SCHEMA_VERSION!r}"
        )

    entries = obj.get("entries")
    if entries is None:
        pass  # already reported as missing above
    elif not isinstance(entries, list):
        errors.append("rubric.entries must be a list")
    else:
        seen_ids = set()
        for idx, entry in enumerate(entries):
            ref = f"rubric.entries[{idx}]"
            if not isinstance(entry, dict):
                errors.append(f"{ref} must be an object")
                continue
            for key in _REQUIRED_RUBRIC_ENTRY_KEYS:
                if key not in entry:
                    errors.append(f"{ref} missing required key '{key}'")
            # See validate_manifest: skip the value check when the key is absent
            # to avoid a redundant "got None" alongside the missing-key error.
            if "category" in entry and entry["category"] not in (
                Category.VULN.value, Category.PENALTY.value, Category.PROHIBITED.value
            ):
                errors.append(
                    f"{ref}.category must be one of vuln/penalty/prohibited, "
                    f"got {entry['category']!r}"
                )
            points = entry.get("points")
            if isinstance(points, bool) or not isinstance(points, int):
                errors.append(f"{ref}.points must be an integer")
            if not isinstance(entry.get("matcher"), dict):
                errors.append(f"{ref}.matcher must be an object")
            cid = entry.get("check_id")
            if cid is not None:
                if cid in seen_ids:
                    errors.append(f"{ref} duplicate check_id '{cid}'")
                seen_ids.add(cid)
            sla = entry.get("sla")
            if sla is not None and not isinstance(sla, dict):
                errors.append(f"{ref}.sla must be an object or null")
            elif isinstance(sla, dict):
                interval_s = sla.get("interval_s")
                if (isinstance(interval_s, bool)
                        or not isinstance(interval_s, (int, float))
                        or interval_s <= 0):
                    # interval_s is the divisor for SLA accrual (engine/sla.py);
                    # zero/negative would divide-by-zero or credit nonsense.
                    errors.append(f"{ref}.sla.interval_s must be a positive number")

    return errors
