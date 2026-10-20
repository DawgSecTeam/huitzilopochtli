"""Data model shared by agent and engine. See architecture.md §6, §14.

Pure stdlib dataclasses. No Pydantic (breaks the pure-Python/zipapp constraint).
All schema objects are serialized as JSON; on-box parsing is stdlib json only.
"""
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit

from common.matchers import validate_matcher

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
class ForensicsQuestion:
    """A scored forensics question as shipped in the Manifest.

    Question text and max points are public (rendered on-box); the answer key
    lives only in the RubricEntry matcher, never here (rubric data must not
    ship in the manifest).
    """
    id: str
    question: str
    max_points: int


@dataclass
class Manifest:
    schema_version: int
    scenario_name: str
    scenario_version: int
    mode: Mode
    engine_url: Optional[str]
    hosts: list
    checks: list  # list[CheckSpec]
    # No rubric, adversary schedule, or seed. Theme is a small optional subset
    # (title/organization/accent/logo_b64) — purely additive, not required.
    theme: Optional[dict] = None
    # Scored forensics questions (question text only — no answer keys).
    forensics: Optional[list] = None  # list[ForensicsQuestion]


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
    # §14.3: stamped on every bundle; the engine rejects incompatible values.
    schema_version: int = SCHEMA_VERSION


# --- §12 / §14.2 Directive + protocol response envelopes -------------------

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
    # Every directive ever issued to this box (§12.1), re-sent on each
    # check-in so a lost response can't lose one; the agent skips event_ids
    # it already ran. `directives` stays "newly issued" so agents that
    # predate this field keep their at-most-once behavior.
    issued_directives: list = field(default_factory=list)  # list[Directive]


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
_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


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

    if "schema_version" in obj:
        version = obj["schema_version"]
        if isinstance(version, bool) or not isinstance(version, int):
            errors.append("manifest schema_version must be an integer")
        elif version != SCHEMA_VERSION:
            errors.append(
                f"manifest schema_version {version!r} != "
                f"supported {SCHEMA_VERSION!r}"
            )

    scenario_name = obj.get("scenario_name")
    if scenario_name is not None and (
        not isinstance(scenario_name, str) or not scenario_name.strip()
    ):
        errors.append("manifest.scenario_name must be a non-empty string")
    scenario_version = obj.get("scenario_version")
    if scenario_version is not None and (
        isinstance(scenario_version, bool)
        or not isinstance(scenario_version, int)
        or scenario_version < 0
    ):
        errors.append("manifest.scenario_version must be a non-negative integer")

    if "mode" in obj and obj["mode"] not in (Mode.HONOR.value, Mode.RANKED.value):
        errors.append(f"manifest mode must be 'honor' or 'ranked', got {obj['mode']!r}")

    engine_url = obj.get("engine_url")
    if engine_url is not None:
        if not isinstance(engine_url, str) or not engine_url.strip():
            errors.append("manifest.engine_url must be a non-empty string")
        else:
            parts = urlsplit(engine_url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                errors.append(
                    f"manifest.engine_url must be an http(s) URL with a host, "
                    f"got {engine_url!r}"
                )
    if obj.get("mode") == Mode.RANKED.value and not engine_url:
        errors.append("manifest mode is 'ranked' but engine_url is missing/empty")

    hosts = obj.get("hosts")
    if hosts is not None:
        if not isinstance(hosts, list):
            errors.append("manifest.hosts must be a list")
        elif not all(isinstance(h, str) and h.strip() for h in hosts):
            errors.append("manifest.hosts entries must be non-empty strings")

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
            cid = check.get("id")
            if cid is not None:
                if not isinstance(cid, str) or not cid.strip():
                    errors.append(f"{ref}.id must be a non-empty string")
                elif cid in seen_ids:
                    errors.append(f"{ref} duplicate check id '{cid}'")
                else:
                    seen_ids.add(cid)
            check_type = check.get("type")
            if check_type is not None and (
                not isinstance(check_type, str) or not check_type.strip()
            ):
                errors.append(f"{ref}.type must be a non-empty string")
            host_id = check.get("host_id")
            if host_id is not None and (
                not isinstance(host_id, str) or not host_id.strip()
            ):
                errors.append(f"{ref}.host_id must be a non-empty string")
            display_title = check.get("display_title")
            if display_title is not None and not isinstance(display_title, str):
                errors.append(f"{ref}.display_title must be a string")
            max_points = check.get("display_max_points")
            if max_points is not None and (
                isinstance(max_points, bool) or not isinstance(max_points, int)
                or max_points < 0
            ):
                errors.append(f"{ref}.display_max_points must be a non-negative integer")
            timeout_s = check.get("timeout_s")
            if timeout_s is not None and (
                isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float))
                or not math.isfinite(timeout_s) or timeout_s <= 0
            ):
                errors.append(f"{ref}.timeout_s must be a finite positive number")
            is_sla = check.get("is_sla")
            if is_sla is not None and not isinstance(is_sla, bool):
                errors.append(f"{ref}.is_sla must be a boolean")
            if "category" in check and check["category"] not in (
                Category.VULN.value, Category.PENALTY.value, Category.PROHIBITED.value
            ):
                errors.append(
                    f"{ref}.category must be one of vuln/penalty/prohibited, "
                    f"got {check['category']!r}"
                )
            # §6.1: collect_params must never contain rubric data.
            collect_params = check.get("collect_params")
            if collect_params is not None and not isinstance(collect_params, dict):
                errors.append(f"{ref}.collect_params must be an object")
            elif isinstance(collect_params, dict):
                for leaked_key in ("expect", "points", "matcher"):
                    if leaked_key in collect_params:
                        errors.append(
                            f"{ref}.collect_params must not contain '{leaked_key}' "
                            "(rubric data must never ship in the manifest)"
                        )

    forensics = obj.get("forensics")
    if forensics is not None:
        if not isinstance(forensics, list):
            errors.append("manifest.forensics must be a list")
        else:
            seen_fq_ids = set()
            # Collision is against author-written checks only — each forensics
            # question compiles into its own forensics_answer CheckSpec with
            # the same id, which is by design.
            check_ids = {
                c.get("id") for c in (checks or [])
                if isinstance(c, dict) and c.get("id") is not None
                and c.get("type") != "forensics_answer"
            }
            for idx, fq in enumerate(forensics):
                ref = f"manifest.forensics[{idx}]"
                if not isinstance(fq, dict):
                    errors.append(f"{ref} must be an object")
                    continue
                for key in ("id", "question", "max_points"):
                    if key not in fq:
                        errors.append(f"{ref} missing required key '{key}'")
                fid = fq.get("id")
                if fid is not None:
                    if not isinstance(fid, str) or not fid.strip():
                        errors.append(f"{ref}.id must be a non-empty string")
                    elif fid in seen_fq_ids:
                        errors.append(f"{ref} duplicate forensics id '{fid}'")
                    elif fid in check_ids:
                        errors.append(f"{ref} id '{fid}' collides with a check id")
                    seen_fq_ids.add(fid)
                question = fq.get("question")
                if question is not None and (
                    not isinstance(question, str) or not question.strip()
                ):
                    errors.append(f"{ref}.question must be a non-empty string")
                max_points = fq.get("max_points")
                if max_points is not None and (
                    isinstance(max_points, bool) or not isinstance(max_points, int)
                    or max_points <= 0
                ):
                    errors.append(f"{ref}.max_points must be a positive integer")
                # Leak guard: answer keys live only in the rubric.
                for leaked_key in ("answer", "answers"):
                    if leaked_key in fq:
                        errors.append(
                            f"{ref} must not contain '{leaked_key}' "
                            "(answer keys must never ship in the manifest)"
                        )

    theme = obj.get("theme")
    if theme is not None:
        if not isinstance(theme, dict):
            errors.append("manifest.theme must be an object or null")
        else:
            for key in ("title", "organization", "accent", "logo_b64", "readme_text"):
                if key in theme and theme[key] is not None and not isinstance(theme[key], str):
                    errors.append(f"manifest.theme.{key} must be a string")
            accent = theme.get("accent")
            if isinstance(accent, str) and not _ACCENT_RE.match(accent):
                errors.append(
                    f"manifest.theme.accent must be a #rrggbb color, got {accent!r}"
                )

    return errors


def _matcher_errors(matcher, ref: str) -> list:
    """Validate a rubric entry's matcher would resolve at evaluation time.

    Delegates to common.matchers.validate_matcher, which checks the argument
    shapes each predicate reads (field/pattern/value/allowed/...). Keeping one
    validator means the upload-time check and the runtime predicate cannot
    drift.
    """
    if not isinstance(matcher, dict):
        return []  # shape error already reported by the caller
    return [f"{ref}: {err}" for err in validate_matcher(matcher)]


def validate_rubric(obj: dict) -> list:
    """Return a list of human-readable error strings; empty list = valid."""
    errors = []
    if not isinstance(obj, dict):
        return ["rubric must be a JSON object"]

    for key in _REQUIRED_RUBRIC_KEYS:
        if key not in obj:
            errors.append(f"rubric missing required key '{key}'")

    if "schema_version" in obj:
        version = obj["schema_version"]
        if isinstance(version, bool) or not isinstance(version, int):
            errors.append("rubric schema_version must be an integer")
        elif version != SCHEMA_VERSION:
            errors.append(
                f"rubric schema_version {version!r} != "
                f"supported {SCHEMA_VERSION!r}"
            )

    scenario_name = obj.get("scenario_name")
    if scenario_name is not None and (
        not isinstance(scenario_name, str) or not scenario_name.strip()
    ):
        errors.append("rubric.scenario_name must be a non-empty string")
    scenario_version = obj.get("scenario_version")
    if scenario_version is not None and (
        isinstance(scenario_version, bool)
        or not isinstance(scenario_version, int)
        or scenario_version < 0
    ):
        errors.append("rubric.scenario_version must be a non-negative integer")

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
            elif category := entry.get("category"):
                # Sign consistency: hardening earns points, penalties cost them.
                if category == Category.VULN.value and points < 0:
                    errors.append(f"{ref}: category 'vuln' must have points >= 0")
                if category in (Category.PENALTY.value, Category.PROHIBITED.value) and points > 0:
                    errors.append(
                        f"{ref}: category {category!r} must have points <= 0"
                    )
            if not isinstance(entry.get("matcher"), dict):
                errors.append(f"{ref}.matcher must be an object")
            else:
                errors.extend(_matcher_errors(entry["matcher"], ref))
            cid = entry.get("check_id")
            if cid is not None:
                if not isinstance(cid, str) or not cid.strip():
                    errors.append(f"{ref}.check_id must be a non-empty string")
                elif cid in seen_ids:
                    errors.append(f"{ref} duplicate check_id '{cid}'")
                else:
                    seen_ids.add(cid)
            sla = entry.get("sla")
            if sla is not None and not isinstance(sla, dict):
                errors.append(f"{ref}.sla must be an object or null")
            elif isinstance(sla, dict):
                interval_s = sla.get("interval_s")
                if (isinstance(interval_s, bool)
                        or not isinstance(interval_s, (int, float))
                        or not math.isfinite(interval_s)
                        or interval_s <= 0):
                    errors.append(
                        f"{ref}.sla.interval_s must be a finite positive number"
                    )
                ppi = sla.get("points_per_interval")
                if isinstance(ppi, bool) or not isinstance(ppi, int) or ppi <= 0:
                    errors.append(
                        f"{ref}.sla.points_per_interval must be a positive integer"
                    )
                # Optional counters: 0 would make hysteresis trip on every
                # observation (an UP box pinned DOWN, accrual frozen).
                for key in ("hysteresis_fail_n", "hysteresis_ok_n",
                            "max_intervals_per_checkin"):
                    if key in sla:
                        val = sla.get(key)
                        if (isinstance(val, bool) or not isinstance(val, int)
                                or val <= 0):
                            errors.append(
                                f"{ref}.sla.{key} must be a positive integer"
                            )
                # The engine rebuilds SlaParams(**sla) on every check-in: an
                # unknown key would 500 every box in the scenario.
                unknown = sorted(set(sla) - set(SlaParams.__dataclass_fields__))
                if unknown:
                    errors.append(f"{ref}.sla has unknown key(s): {', '.join(unknown)}")

            # A zero-point non-SLA entry can never change the score and (for
            # a VULN) makes the board count a "fixed" issue that awards
            # nothing. SLA entries legitimately carry points=0 because their
            # points come from points_per_interval.
            if (not isinstance(points, bool) and isinstance(points, int)
                    and not isinstance(sla, dict) and points == 0):
                errors.append(
                    f"{ref}.points must be non-zero for a non-SLA entry"
                )

    return errors
