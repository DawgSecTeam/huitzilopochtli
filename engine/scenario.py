"""Engine-side scenario record parsing, validation, and lookup.

Keeping parsing/lookup here (rather than in the HTTP handler) lets the
check-in path load a rubric only *after* the box signature has been verified,
and lets the admin/bootstrap paths share exactly one validator.
"""
import json
import threading
from typing import Optional

from common.schema import Category, Rubric, RubricEntry, SlaParams, validate_rubric
from common.adversary import validate_adversary_pool
from engine.store import Store


_CACHE = {}
_CACHE_LOCK = threading.Lock()


class ScenarioError(Exception):
    """A stored scenario record is missing or malformed."""


def rubric_from_dict(d: dict) -> Rubric:
    entries = []
    for e in d.get("entries", []):
        sla = e.get("sla")
        sla_obj = SlaParams(**sla) if sla is not None else None
        entries.append(
            RubricEntry(
                check_id=e["check_id"],
                category=Category(e["category"]),
                matcher=e["matcher"],
                points=e["points"],
                sla=sla_obj,
            )
        )
    return Rubric(
        schema_version=d.get("schema_version", 1),
        scenario_name=d.get("scenario_name", ""),
        scenario_version=d.get("scenario_version", 0),
        entries=entries,
    )


def _validate_services(services) -> list:
    errors = []
    if services is None:
        return errors
    if not isinstance(services, list):
        return ["services must be a list"]
    seen = set()
    for idx, svc in enumerate(services):
        ref = f"services[{idx}]"
        if not isinstance(svc, dict):
            errors.append(f"{ref} must be an object")
            continue
        for key in ("id", "check_id", "display", "type", "interval_s",
                    "points_per_interval"):
            if key not in svc:
                errors.append(f"{ref} missing required key '{key}'")
        sid = svc.get("id")
        if not isinstance(sid, str) or not sid:
            errors.append(f"{ref}.id must be a non-empty string")
        elif sid in seen:
            errors.append(f"{ref} duplicate service id {sid!r}")
        else:
            seen.add(sid)
        if not isinstance(svc.get("check_id"), str) or not svc.get("check_id"):
            errors.append(f"{ref}.check_id must be a non-empty string")
        if not isinstance(svc.get("display"), str) or not svc.get("display"):
            errors.append(f"{ref}.display must be a non-empty string")
        if not isinstance(svc.get("type"), str) or not svc.get("type"):
            errors.append(f"{ref}.type must be a non-empty string")
        for key in ("interval_s", "points_per_interval"):
            val = svc.get(key)
            if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
                errors.append(f"{ref}.{key} must be a positive integer")
    return errors


def _validate_pool_spec(pool) -> list:
    """Validate an engine record's optional ``pool`` block.

    Mirrors authoring/validate.py's rules; kept separate because engine/ is
    stdlib-only (authoring pulls in PyYAML). Field names pass through to
    workshop-vm-distribution's POST /api/admin/provision untouched.
    """
    errors = []
    if pool is None:
        return errors
    if not isinstance(pool, dict) or not pool:
        return ["pool must be a non-empty mapping when present"]
    allowed = {
        "template_vm_id", "template_vm_access_method", "template_vm_username",
        "template_vm_password", "vm_count", "guac_link_ttl_seconds",
        "dispenser", "private", "group",
    }
    unknown = sorted(set(pool) - allowed)
    if unknown:
        errors.append(f"pool has unknown key(s): {', '.join(unknown)}")
    for key in ("template_vm_id", "template_vm_access_method",
                "template_vm_username", "template_vm_password"):
        if key not in pool:
            errors.append(f"pool missing required key '{key}'")
    vm_id = pool.get("template_vm_id")
    if vm_id is not None and (isinstance(vm_id, bool) or not isinstance(vm_id, int)
                              or vm_id < 1):
        errors.append("pool.template_vm_id must be a positive integer")
    access = pool.get("template_vm_access_method")
    if access is not None and access not in ("ssh", "vnc", "rdp"):
        errors.append("pool.template_vm_access_method must be one of "
                      "('ssh', 'vnc', 'rdp')")
    for key in ("template_vm_username", "template_vm_password"):
        value = pool.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"pool.{key} must be a non-empty string")
    for key, minimum in (("vm_count", 0), ("guac_link_ttl_seconds", 60)):
        value = pool.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                                  or value < minimum):
            errors.append(f"pool.{key} must be an integer >= {minimum}")
    for key in ("dispenser", "private"):
        value = pool.get(key)
        if value is not None and not isinstance(value, bool):
            errors.append(f"pool.{key} must be a boolean")
    group = pool.get("group")
    if group is not None and group not in ("Workshop", "Challenge", "Generic"):
        errors.append("pool.group must be one of ('Workshop', 'Challenge', 'Generic')")
    return errors


def validate_scenario_record(rubric: dict, adversary: dict,
                             services=None, pool=None) -> list:
    """Validate an engine record for upload/bootstrap; empty list = valid."""
    errors = list(validate_rubric(rubric))
    if services is not None:
        errors.extend(_validate_services(services))
    errors.extend(_validate_pool_spec(pool))
    if isinstance(rubric, dict):
        version = rubric.get("scenario_version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            errors.append("rubric.scenario_version must be a non-negative integer")
        sla_ids = {
            e.get("check_id") for e in (rubric.get("entries") or [])
            if isinstance(e, dict) and isinstance(e.get("sla"), dict)
        }
    else:
        sla_ids = set()
    errors.extend(validate_adversary_pool(adversary))
    if isinstance(adversary, dict) and isinstance(adversary.get("events"), list):
        for idx, event in enumerate(adversary["events"]):
            if not isinstance(event, dict):
                continue
            affects = event.get("affects_check")
            if affects is None:
                continue
            if not isinstance(affects, str) or affects not in sla_ids:
                errors.append(
                    f"adversary.events[{idx}].affects_check must name an SLA "
                    f"check in this rubric, got {affects!r}"
                )
    return errors


def parse_stored_record(record: dict) -> tuple:
    """(Rubric, event_pool) from a store row; raises ScenarioError."""
    try:
        rubric_dict = json.loads(record["rubric_json"])
        adversary = json.loads(record["adversary_json"])
        errors = validate_scenario_record(rubric_dict, adversary)
        if errors:
            raise ScenarioError("; ".join(errors[:8]))
        return rubric_from_dict(rubric_dict), list(adversary.get("events", []))
    except ScenarioError:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise ScenarioError(str(exc)) from exc


def load_services(store: Store, scenario_name: str,
                  scenario_version: int) -> list:
    """Public service metadata for a scenario (empty for legacy records)."""
    record = store.get_scenario(scenario_name, scenario_version)
    if record is None:
        return []
    try:
        data = json.loads(record.get("services_json") or "[]")
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []


class ScenarioNotFound(ScenarioError):
    """No stored record for the requested (name, version)."""


def load_scenario(store: Store, scenario_name: str,
                  scenario_version: int) -> tuple:
    """Load the exact enrolled version; raises ScenarioNotFound.

    Parsed records are cached by upload timestamp so a check-in does not
    re-parse the rubric JSON (and recompile matcher regexes) every cycle.
    """
    record = store.get_scenario(scenario_name, scenario_version)
    if record is None:
        raise ScenarioNotFound(
            f"no engine record for {scenario_name!r} version {scenario_version}"
        )
    key = (scenario_name, scenario_version)
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == record["uploaded_at"]:
            return cached[1]
    parsed = parse_stored_record(record)
    with _CACHE_LOCK:
        _CACHE[key] = (record["uploaded_at"], parsed)
    return parsed


def save_scenario_record(store: Store, rubric: dict, adversary: dict,
                         services: Optional[list] = None,
                         pool: Optional[dict] = None) -> None:
    """Validate then persist a record keyed by (name, version)."""
    errors = validate_scenario_record(rubric, adversary, services, pool)
    if errors:
        raise ScenarioError("; ".join(errors))
    store.save_scenario(
        rubric["scenario_name"], rubric["scenario_version"],
        json.dumps(rubric), json.dumps(adversary),
        json.dumps(services or []),
        json.dumps(pool) if pool else None,
    )


def load_pool_spec(store: Store, scenario_name: str,
                   scenario_version: int) -> Optional[dict]:
    """The scenario's workshop pool provisioning block, or None."""
    record = store.get_scenario(scenario_name, scenario_version)
    if record is None or not record.get("pool_json"):
        return None
    try:
        data = json.loads(record["pool_json"])
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) and data else None


# --- repo box-folder source ---------------------------------------------------
#
# Ranked scenarios live in the repo: each box folder carries its compiled
# ``engine_record.json`` (rubric + adversary + services, produced by
# authoring compile). The engine never reads YAML (stdlib-only); the folder is
# the source of truth and the DB is the serving cache.

import os



def boxes_dir() -> str:
    """Configured box folder, or ./boxes when it exists."""
    override = os.environ.get("HUITZILOPOCHTLI_BOXES_DIR", "")
    if override:
        return override
    local = os.path.join(os.getcwd(), "boxes")
    return local if os.path.isdir(local) else ""


def _read_record(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)
    except (OSError, ValueError):
        return None
    rubric = record.get("rubric")
    if not isinstance(rubric, dict):
        return None
    name, version = rubric.get("scenario_name"), rubric.get("scenario_version")
    if not isinstance(name, str) or not name or not isinstance(version, int):
        return None
    return record


def list_box_scenarios() -> list:
    """Ranked scenarios found in the box folder: [(name, version, dir)]."""
    root = boxes_dir()
    if not root:
        return []
    found = {}
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return []
    for box in entries:
        box_path = os.path.join(root, box)
        if not os.path.isdir(box_path):
            continue
        for fname in sorted(os.listdir(box_path)):
            if not (fname == "engine_record.json"
                    or (fname.startswith("engine_record-") and fname.endswith(".json"))):
                continue
            record = _read_record(os.path.join(box_path, fname))
            if record is None:
                continue
            if record.get("mode") != "ranked":
                continue  # only ranked boxes are competition scenarios
            rubric = record["rubric"]
            found[(rubric["scenario_name"], rubric["scenario_version"])] = box_path
    return sorted((name, version, path)
                  for (name, version), path in found.items())


def list_admin_scenarios(store) -> list:
    """(name, version, source) for the admin picker.

    Engine-uploaded records come first, then ranked records found in the box
    folder. The folder still wins on import when it is present (the box build
    is the source of truth there), but an engine that has no box folder -- the
    deployed layout -- must still be able to start a competition from what it
    has been given.
    """
    found = {}
    for name, version, _uploaded_at in store.list_scenarios():
        found[(name, version)] = "engine"
    for name, version, path in list_box_scenarios():
        found.setdefault((name, version), path)
    return sorted(
        ((name, version, source) for (name, version), source in found.items()),
        key=lambda row: (row[0].lower(), row[1]),
    )


def load_box_scenario(name: str, version: int) -> Optional[tuple]:
    """(rubric, adversary, services, pool) for a record in the box folder."""
    for box_name, box_version, path in list_box_scenarios():
        if box_name != name or box_version != version:
            continue
        for fname in sorted(os.listdir(path)):
            if not fname.startswith("engine_record") or not fname.endswith(".json"):
                continue
            record = _read_record(os.path.join(path, fname))
            if record is None:
                continue
            rubric = record["rubric"]
            if (rubric["scenario_name"], rubric["scenario_version"]) == (name, version):
                pool = record.get("pool")
                return (rubric, record.get("adversary") or {},
                        record.get("services") or [],
                        pool if isinstance(pool, dict) and pool else None)
    return None
