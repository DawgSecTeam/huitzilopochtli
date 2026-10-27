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
        current = current_box_scenario(scenario_name)
        if current is not None and current[0] != scenario_version:
            raise ScenarioNotFound(
                f"scenario {scenario_name!r} version {scenario_version} is not "
                f"current (engine has v{current[0]}); the competition must be "
                f"migrated to the current version"
            )
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
# The engine parses the committed boxes/<box>/scenario.yaml files directly:
# the box folder is the source of truth and the DB is only the serving cache.
# The record is built by the same shared pipeline `boxbuilder compile` uses
# (common.scenario_record), so what the engine serves can never drift from a
# compiled build, and no engine_record.json artefact is required. Only
# scenarios with a ranked: block are listed. The store keeps one version per
# scenario (sync_box_scenarios purges the rest): running a competition against
# anything but the box folder's current version is refused -- competitions are
# migrated when a new version is released, never back-compatible.

import os

import yaml

from common.scenario_record import ScenarioModeError, build_scenario_parts


def boxes_dir() -> str:
    """Configured box folder, or ./boxes when it exists."""
    override = os.environ.get("HUITZILOPOCHTLI_BOXES_DIR", "")
    if override:
        return override
    local = os.path.join(os.getcwd(), "boxes")
    return local if os.path.isdir(local) else ""


_SCAN_LOCK = threading.Lock()
_SCAN_CACHE = {"key": None, "result": (None, ())}


def _scan_box_folder() -> tuple:
    """(scenarios, errors) from one boxes/ pass, cached on file mtimes.

    ``scenarios`` maps scenario name -> (version, box_dir, record), where
    record is the (rubric, adversary, services, pool) tuple for that box's
    current authored version; if two boxes claim one name, the higher version
    wins (an older fork is shadowed, never served) and equal versions are a
    reported collision. ``errors`` carries per-box parse/build problems for
    the admin picker; a broken box never shadows anything. A missing or
    unreadable folder yields ``(None, ())`` -- distinct from an existing but
    empty one, so sync can fail safe instead of purging.

    The cache key stats the folder and every scenario.yaml, so an in-place
    edit invalidates without re-parsing YAML on every call (the sweep loop
    calls this every few seconds).
    """
    root = boxes_dir()
    if not root:
        return None, ()
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return None, ()
    stamps = []
    sources = []
    for box in entries:
        box_path = os.path.join(root, box)
        if not os.path.isdir(box_path):
            continue
        source = os.path.join(box_path, "scenario.yaml")
        try:
            stamps.append((box, os.stat(source).st_mtime_ns))
        except OSError:
            continue  # not a scenario folder
        sources.append((box_path, source))
    key = (root, tuple(stamps))
    with _SCAN_LOCK:
        if _SCAN_CACHE["key"] == key:
            return _SCAN_CACHE["result"]

    scenarios = {}
    declared = set()
    errors = []
    for box_path, source in sources:
        try:
            with open(source, "r", encoding="utf-8") as f:
                parsed = yaml.safe_load(f.read())
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{source}: {exc}")
            continue
        if not isinstance(parsed, dict) or not parsed.get("ranked"):
            continue  # honor-only box: never a ranked competition scenario
        scenario = parsed.get("scenario") or {}
        name = scenario.get("name")
        if isinstance(name, str) and name:
            declared.add(name)
        try:
            parts = build_scenario_parts(parsed, "ranked", source=source)
        except (ScenarioModeError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{source}: {exc}")
            continue
        record = parts["engine_record"]
        rubric = record["rubric"]
        problems = validate_scenario_record(
            rubric, record["adversary"], record["services"], record.get("pool"))
        if problems:
            errors.append(f"{source}: {'; '.join(problems[:4])}")
            continue
        name, version = rubric["scenario_name"], rubric["scenario_version"]
        entry = (version, box_path,
                 (rubric, record["adversary"], record["services"],
                  record.get("pool")))
        previous = scenarios.get(name)
        if previous is None or version > previous[0]:
            if previous is not None:
                errors.append(
                    f"{source}: scenario {name!r} v{version} shadows v"
                    f"{previous[0]} from {previous[1]} (older fork)")
            scenarios[name] = entry
        elif version == previous[0]:
            errors.append(
                f"{source}: scenario {name!r} v{version} is also declared by "
                f"{previous[1]}; rename one of them")
        else:
            errors.append(
                f"{source}: scenario {name!r} v{version} is shadowed by v"
                f"{previous[0]} from {previous[1]} (older fork is ignored)")
    result = (scenarios, tuple(errors))
    with _SCAN_LOCK:
        _SCAN_CACHE["key"] = key
        _SCAN_CACHE["result"] = result
    return result


def list_box_scenarios() -> list:
    """Ranked scenarios found in the box folder: [(name, version, dir)].

    One entry per scenario name -- the box folder's current authored version.
    """
    scenarios, _errors = _scan_box_folder()
    if not scenarios:
        return []
    return sorted((name, version, path)
                  for name, (version, path, _record) in scenarios.items())


def box_folder_errors() -> list:
    """Human-readable problems found while scanning the box folder."""
    return list(_scan_box_folder()[1])


def current_box_scenario(scenario_name: str) -> Optional[tuple]:
    """(version, record) for the box folder's current version of a scenario."""
    scenarios, _errors = _scan_box_folder()
    found = (scenarios or {}).get(scenario_name)
    return None if found is None else (found[0], found[2])


def load_box_scenario(name: str, version: int) -> Optional[tuple]:
    """(rubric, adversary, services, pool) for the box folder's current
    version of a scenario; None for any other version (there is no backlog of
    older versions to serve)."""
    current = current_box_scenario(name)
    if current is None or current[0] != version:
        return None
    return current[1]


def list_admin_scenarios() -> list:
    """(name, version, source) for the admin picker: the box folder only.

    The engine-DB rows are a serving cache seeded from this folder (and,
    historically, uploads); they never add picker entries.
    """
    return list_box_scenarios()


def sync_box_scenarios(store: Store) -> list:
    """Mirror the box folder into the store; returns error strings.

    Upserts every current record and purges every other stored version of
    that scenario. Scenario names the folder no longer declares at all are
    purged too -- but only when the scan was fully clean, so a vanished
    folder (fail-safe) or a box broken mid-edit never wipes a record a live
    run might still be serving. Returns error strings.
    """
    scenarios, errors = _scan_box_folder()
    if scenarios is None:
        return list(errors)
    for name, (version, _path, record) in sorted(scenarios.items()):
        rubric, adversary, services, pool = record
        try:
            save_scenario_record(store, rubric, adversary, services, pool)
        except ScenarioError as exc:
            errors.append(f"{name} v{version}: {exc}")
            continue
        store.delete_scenario_versions(name, keep_version=version)
    if not errors:
        # Orphan purge: rows for scenarios the folder does not declare at all.
        for stored_name, _version, _ts in store.list_scenarios():
            if stored_name not in scenarios:
                store.delete_scenario(stored_name)
    return list(errors)
