"""Engine-side scenario record parsing, validation, and lookup.

Keeping parsing/lookup here (rather than in the HTTP handler) lets the
check-in path load a rubric only *after* the box signature has been verified,
and lets the admin/bootstrap paths share exactly one validator.
"""
import json
import threading

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


def validate_scenario_record(rubric: dict, adversary: dict) -> list:
    """Validate an engine record for upload/bootstrap; empty list = valid."""
    errors = list(validate_rubric(rubric))
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


def save_scenario_record(store: Store, rubric: dict, adversary: dict) -> None:
    """Validate then persist a record keyed by (name, version)."""
    errors = validate_scenario_record(rubric, adversary)
    if errors:
        raise ScenarioError("; ".join(errors))
    store.save_scenario(
        rubric["scenario_name"], rubric["scenario_version"],
        json.dumps(rubric), json.dumps(adversary),
    )
