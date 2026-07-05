"""Author-facing validation. See architecture.md §6.7, §8.

PHASE 1 TASK: implement. Wraps common.schema.validate_manifest /
validate_rubric (structural validation of compiled JSON) with YAML-source
line-number mapping so build failures are line-referenced for the author.
"""

_VALID_MODES = ("honor", "ranked")
_VALID_CATEGORIES = ("vuln", "penalty", "prohibited")

# Required keys on each `checks[]` entry, per architecture.md §8.
_REQUIRED_CHECK_KEYS = ("id", "type", "category", "display", "max_points", "collect", "expect")


def validate_scenario_yaml(parsed_yaml: dict, source_path: str) -> list:
    """Returns a list of human-readable, line-referenced error strings;
    empty list = valid. Called before compile.py splits the scenario into
    manifest/rubric/engine record.

    NOTE ON "LINE-REFERENCED": raw YAML parsed via yaml.safe_load does not
    carry line numbers without a custom Loader/constructor. As a best-effort
    substitute, errors reference the entry's *index* within its containing
    list (e.g. "checks[2]") rather than a true source line number. This is
    an acceptable simplification for now; a custom loader that tags nodes
    with line numbers could replace this later without changing the return
    contract (still a list of strings).
    """
    errors = []

    if not isinstance(parsed_yaml, dict):
        return [f"{source_path}: top-level YAML document must be a mapping"]

    scenario = parsed_yaml.get("scenario")
    if scenario is None:
        return [f"{source_path}: missing required top-level key 'scenario'"]
    if not isinstance(scenario, dict):
        return [f"{source_path}: 'scenario' must be a mapping"]

    # --- scenario-level required keys ---------------------------------
    for key in ("name", "version", "mode", "hosts"):
        if key not in scenario:
            errors.append(f"{source_path}: scenario missing required key '{key}'")

    mode = scenario.get("mode")
    if mode is not None and mode not in _VALID_MODES:
        errors.append(
            f"{source_path}: scenario.mode must be one of {_VALID_MODES!r}, got {mode!r}"
        )

    hosts = scenario.get("hosts")
    if hosts is not None and not isinstance(hosts, list):
        errors.append(f"{source_path}: scenario.hosts must be a list")

    if mode == "ranked" and not scenario.get("engine_url"):
        errors.append(
            f"{source_path}: scenario.engine_url is required when mode is 'ranked'"
        )

    # --- checks[] ---------------------------------------------------------
    # NOTE: per the §8 YAML example, `checks` is a TOP-LEVEL key (a sibling
    # of `scenario`), not nested under `scenario`. Likewise `adversary`.
    checks = parsed_yaml.get("checks")
    if checks is None:
        errors.append(f"{source_path}: missing required top-level key 'checks'")
    elif not isinstance(checks, list):
        errors.append(f"{source_path}: 'checks' must be a list")
    else:
        for idx, check in enumerate(checks):
            ref = f"checks[{idx}]"
            if not isinstance(check, dict):
                errors.append(f"{source_path}: {ref} must be a mapping")
                continue

            for key in _REQUIRED_CHECK_KEYS:
                if key not in check:
                    errors.append(f"{source_path}: {ref} missing required key '{key}'")

            category = check.get("category")
            if category is not None and category not in _VALID_CATEGORIES:
                errors.append(
                    f"{source_path}: {ref}.category must be one of "
                    f"{_VALID_CATEGORIES!r}, got {category!r}"
                )

            collect = check.get("collect")
            if collect is not None and not isinstance(collect, dict):
                errors.append(f"{source_path}: {ref}.collect must be a mapping")

            expect = check.get("expect")
            if expect is not None and not isinstance(expect, dict):
                errors.append(f"{source_path}: {ref}.expect must be a mapping")

    return errors
