"""Author-facing validation. See architecture.md §6.7, §8.

This is the first line of defense for a release: a typo in a check type,
matcher argument, timeout, points value, engine URL, or adversary event should
fail `compile` with an actionable message instead of surfacing as a silent
zero or a runtime traceback on a box.
"""
import math
import re
from urllib.parse import urlsplit

from common.adversary import validate_adversary_pool
from common.check_types import CHECK_TYPES
from common.matchers import validate_matcher

_VALID_MODES = ("honor", "ranked")
_VALID_CATEGORIES = ("vuln", "penalty", "prohibited")

_TOP_LEVEL_KEYS = frozenset({"scenario", "checks", "services", "theme", "forensics",
                             "adversary", "pool", "ranked"})
_SCENARIO_KEYS = frozenset({"name", "version", "mode", "hosts", "engine_url"})
_RANKED_KEYS = frozenset({"engine_url", "checks", "services", "adversary", "pool"})

# workshop-vm-distribution provision API contract (provision.GROUPS there).
_POOL_GROUPS = ("Workshop", "Challenge", "Generic")
_POOL_ACCESS_METHODS = ("ssh", "vnc", "rdp")
_POOL_KEYS = frozenset({
    "template_vm_id", "template_vm_access_method", "template_vm_username",
    "template_vm_password", "vm_count", "guac_link_ttl_seconds",
    "dispenser", "private", "group",
})

# Required keys on each `checks[]` entry, per architecture.md §8.
_REQUIRED_CHECK_KEYS = ("id", "type", "category", "display", "max_points", "collect", "expect")
_CHECK_KEYS = frozenset(set(_REQUIRED_CHECK_KEYS) | {"host_id", "timeout_s", "is_sla", "solution"})

# Minimal collect_params each check implementation reads. Extra keys are
# allowed (future/specialized options), missing required keys are not.
_REQUIRED_COLLECT = {
    "file_regex": ("path", "extract"),
    "permission": ("path",),
    "service_state": ("service",),
    "package": ("package",),
    "process_state": ("pattern",),
    "http_uptime": ("url",),
    "db_query": ("host", "port"),
    "forensics_answer": ("path", "question_id", "ordinal"),
    "command_json": ("script",),
    "powershell_json": ("script",),
    "registry_value": ("hive", "key"),
    "tcp_port": ("host", "port"),
}

_THEME_KEYS = frozenset({
    "title", "organization", "accent", "logo", "wallpaper", "readme", "motd",
    "issue", "desktop_shortcuts", "include_report_shortcut", "readme_lint_allow",
    "forensics_questions",
})
_THEME_STRING_KEYS = ("title", "organization", "accent", "logo", "wallpaper", "readme", "motd", "issue")
_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _is_finite_number(value) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def _validate_sla_block(sla, ref: str) -> tuple:
    """Validate expect.sla; returns (errors, valid_bool)."""
    errors = []
    if not isinstance(sla, dict):
        return [f"{ref}.expect.sla must be a mapping"], False
    allowed = {"interval_s", "points_per_interval", "hysteresis_fail_n",
               "hysteresis_ok_n", "max_intervals_per_checkin"}
    unknown = sorted(set(sla) - allowed)
    if unknown:
        errors.append(f"{ref}.expect.sla has unknown key(s): {', '.join(unknown)}")
    interval = sla.get("interval_s")
    if not _is_finite_number(interval) or interval <= 0:
        errors.append(f"{ref}.expect.sla.interval_s must be a finite positive number")
    ppi = sla.get("points_per_interval")
    if isinstance(ppi, bool) or not isinstance(ppi, int) or ppi <= 0:
        errors.append(f"{ref}.expect.sla.points_per_interval must be a positive integer")
    for key in ("hysteresis_fail_n", "hysteresis_ok_n", "max_intervals_per_checkin"):
        if key in sla:
            value = sla[key]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                errors.append(f"{ref}.expect.sla.{key} must be a positive integer")
    return errors, not errors


def validate_scenario_yaml(parsed_yaml: dict, source_path: str) -> list:
    """Validate scenario YAML; returns list of error strings (empty = valid)."""
    errors = []

    if not isinstance(parsed_yaml, dict):
        return [f"{source_path}: top-level YAML document must be a mapping"]

    unknown_top = sorted(set(parsed_yaml) - _TOP_LEVEL_KEYS)
    if unknown_top:
        errors.append(
            f"{source_path}: unknown top-level key(s): {', '.join(unknown_top)} "
            f"(allowed: {', '.join(sorted(_TOP_LEVEL_KEYS))})"
        )

    scenario = parsed_yaml.get("scenario")
    if scenario is None:
        return [f"{source_path}: missing required top-level key 'scenario'"]
    if not isinstance(scenario, dict):
        return [f"{source_path}: 'scenario' must be a mapping"]

    unknown_scenario = sorted(set(scenario) - _SCENARIO_KEYS)
    if unknown_scenario:
        errors.append(
            f"{source_path}: unknown scenario key(s): {', '.join(unknown_scenario)}"
        )

    # --- scenario-level required keys and types ------------------------
    for key in ("name", "version", "mode", "hosts"):
        if key not in scenario:
            errors.append(f"{source_path}: scenario missing required key '{key}'")

    name = scenario.get("name")
    if name is not None and (not isinstance(name, str) or not name.strip()):
        errors.append(f"{source_path}: scenario.name must be a non-empty string")

    version = scenario.get("version")
    if version is not None and (
        isinstance(version, bool) or not isinstance(version, int) or version < 0
    ):
        errors.append(f"{source_path}: scenario.version must be a non-negative integer")

    mode = scenario.get("mode")
    if mode is not None and mode not in _VALID_MODES:
        errors.append(
            f"{source_path}: scenario.mode must be one of {_VALID_MODES!r}, got {mode!r}"
        )

    hosts = scenario.get("hosts")
    if hosts is not None:
        if not isinstance(hosts, list):
            errors.append(f"{source_path}: scenario.hosts must be a list")
        elif not all(isinstance(h, str) and h.strip() for h in hosts):
            errors.append(f"{source_path}: scenario.hosts entries must be non-empty strings")

    ranked = parsed_yaml.get("ranked")
    if ranked is not None and not isinstance(ranked, dict):
        errors.append(f"{source_path}: 'ranked' must be a mapping")
        ranked = {}
    ranked = ranked or {}
    unknown_ranked = sorted(set(ranked) - _RANKED_KEYS)
    if unknown_ranked:
        errors.append(
            f"{source_path}: ranked block has unknown key(s): "
            f"{', '.join(unknown_ranked)} (allowed: {', '.join(sorted(_RANKED_KEYS))})"
        )

    for label, value in (("scenario.engine_url", scenario.get("engine_url")),
                         ("ranked.engine_url", ranked.get("engine_url"))):
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{source_path}: {label} must be a non-empty string")
        else:
            parts = urlsplit(value)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                errors.append(
                    f"{source_path}: {label} must be an http(s) URL "
                    f"with a host, got {value!r}"
                )

    # An engine address may live in the ranked block; a ranked build without
    # one is a deployment that would silently target nothing.
    if (mode == "ranked" or ranked) and not (
            scenario.get("engine_url") or ranked.get("engine_url")):
        errors.append(
            f"{source_path}: an engine_url is required for a ranked build "
            f"(put it in the top-level 'ranked' block)"
        )

    # Ranked-only content belongs under `ranked:`. On a ranked-only file the
    # legacy top-level placement is still accepted.
    for key in ("services", "adversary", "pool"):
        if key in parsed_yaml and "ranked" not in parsed_yaml and mode == "honor":
            errors.append(
                f"{source_path}: '{key}' is ranked-only; move it under the "
                f"top-level 'ranked:' block"
            )
    if "pool" in parsed_yaml:
        errors.extend(_validate_pool(parsed_yaml.get("pool"), source_path))
    if "pool" in ranked:
        errors.extend(_validate_pool(ranked.get("pool"), source_path))

    checks = parsed_yaml.get("checks")
    check_by_id = {}
    if checks is None:
        errors.append(f"{source_path}: missing required top-level key 'checks'")
    elif not isinstance(checks, list):
        errors.append(f"{source_path}: 'checks' must be a list")
        checks = []
    else:
        _validate_checks(checks, source_path, "checks", errors, check_by_id)

    ranked_checks = ranked.get("checks")
    if ranked_checks is not None and not isinstance(ranked_checks, list):
        errors.append(f"{source_path}: ranked.checks must be a list")
        ranked_checks = []
    elif ranked_checks:
        # Ranked-only checks share the base id namespace: a collision would
        # silently drop one entry from the rubric.
        _validate_checks(ranked_checks, source_path, "ranked.checks", errors,
                         check_by_id)
    ranked_checks = ranked_checks or []

    all_checks = list(checks or []) + list(ranked_checks)

    services = ranked.get("services") or parsed_yaml.get("services") or []
    if services:
        errors.extend(_validate_services(services, all_checks, source_path))
    if not all_checks and not parsed_yaml.get("forensics") and not services:
        errors.append(
            f"{source_path}: scenario has no checks, services, or forensics questions"
        )

    # --- adversary ------------------------------------------------------
    if "adversary" in ranked or "adversary" in parsed_yaml:
        adversary = ranked.get("adversary") or parsed_yaml.get("adversary")
        adv_errors = validate_adversary_pool(adversary)
        errors.extend(f"{source_path}: {e}" for e in adv_errors)
        service_ids = {
            s.get("id") for s in services
            if isinstance(s, dict) and isinstance(s.get("id"), str)
        }
        if isinstance(adversary, dict) and isinstance(adversary.get("events"), list):
            for idx, event in enumerate(adversary["events"]):
                if not isinstance(event, dict):
                    continue
                affects = event.get("affects_check")
                if affects is None or not isinstance(affects, str):
                    continue
                if affects in service_ids:
                    continue
                target = check_by_id.get(affects)
                if target is None:
                    errors.append(
                        f"{source_path}: adversary.events[{idx}].affects_check "
                        f"{affects!r} is not a check id or service id in this scenario"
                    )
                elif not isinstance((target.get("expect") or {}).get("sla"), dict):
                    errors.append(
                        f"{source_path}: adversary.events[{idx}].affects_check "
                        f"{affects!r} must name an SLA check (expect.sla)"
                    )

    if "theme" in parsed_yaml:
        errors.extend(_validate_theme(parsed_yaml.get("theme"), source_path))

    if "forensics" in parsed_yaml:
        errors.extend(_validate_forensics(parsed_yaml.get("forensics"), all_checks,
                                          source_path))

    return errors


def _validate_checks(checks: list, source_path: str, prefix: str,
                     errors: list, check_by_id: dict) -> None:
    """Validate one ``checks``-shaped list, appending to ``errors`` in place."""
    for idx, check in enumerate(checks):
        ref = f"{prefix}[{idx}]"
        if not isinstance(check, dict):
            errors.append(f"{source_path}: {ref} must be a mapping")
            continue

        unknown_check = sorted(set(check) - _CHECK_KEYS)
        if unknown_check:
            errors.append(
                f"{source_path}: {ref} has unknown key(s): {', '.join(unknown_check)}"
            )

        for key in _REQUIRED_CHECK_KEYS:
            if key not in check:
                errors.append(f"{source_path}: {ref} missing required key '{key}'")

        cid = check.get("id")
        if cid is not None:
            if not isinstance(cid, str) or not cid.strip():
                errors.append(f"{source_path}: {ref}.id must be a non-empty string")
            elif cid in check_by_id:
                errors.append(f"{source_path}: {ref} duplicate check id {cid!r}")
            else:
                check_by_id[cid] = check

        check_type = check.get("type")
        if check_type is not None:
            if not isinstance(check_type, str) or not check_type.strip():
                errors.append(f"{source_path}: {ref}.type must be a non-empty string")
            elif check_type not in CHECK_TYPES:
                errors.append(
                    f"{source_path}: {ref}.type {check_type!r} is not a registered "
                    f"check type (known: {', '.join(sorted(CHECK_TYPES))})"
                )

        category = check.get("category")
        if category is not None and category not in _VALID_CATEGORIES:
            errors.append(
                f"{source_path}: {ref}.category must be one of "
                f"{_VALID_CATEGORIES!r}, got {category!r}"
            )

        display = check.get("display")
        if display is not None and (not isinstance(display, str) or not display.strip()):
            errors.append(f"{source_path}: {ref}.display must be a non-empty string")

        max_points = check.get("max_points")
        if max_points is not None and (
            isinstance(max_points, bool) or not isinstance(max_points, int)
            or max_points < 0
        ):
            errors.append(f"{source_path}: {ref}.max_points must be a non-negative integer")

        timeout_s = check.get("timeout_s")
        if timeout_s is not None and (
            not _is_finite_number(timeout_s) or timeout_s <= 0
        ):
            errors.append(f"{source_path}: {ref}.timeout_s must be a finite positive number")

        is_sla = check.get("is_sla")
        if is_sla is not None and not isinstance(is_sla, bool):
            errors.append(f"{source_path}: {ref}.is_sla must be a boolean")

        collect = check.get("collect")
        if collect is not None and not isinstance(collect, dict):
            errors.append(f"{source_path}: {ref}.collect must be a mapping")
        elif isinstance(collect, dict) and isinstance(check_type, str):
            for required_key in _REQUIRED_COLLECT.get(check_type, ()):
                if required_key not in collect:
                    errors.append(
                        f"{source_path}: {ref}.collect missing required key "
                        f"'{required_key}' for type {check_type!r}"
                    )

        expect = check.get("expect")
        if "expect" in check:
            if not isinstance(expect, dict) or len(expect) == 0:
                errors.append(
                    f"{source_path}: {ref}.expect must be a non-null, "
                    f"non-empty mapping (an empty matcher crashes the evaluator)"
                )
            elif isinstance(expect, dict):
                errors.extend(
                    _validate_expect(check, expect, ref, source_path,
                                     check_type, category, max_points, is_sla)
                )

        if "solution" in check:
            errors.extend(
                _validate_solution(check["solution"], f"{source_path}: {ref}.solution")
            )


_ENV_PLACEHOLDER_RE = re.compile(r"^\$\{[A-Z0-9_]+\}$")


def _is_env_placeholder(value) -> bool:
    """A deployment-supplied value (`${VAR}`), resolved when a ranked build runs."""
    return isinstance(value, str) and bool(_ENV_PLACEHOLDER_RE.match(value))


def _validate_pool(pool, source_path: str) -> list:
    """Validate the ``pool`` block that lives under ``ranked:``.

    The engine provisions one workshop pool per competition from this block;
    field names mirror the workshop portal's POST /api/admin/provision 1:1 so
    the engine can pass them through untouched.
    """
    errors = []
    if pool is None or not isinstance(pool, dict) or not pool:
        return [f"{source_path}: 'pool' must be a non-empty mapping"]

    unknown = sorted(set(pool) - _POOL_KEYS)
    if unknown:
        errors.append(f"{source_path}: pool has unknown key(s): {', '.join(unknown)}")

    for key in ("template_vm_id", "template_vm_access_method",
                "template_vm_username", "template_vm_password"):
        if key not in pool:
            errors.append(f"{source_path}: pool missing required key '{key}'")

    vm_id = pool.get("template_vm_id")
    if _is_env_placeholder(vm_id):
        pass
    elif vm_id is not None and (isinstance(vm_id, bool) or not isinstance(vm_id, int)
                                or vm_id < 1):
        errors.append(f"{source_path}: pool.template_vm_id must be a positive integer")

    access = pool.get("template_vm_access_method")
    if access is not None and access not in _POOL_ACCESS_METHODS:
        errors.append(
            f"{source_path}: pool.template_vm_access_method must be one of "
            f"{_POOL_ACCESS_METHODS!r}, got {access!r}"
        )

    for key in ("template_vm_username", "template_vm_password"):
        value = pool.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{source_path}: pool.{key} must be a non-empty string")

    for key, minimum in (("vm_count", 0), ("guac_link_ttl_seconds", 60)):
        value = pool.get(key)
        if _is_env_placeholder(value):
            continue
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                                  or value < minimum):
            errors.append(
                f"{source_path}: pool.{key} must be an integer >= {minimum}"
            )

    for key in ("dispenser", "private"):
        value = pool.get(key)
        if value is not None and not isinstance(value, bool):
            errors.append(f"{source_path}: pool.{key} must be a boolean")

    group = pool.get("group")
    if group is not None and group not in _POOL_GROUPS:
        errors.append(
            f"{source_path}: pool.group must be one of {_POOL_GROUPS!r}, got {group!r}"
        )

    return errors


_SERVICE_KEYS = frozenset({
    "id", "display", "type", "collect", "expect", "interval_s",
    "points_per_interval", "hysteresis_fail_n", "hysteresis_ok_n",
    "max_intervals_per_checkin", "timeout_s", "solution",
})


def _validate_services(services, checks, source_path: str) -> list:
    errors = []
    if not isinstance(services, list):
        return [f"{source_path}: 'services' must be a list"]
    check_ids = {c.get("id") for c in (checks or [])
                 if isinstance(c, dict) and isinstance(c.get("id"), str)}
    seen = set()
    for idx, svc in enumerate(services):
        ref = f"services[{idx}]"
        if not isinstance(svc, dict):
            errors.append(f"{source_path}: {ref} must be a mapping")
            continue
        unknown = sorted(set(svc) - _SERVICE_KEYS)
        if unknown:
            errors.append(
                f"{source_path}: {ref} has unknown key(s): {', '.join(unknown)}"
            )
        for key in ("id", "display", "type", "collect", "expect",
                    "interval_s", "points_per_interval"):
            if key not in svc:
                errors.append(f"{source_path}: {ref} missing required key '{key}'")
        sid = svc.get("id")
        if isinstance(sid, str) and sid:
            if sid in seen:
                errors.append(f"{source_path}: {ref} duplicate service id {sid!r}")
            seen.add(sid)
            if f"svc_{sid}" in check_ids:
                errors.append(
                    f"{source_path}: {ref} service id {sid!r} collides with "
                    f"check id 'svc_{sid}'"
                )
        elif sid is not None:
            errors.append(f"{source_path}: {ref}.id must be a non-empty string")
        display = svc.get("display")
        if display is not None and (not isinstance(display, str) or not display.strip()):
            errors.append(f"{source_path}: {ref}.display must be a non-empty string")
        stype = svc.get("type")
        if isinstance(stype, str) and stype and stype not in CHECK_TYPES:
            errors.append(
                f"{source_path}: {ref}.type {stype!r} is not a registered check type "
                f"(known: {', '.join(sorted(CHECK_TYPES))})"
            )
        collect = svc.get("collect")
        if collect is not None and not isinstance(collect, dict):
            errors.append(f"{source_path}: {ref}.collect must be a mapping")
        elif isinstance(collect, dict) and isinstance(stype, str):
            for required_key in _REQUIRED_COLLECT.get(stype, ()):
                if required_key not in collect:
                    errors.append(
                        f"{source_path}: {ref}.collect missing required key "
                        f"'{required_key}' for type {stype!r}"
                    )
        expect = svc.get("expect")
        if not isinstance(expect, dict) or not expect:
            errors.append(f"{source_path}: {ref}.expect must be a non-empty mapping")
        else:
            for err in validate_matcher(expect):
                errors.append(f"{source_path}: {ref}.expect {err}")
        for key in ("interval_s", "points_per_interval"):
            val = svc.get(key)
            if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
                errors.append(f"{source_path}: {ref}.{key} must be a positive integer")
        for key in ("hysteresis_fail_n", "hysteresis_ok_n",
                    "max_intervals_per_checkin"):
            if key in svc:
                val = svc[key]
                if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
                    errors.append(f"{source_path}: {ref}.{key} must be a positive integer")
        timeout_s = svc.get("timeout_s")
        if timeout_s is not None and (
                not _is_finite_number(timeout_s) or timeout_s <= 0):
            errors.append(f"{source_path}: {ref}.timeout_s must be a finite positive number")
    return errors


def _validate_expect(check, expect, ref, source_path, check_type, category,
                     max_points, is_sla) -> list:
    """Validate points/sla/matcher consistency for one check."""
    errors = []
    expect = dict(expect)
    points = expect.pop("points", None)
    sla_raw = expect.pop("sla", None)
    sla_valid = False

    if points is None:
        errors.append(
            f"{source_path}: {ref}.expect.points is required so the check can "
            f"actually change the score"
        )
    elif isinstance(points, bool) or not isinstance(points, int):
        errors.append(f"{source_path}: {ref}.expect.points must be an integer")

    if sla_raw is not None:
        sla_errors, sla_valid = _validate_sla_block(sla_raw, ref)
        errors.extend(f"{source_path}: {e}" for e in sla_errors)
        if is_sla is False:
            errors.append(
                f"{source_path}: {ref} sets expect.sla but explicitly disables is_sla"
            )
    elif is_sla is True:
        errors.append(
            f"{source_path}: {ref} sets is_sla: true without expect.sla; either add "
            f"the SLA parameters or remove is_sla"
        )
    elif isinstance(points, int) and not isinstance(points, bool) and points == 0:
        errors.append(
            f"{source_path}: {ref}.expect.points must be non-zero for a non-SLA check"
        )

    if (isinstance(points, int) and not isinstance(points, bool)
            and isinstance(max_points, int) and not isinstance(max_points, bool)):
        if sla_raw is not None:
            if max_points <= 0:
                errors.append(f"{source_path}: {ref}.max_points must be positive for an SLA check")
        else:
            expected_max = points if category == "vuln" else abs(points)
            if max_points != expected_max:
                errors.append(
                    f"{source_path}: {ref}.max_points ({max_points}) must match "
                    f"expect.points ({points}) for category {category!r}"
                )

    # Matcher argument validation (shared with the engine).
    for err in validate_matcher(expect):
        errors.append(f"{source_path}: {ref}.expect {err}")

    if check_type == "file_regex":
        # YAML 1.1: unquoted no/yes/true/false become booleans, and
        # `equals: false` never matches string evidence like "no"
        # (PermitRootLogin no) — silently scoring 0 forever.
        for exp_key, exp_val in expect.items():
            if isinstance(exp_val, bool) or (
                    isinstance(exp_val, list)
                    and any(isinstance(i, bool) for i in exp_val)):
                errors.append(
                    f"{source_path}: {ref}.expect.{exp_key} is a boolean "
                    f"({exp_val!r}) — YAML parsed an unquoted yes/no/true/false, "
                    f"but file_regex evidence is a string. Quote it if a string "
                    f"was meant (e.g. {exp_key}: 'no')."
                )
    return errors


_FORENSIC_KEYS = ("id", "question", "answer", "answers", "points", "path", "solution")


def _validate_solution(value, ref: str) -> list:
    """Authored walkthrough body (answer-key handouts only, never compiled):
    a non-empty string, or a non-empty list of non-empty strings."""
    valid = isinstance(value, str) and bool(value.strip())
    if isinstance(value, list):
        valid = bool(value) and all(isinstance(s, str) and s.strip() for s in value)
    if not valid:
        return [
            f"{ref} must be a non-empty string or a non-empty list "
            f"of non-empty strings, got {type(value).__name__}"
        ]
    return []


def _validate_forensics(forensics, checks, source_path: str) -> list:
    """Validate the optional scored ``forensics`` block."""
    errors = []
    if forensics is None:
        return [f"{source_path}: 'forensics' must be a list of question mappings"]
    if not isinstance(forensics, list):
        return [f"{source_path}: 'forensics' must be a list of question mappings"]

    check_ids = {
        c.get("id") for c in (checks or [])
        if isinstance(c, dict) and c.get("id") is not None
    }
    seen_ids = set()
    for idx, fq in enumerate(forensics):
        ref = f"forensics[{idx}]"
        if not isinstance(fq, dict):
            errors.append(f"{source_path}: {ref} must be a mapping")
            continue

        for key in fq:
            if key not in _FORENSIC_KEYS:
                errors.append(
                    f"{source_path}: {ref} has unknown key '{key}' "
                    f"(expected one of {_FORENSIC_KEYS!r})"
                )

        for key in ("id", "question", "points"):
            if key not in fq:
                errors.append(f"{source_path}: {ref} missing required key '{key}'")

        fid = fq.get("id")
        if fid is not None:
            if not isinstance(fid, str) or not fid.strip():
                errors.append(f"{source_path}: {ref}.id must be a non-empty string")
            elif fid in seen_ids:
                errors.append(f"{source_path}: {ref} duplicate forensics id '{fid}'")
            elif fid in check_ids:
                errors.append(
                    f"{source_path}: {ref} id '{fid}' collides with a check id"
                )
            seen_ids.add(fid)

        question = fq.get("question")
        if question is not None and (not isinstance(question, str) or not question.strip()):
            errors.append(f"{source_path}: {ref}.question must be a non-empty string")

        points = fq.get("points")
        if points is not None and (
            isinstance(points, bool) or not isinstance(points, int) or points <= 0
        ):
            errors.append(f"{source_path}: {ref}.points must be a positive integer")

        has_answer = "answer" in fq
        has_answers = "answers" in fq
        if has_answer:
            answer = fq.get("answer")
            if not isinstance(answer, str) or not answer.strip():
                errors.append(f"{source_path}: {ref}.answer must be a non-empty string")
        if has_answers:
            answers = fq.get("answers")
            if (
                not isinstance(answers, list)
                or not answers
                or not all(isinstance(a, str) and a.strip() for a in answers)
            ):
                errors.append(
                    f"{source_path}: {ref}.answers must be a non-empty list of "
                    "non-empty strings"
                )
        if not has_answer and not has_answers:
            errors.append(
                f"{source_path}: {ref} missing required key 'answer' (or 'answers')"
            )

        path = fq.get("path")
        if path is not None and (not isinstance(path, str) or not path.strip()):
            errors.append(f"{source_path}: {ref}.path must be a non-empty string")

        if "solution" in fq:
            errors.extend(
                _validate_solution(fq["solution"], f"{source_path}: {ref}.solution")
            )

    return errors


def _validate_theme(theme, source_path: str) -> list:
    """Validate optional ``theme`` block (structural only, no filesystem access)."""
    errors = []

    if theme is None or (isinstance(theme, dict) and len(theme) == 0):
        return errors
    if not isinstance(theme, dict):
        return [f"{source_path}: 'theme' must be a mapping"]

    unknown = sorted(set(theme) - _THEME_KEYS)
    if unknown:
        errors.append(f"{source_path}: unknown theme key(s): {', '.join(unknown)}")

    for key in _THEME_STRING_KEYS:
        if key in theme and not isinstance(theme[key], str):
            errors.append(f"{source_path}: theme.{key} must be a string")
        elif key in theme and any(
                ord(ch) < 0x20 and ch not in "\n\t" or 0x7F <= ord(ch) <= 0x9F
                for ch in theme[key]):
            errors.append(
                f"{source_path}: theme.{key} must not contain control characters")

    accent = theme.get("accent")
    if isinstance(accent, str) and not _ACCENT_RE.match(accent):
        errors.append(
            f"{source_path}: theme.accent must match ^#[0-9a-fA-F]{{6}}$, got {accent!r}"
        )

    questions = theme.get("forensics_questions")
    if questions is not None:
        errors.append(
            f"{source_path}: theme.forensics_questions is no longer supported; "
            "move questions to the top-level scored 'forensics' section "
            "(id/question/answer/points per entry)"
        )

    shortcuts = theme.get("desktop_shortcuts")
    if shortcuts is not None:
        if not isinstance(shortcuts, list):
            errors.append(f"{source_path}: theme.desktop_shortcuts must be a list")
        else:
            for idx, sc in enumerate(shortcuts):
                ref = f"theme.desktop_shortcuts[{idx}]"
                if not isinstance(sc, dict):
                    errors.append(f"{source_path}: {ref} must be a mapping")
                    continue
                for key in ("name", "exec"):
                    if key not in sc:
                        errors.append(f"{source_path}: {ref} missing required key '{key}'")
                    elif not isinstance(sc[key], str):
                        errors.append(f"{source_path}: {ref}.{key} must be a string")

    if "include_report_shortcut" in theme and not isinstance(theme["include_report_shortcut"], bool):
        errors.append(f"{source_path}: theme.include_report_shortcut must be a boolean")

    allow = theme.get("readme_lint_allow")
    if allow is not None:
        if not isinstance(allow, list) or not all(isinstance(a, str) for a in allow):
            errors.append(
                f"{source_path}: theme.readme_lint_allow must be a list of strings "
                "(forensics answer values the spoiler lint may ignore — lenient "
                "aliases that collide with the story vocabulary)"
            )

    return errors
