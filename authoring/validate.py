"""Author-facing validation. See architecture.md §6.7, §8.

PHASE 1 TASK: implement. Wraps common.schema.validate_manifest /
validate_rubric (structural validation of compiled JSON) with YAML-source
line-number mapping so build failures are line-referenced for the author.
"""
import re

_VALID_MODES = ("honor", "ranked")
_VALID_CATEGORIES = ("vuln", "penalty", "prohibited")

# Required keys on each `checks[]` entry, per architecture.md §8.
_REQUIRED_CHECK_KEYS = ("id", "type", "category", "display", "max_points", "collect", "expect")

# Optional top-level `theme` block (box theming -- see boxbuilder/theme.py and
# nakon/theme/). Every key is independently optional; only `wallpaper`/`readme`/`logo`
# are file paths, everything else is inline text. Pure structural/shape checks only --
# no filesystem access here (consistent with the rest of this file); path existence is
# checked later where the paths are actually resolved (boxbuilder/theme.py for
# wallpaper/readme, authoring/compile.py for logo).
_THEME_STRING_KEYS = ("title", "organization", "accent", "logo", "wallpaper", "readme", "motd", "issue")
_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


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

            # `expect` is a required key (checked above). A present-but-null
            # `expect:` (YAML null) satisfied the required-key check, and an
            # explicit `expect: {}` is also a valid dict -- but both compile to
            # an empty matcher {} that later crashes the evaluator with
            # KeyError('tag'); reject them here at authoring time. Only enforce
            # when the key is present so the earlier "missing required key"
            # message stands on its own when it's absent.
            if "expect" in check:
                expect = check.get("expect")
                if not isinstance(expect, dict) or len(expect) == 0:
                    errors.append(
                        f"{source_path}: {ref}.expect must be a non-null, "
                        f"non-empty mapping (an empty matcher crashes the evaluator)"
                    )

    # --- theme (optional, top-level, sibling of scenario/checks/adversary) -----------
    if "theme" in parsed_yaml:
        errors.extend(_validate_theme(parsed_yaml.get("theme"), source_path))

    return errors


def _validate_theme(theme, source_path: str) -> list:
    """Structural checks only for the optional `theme` block -- no filesystem access.
    Every key is independently optional; presence-checking a key only validates its
    *shape*, never that a referenced file exists (see module docstring above)."""
    errors = []

    if theme is None or (isinstance(theme, dict) and len(theme) == 0):
        # `theme:` present but null/empty is a no-op, not an error -- unlike `expect`,
        # nothing downstream crashes on an empty theme.
        return errors
    if not isinstance(theme, dict):
        return [f"{source_path}: 'theme' must be a mapping"]

    for key in _THEME_STRING_KEYS:
        if key in theme and not isinstance(theme[key], str):
            errors.append(f"{source_path}: theme.{key} must be a string")

    accent = theme.get("accent")
    if isinstance(accent, str) and not _ACCENT_RE.match(accent):
        errors.append(
            f"{source_path}: theme.accent must match ^#[0-9a-fA-F]{{6}}$, got {accent!r}"
        )

    questions = theme.get("forensics_questions")
    if questions is not None:
        if not isinstance(questions, list) or not all(isinstance(q, str) for q in questions):
            errors.append(f"{source_path}: theme.forensics_questions must be a list of strings")

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

    return errors
