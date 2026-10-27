"""One authored scenario file, two build targets.

A scenario YAML carries the mode-independent content (``scenario``, ``checks``,
``theme``, ``forensics``) plus an optional ``ranked:`` block holding everything
that only exists for a ranked build: the engine URL, ranked-only extra checks,
scored ``services``, the ``adversary`` schedule, and the workshop ``pool``.

``scenario.mode`` names the *default* build target. ``honor`` means the file can
build both targets; ``ranked`` means it is ranked-only (building honor is an
error). The ranked block is never read on an honor build, so a ranked-only
artefact cannot leak into an honor manifest or rubric structurally.

This module is the single implementation of that merge; ``authoring/compile.py``,
``boxbuilder.spec`` and ``boxbuilder.lint`` all call it.
"""
import os

MODES = ("honor", "ranked")

# Committed scenarios name the loopback default and a deployment overrides it
# with --engine-url or $HUITZILOPOCHTLI_ENGINE_URL. A loopback value means
# "no engine configured yet" and boxbuilder warns about it at install.
LOOPBACK_ENGINE_URL = "http://127.0.0.1:8080"

_RANKED_KEYS = frozenset({"engine_url", "checks", "services", "adversary", "pool"})

# pool fields that are integers in the provision API but may be authored as
# "${VAR}" strings so a committed scenario carries no deployment specifics.
_POOL_INT_KEYS = ("template_vm_id", "vm_count", "guac_link_ttl_seconds")


class ScenarioModeError(ValueError):
    """The requested build target does not match what the file authored."""


def expand_env(value: str, where: str) -> str:
    """Expand ``${VAR}`` in an authored string. Unset vars are an error: a
    silently empty template id or password would be a bad deployment."""
    if "${" not in value:
        return value
    out = os.path.expandvars(value)
    if "${" in out:
        raise ScenarioModeError(
            f"{where}: unset environment variable in {value!r}; export it before "
            f"building (the committed scenario names no deployment specifics)"
        )
    return out


def expand_pool(pool: dict) -> dict:
    """Expand ``${VAR}`` in every pool value and coerce integer fields."""
    if not isinstance(pool, dict):
        return pool
    expanded = {}
    for key, value in pool.items():
        if isinstance(value, str):
            value = expand_env(value, f"ranked.pool.{key}")
            if key in _POOL_INT_KEYS and value.lstrip("-").isdigit():
                value = int(value)
        expanded[key] = value
    return expanded


def base_mode(parsed: dict) -> str:
    scenario = parsed.get("scenario") or {}
    return scenario.get("mode") or "honor"


def resolve_engine_url(parsed: dict, mode: str, override: str = None,
                       source: str = "<scenario>") -> str:
    """override > $HUITZILOPOCHTLI_ENGINE_URL > ranked.engine_url > scenario.engine_url."""
    if mode != "ranked":
        return None
    block = parsed.get("ranked") or {}
    url = (override
           or os.environ.get("HUITZILOPOCHTLI_ENGINE_URL")
           or block.get("engine_url")
           or (parsed.get("scenario") or {}).get("engine_url"))
    if not url:
        raise ScenarioModeError(
            f"{source}: a ranked build needs an engine_url; name one in the "
            f"ranked block or pass --engine-url / $HUITZILOPOCHTLI_ENGINE_URL")
    return url


def ranked_block(parsed: dict) -> dict:
    block = parsed.get("ranked")
    return block if isinstance(block, dict) else {}


def ranked_only_checks(parsed: dict) -> list:
    checks = ranked_block(parsed).get("checks") or []
    return list(checks)


def merge_effective(parsed: dict, mode: str, engine_url: str = None,
                    source: str = "<scenario>") -> dict:
    """Return the scenario as it should be compiled for ``mode``.

    The returned dict has the classic shape ``authoring.compile`` consumes:
    ``scenario`` (with a concrete ``engine_url`` when ranked), ``checks``,
    ``theme``, ``forensics``, and — ranked only — ``services``, ``adversary``,
    ``pool``.
    """
    if mode not in MODES:
        raise ScenarioModeError(f"{source}: mode must be one of {MODES!r}, got {mode!r}")

    scenario = dict(parsed.get("scenario") or {})
    declared = scenario.get("mode") or "honor"
    if declared not in MODES:
        raise ScenarioModeError(
            f"{source}: scenario.mode must be one of {MODES!r}, got {declared!r}")

    if mode == "honor" and declared == "ranked":
        raise ScenarioModeError(
            f"{source}: scenario.mode is 'ranked' and no honor variant is authored; "
            f"a ranked scenario cannot be built as an honor box")

    effective = {
        "scenario": scenario,
        "checks": list(parsed.get("checks") or []),
        "theme": parsed.get("theme"),
        "forensics": parsed.get("forensics") or [],
        "services": [],
        "adversary": {},
    }

    if mode == "ranked":
        block = ranked_block(parsed)
        if declared == "honor" and not block:
            raise ScenarioModeError(
                f"{source}: no ranked variant is authored (add a top-level "
                f"'ranked:' block to build this scenario as a ranked box)")
        unknown = sorted(set(block) - _RANKED_KEYS)
        if unknown:
            raise ScenarioModeError(
                f"{source}: unknown key(s) in the ranked block: {', '.join(unknown)} "
                f"(allowed: {', '.join(sorted(_RANKED_KEYS))})")

        effective["checks"] = effective["checks"] + ranked_only_checks(parsed)
        effective["scenario"] = dict(scenario)
        effective["scenario"]["mode"] = "ranked"
        effective["scenario"]["engine_url"] = resolve_engine_url(
            parsed, mode, engine_url, source=source)
        # The ranked block is the authored home for these; a ranked-only file
        # (scenario.mode: ranked) may still carry them at top level.
        effective["services"] = list(block.get("services") or parsed.get("services") or [])
        effective["adversary"] = block.get("adversary") or parsed.get("adversary") or {}
        pool = block.get("pool") if block.get("pool") else parsed.get("pool")
        if pool:
            effective["pool"] = expand_pool(pool)
    else:
        # Honor builds never see ranked content. Strip it so a caller cannot
        # accidentally compile services/adversary/pool into an honor record.
        effective["scenario"] = dict(scenario)
        effective["scenario"].pop("engine_url", None)

    return effective
