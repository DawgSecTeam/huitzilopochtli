"""Scenario source -> compiled engine record: the one shared implementation.

``authoring/compile.py`` (box builds) and ``engine/scenario.py`` (the engine
parsing ``boxes/<box>/scenario.yaml`` directly) must produce the *same* engine
record, so the whole pure dict pipeline lives here: mode merge
(``authoring``-authored shape -> effective per-target shape), services ->
synthetic SLA checks, adversary service-id rewrite, expect -> matcher rubric
entries, and forensics answer entries. Only the YAML load itself and the
manifest signing (an authoring concern) live elsewhere.

Stdlib-only: this module ships inside the agent zipapp bundle (via ``common``)
and must never import PyYAML or anything else beyond the standard library.
"""
import dataclasses
import os
from typing import Optional

from common.schema import (
    Category,
    CheckSpec,
    ForensicsQuestion,
    Rubric,
    RubricEntry,
    SCHEMA_VERSION,
    ServiceSpec,
    SlaParams,
)

MODES = ("honor", "ranked")

# Committed scenarios name the loopback default and a deployment overrides it
# with --engine-url or $HUITZILOPOCHTLI_ENGINE_URL. A loopback value means
# "no engine configured yet" and boxbuilder warns about it at install.
LOOPBACK_ENGINE_URL = "http://127.0.0.1:8080"

_RANKED_KEYS = frozenset({"engine_url", "checks", "services", "adversary", "pool"})

# pool fields that are integers in the provision API but may be authored as
# "${VAR}" strings so a committed scenario carries no deployment specifics.
_POOL_INT_KEYS = ("template_vm_id", "vm_count", "guac_link_ttl_seconds")

_DEFAULT_TIMEOUT_S = 5.0
_DEFAULT_HOST_ID = "localhost"
_DEFAULT_FORENSICS_PATH = "Forensics-Questions.txt"


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


def _build_check_spec(check: dict) -> CheckSpec:
    expect = check.get("expect", {}) or {}
    return CheckSpec(
        id=check["id"],
        type=check["type"],
        category=Category(check["category"]),
        host_id=check.get("host_id", _DEFAULT_HOST_ID),
        collect_params=check.get("collect", {}),
        display_title=check["display"],
        display_max_points=check["max_points"],
        timeout_s=check.get("timeout_s", _DEFAULT_TIMEOUT_S),
        is_sla=bool(check.get("is_sla") or ("sla" in expect)),
    )


def _build_rubric_entry(check: dict) -> RubricEntry:
    expect = dict(check.get("expect", {}) or {})
    category = check["category"]

    points = expect.pop("points", 0)
    sla_raw = expect.pop("sla", None)

    if isinstance(points, bool) or not isinstance(points, int):
        raise ValueError(
            f"check {check.get('id')!r}: expect.points must be an integer, "
            f"got {points!r}"
        )

    matcher = expect

    if category in ("penalty", "prohibited"):
        points = -abs(points)

    sla = None
    if sla_raw is not None:
        unknown = sorted(set(sla_raw) - set(SlaParams.__dataclass_fields__))
        if unknown:
            raise ValueError(
                f"check {check.get('id')!r}: expect.sla has unknown key(s): "
                f"{', '.join(unknown)}"
            )
        sla = SlaParams(
            interval_s=sla_raw["interval_s"],
            points_per_interval=sla_raw["points_per_interval"],
            hysteresis_fail_n=sla_raw.get("hysteresis_fail_n", 2),
            hysteresis_ok_n=sla_raw.get("hysteresis_ok_n", 2),
            max_intervals_per_checkin=sla_raw.get("max_intervals_per_checkin", 3),
        )

    return RubricEntry(
        check_id=check["id"],
        category=Category(category),
        matcher=matcher,
        points=points,
        sla=sla,
    )


def _build_forensics(question: dict, ordinal: int) -> tuple:
    """Compile one forensics question into (CheckSpec, RubricEntry).

    The CheckSpec (public, shipped in the manifest) carries only the question
    text and where to read answers from; the answer key lives solely in the
    RubricEntry matcher (engine-side in ranked, on-box rubric.json in honor).
    """
    fq_id = question["id"]
    path = question.get("path", _DEFAULT_FORENSICS_PATH)
    points = question["points"]

    spec = CheckSpec(
        id=fq_id,
        type="forensics_answer",
        category=Category.VULN,
        host_id=_DEFAULT_HOST_ID,
        collect_params={
            "path": path,
            "question_id": fq_id,
            "ordinal": ordinal,
        },
        display_title=question["question"],
        display_max_points=points,
        timeout_s=_DEFAULT_TIMEOUT_S,
    )

    if "answer" in question and "answers" in question:
        matcher = {
            "tag": "answer_equals",
            "value": question["answer"],
            "accept": list(question["answers"]),
        }
    elif "answers" in question:
        matcher = {"tag": "answer_equals", "accept": list(question["answers"])}
    else:
        matcher = {"tag": "answer_equals", "value": question["answer"]}

    entry = RubricEntry(
        check_id=fq_id,
        category=Category.VULN,
        matcher=matcher,
        points=points,
    )
    return spec, entry


_SERVICE_KEYS = frozenset({
    "id", "display", "type", "collect", "expect", "interval_s",
    "points_per_interval", "hysteresis_fail_n", "hysteresis_ok_n",
    "max_intervals_per_checkin", "timeout_s",
})


def _build_service(service: dict) -> tuple:
    """Expand one services[] entry into (CheckSpec dict, RubricEntry dict,
    public ServiceSpec metadata).

    The check id is prefixed with ``svc_`` so a service can never collide with
    an author-written check id. Expected values stay in the rubric only; the
    manifest carries just the display metadata.
    """
    sid = service["id"]
    check_id = f"svc_{sid}"
    display = service["display"]
    collect = dict(service.get("collect") or {})
    expect = dict(service.get("expect") or {})
    expect["points"] = 0
    expect["sla"] = {
        "interval_s": service["interval_s"],
        "points_per_interval": service["points_per_interval"],
        "hysteresis_fail_n": service.get("hysteresis_fail_n", 2),
        "hysteresis_ok_n": service.get("hysteresis_ok_n", 2),
        "max_intervals_per_checkin": service.get("max_intervals_per_checkin", 3),
    }
    check = {
        "id": check_id,
        "type": service["type"],
        "category": "vuln",
        "display": f"SERVICE: {display}",
        "max_points": service["points_per_interval"],
        "collect": collect,
        "expect": expect,
        "is_sla": True,
        "timeout_s": service.get("timeout_s", _DEFAULT_TIMEOUT_S),
    }
    meta = ServiceSpec(
        id=sid,
        check_id=check_id,
        display=display,
        type=service["type"],
        interval_s=service["interval_s"],
        points_per_interval=service["points_per_interval"],
    )
    return check, meta


def build_scenario_parts(parsed: dict, mode: Optional[str] = None,
                         engine_url: Optional[str] = None,
                         source: str = "<scenario>") -> dict:
    """Parsed scenario -> every compiled artefact the two consumers need.

    Returns a dict with:

    - ``effective``: the merged per-target scenario dict (theme lives here)
    - ``check_specs`` / ``rubric_entries``: compiled check + rubric objects
    - ``forensics_questions``: manifest-side question metadata
    - ``service_specs``: public service metadata
    - ``rubric``: the assembled ``Rubric`` object
    - ``engine_record``: the ``{rubric, adversary, services, mode, pool?}``
      dict the engine stores and serves

    Raises ``ScenarioModeError``/``ValueError`` on authored content that
    cannot compile. Structural validation of the produced record is the
    caller's job (``authoring.validate`` at build time;
    ``engine.scenario.validate_scenario_record`` at engine time).
    """
    effective = merge_effective(parsed, mode or base_mode(parsed),
                                engine_url=engine_url, source=source)

    scenario = effective["scenario"]
    checks = list(effective["checks"])
    forensics = effective["forensics"]

    service_specs = []
    service_check_ids = {}
    for service in effective["services"]:
        check, meta = _build_service(service)
        checks.append(check)
        service_specs.append(meta)
        service_check_ids[service["id"]] = check["id"]

    # Let an adversary event name a service id (`web`) instead of the
    # generated check id (`svc_web`); the rubric/scheduler needs the latter.
    adversary_raw = effective["adversary"] or {}
    if service_check_ids and isinstance(adversary_raw, dict):
        rewritten = []
        for event in adversary_raw.get("events", []):
            if isinstance(event, dict):
                target = event.get("affects_check")
                if isinstance(target, str) and target in service_check_ids:
                    event = dict(event)
                    event["affects_check"] = service_check_ids[target]
            rewritten.append(event)
        adversary_raw = dict(adversary_raw)
        adversary_raw["events"] = rewritten

    check_specs = [_build_check_spec(c) for c in checks]
    rubric_entries = [_build_rubric_entry(c) for c in checks]

    forensics_questions = []
    for ordinal, fq in enumerate(forensics, start=1):
        spec, entry = _build_forensics(fq, ordinal)
        check_specs.append(spec)
        rubric_entries.append(entry)
        forensics_questions.append(
            ForensicsQuestion(
                id=fq["id"], question=fq["question"], max_points=fq["points"]
            )
        )

    rubric = Rubric(
        schema_version=SCHEMA_VERSION,
        scenario_name=scenario["name"],
        scenario_version=scenario["version"],
        entries=rubric_entries,
    )

    engine_record = {
        "rubric": dataclasses.asdict(rubric),
        "adversary": adversary_raw,
        "services": [dataclasses.asdict(s) for s in service_specs],
        # The engine's box-folder listing filters on this (ranked boxes only);
        # honor records simply carry "honor".
        "mode": scenario["mode"],
    }
    # Workshop pool provisioning spec (ranked only; validation rejects a pool
    # block on honor scenarios). Passed through to the engine, which provisions
    # one pool per competition from it.
    if "pool" in effective:
        engine_record["pool"] = effective["pool"]

    return {
        "effective": effective,
        "check_specs": check_specs,
        "rubric_entries": rubric_entries,
        "forensics_questions": forensics_questions,
        "service_specs": service_specs,
        "rubric": rubric,
        "engine_record": engine_record,
    }
