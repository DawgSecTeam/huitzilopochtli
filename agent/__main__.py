"""Agent entrypoint. See architecture.md §15. PHASE 2 (integration).

Wires: config -> collector -> (honor: evaluator+reporter |
                                ranked: transport+reporter+adversary executor)

Honor-mode run: load signed manifest -> verify authoring signature -> run all
checks concurrently -> assemble evidence -> load local rubric ->
common.evaluate(evidence, rubric, no-op clock) -> write HTML. No network, no
time axis, no adversary.

Ranked check-in loop: every checkin_interval_s -> collect evidence ->
assemble+sign bundle (seq++) -> POST /checkin (TLS) -> on success apply score
to cache/report and execute directives; on network failure queue bundle and
retry next cycle.
"""
import json
import sys
import time
import uuid

import agent.config
import agent.collector
import agent.identity
import agent.platform.detect
import agent.reporter
import agent.transport
import agent.adversary.executor
import common.evaluator
from common.schema import (
    Bundle,
    Category,
    CheckSpec,
    Manifest,
    Mode,
    Rubric,
    RubricEntry,
    SlaParams,
)
from common.version import AGENT_VERSION

_DEFAULT_CONFIG_PATH = "agent_config.json"
_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"


class _WallClock:
    """Trivial Clock (see common.evaluator.Clock protocol) for honor mode,
    where there is no engine to supply an authoritative time (§10, §15:
    "no-op clock"). The box's own wall clock is diagnostic-grade only, but
    honor mode is untimed anyway so this is fine."""

    def now(self) -> float:
        return time.time()


def _check_spec_from_dict(d: dict) -> CheckSpec:
    return CheckSpec(
        id=d["id"],
        type=d["type"],
        category=Category(d["category"]),
        host_id=d["host_id"],
        collect_params=d.get("collect_params", {}),
        display_title=d["display_title"],
        display_max_points=d["display_max_points"],
        timeout_s=d.get("timeout_s", 5.0),
        is_sla=d.get("is_sla", False),
    )


def _manifest_from_dict(d: dict) -> Manifest:
    return Manifest(
        schema_version=d["schema_version"],
        scenario_name=d["scenario_name"],
        scenario_version=d["scenario_version"],
        mode=Mode(d["mode"]),
        engine_url=d.get("engine_url"),
        hosts=d.get("hosts", []),
        checks=[_check_spec_from_dict(c) for c in d.get("checks", [])],
    )


def _sla_params_from_dict(d):
    if d is None:
        return None
    return SlaParams(
        interval_s=d["interval_s"],
        points_per_interval=d["points_per_interval"],
        hysteresis_fail_n=d.get("hysteresis_fail_n", 2),
        hysteresis_ok_n=d.get("hysteresis_ok_n", 2),
        max_intervals_per_checkin=d.get("max_intervals_per_checkin", 3),
    )


def _rubric_entry_from_dict(d: dict) -> RubricEntry:
    return RubricEntry(
        check_id=d["check_id"],
        matcher=d.get("matcher", {}),
        points=d["points"],
        sla=_sla_params_from_dict(d.get("sla")),
    )


def _rubric_from_dict(d: dict) -> Rubric:
    return Rubric(
        schema_version=d["schema_version"],
        scenario_name=d["scenario_name"],
        scenario_version=d["scenario_version"],
        entries=[_rubric_entry_from_dict(e) for e in d.get("entries", [])],
    )


def _load_manifest(manifest_path: str) -> Manifest:
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_dict = json.load(f)

    # §16/§7: the manifest is signed by the authoring key. Full verification
    # requires the authoring PUBLIC key to be distributed to boxes, and there
    # is no such distribution mechanism/config wired up yet (a real gap,
    # flagged rather than silently skipped -- see final integration report).
    # For now: refuse to run on a manifest that isn't even well-formed enough
    # to carry a signature field, but don't block on verifying it.
    if "_signature" not in manifest_dict:
        raise ValueError(
            f"manifest at {manifest_path} is missing a '_signature' field; "
            "refusing to run on an unsigned manifest"
        )
    print(
        "WARNING: authoring-signature verification is a TODO pending an "
        "authoring-public-key distribution mechanism; proceeding unverified.",
        file=sys.stderr,
    )

    manifest_dict = {k: v for k, v in manifest_dict.items() if k != "_signature"}
    return _manifest_from_dict(manifest_dict)


def _read_boot_id() -> str:
    try:
        with open(_BOOT_ID_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return str(uuid.uuid4())


def _run_honor(config, manifest, ctx) -> None:
    evidence = agent.collector.run_all(manifest.checks, ctx)

    with open(config.rubric_path, "r", encoding="utf-8") as f:
        rubric_dict = json.load(f)
    rubric = _rubric_from_dict(rubric_dict)

    score = common.evaluator.evaluate(evidence, rubric, _WallClock())
    html = agent.reporter.render_report(score, Mode.HONOR, None)
    with open(config.report_path, "w", encoding="utf-8") as f:
        f.write(html)


def _run_ranked(config, manifest, ctx) -> None:
    queue_path = config.identity_path + ".queue"
    last_response = None  # cached CheckinResponse across loop iterations

    while True:
        evidence = agent.collector.run_all(manifest.checks, ctx)

        identity = agent.identity.load_or_create(config.identity_path)
        bundle = Bundle(
            box_id=identity.box_id,
            seq=identity.last_seq + 1,
            boot_id=_read_boot_id(),
            agent_version=AGENT_VERSION,
            scenario_name=manifest.scenario_name,
            scenario_version=manifest.scenario_version,
            evidence=evidence,
            created_wall_claim=time.time(),
        )

        client = agent.transport.TransportClient(
            manifest.engine_url, identity, queue_path=queue_path
        )
        response = client.checkin(bundle)

        # Whether or not the check-in succeeded, this bundle's seq has been
        # committed (sent, or queued with this seq preserved per §9.5) -- the
        # seq must still advance.
        identity.last_seq = bundle.seq
        agent.identity.save(config.identity_path, identity)

        if response is not None:
            last_response = response
            for directive in response.directives:
                agent.adversary.executor.execute(directive, ctx)
            html = agent.reporter.render_report(
                response.score, Mode.RANKED, response.server_time
            )
        else:
            last_confirmed_at = (
                last_response.server_time if last_response is not None else None
            )
            score = last_response.score if last_response is not None else None
            if score is not None:
                html = agent.reporter.render_report(
                    score, Mode.RANKED, last_confirmed_at
                )
            else:
                # No prior confirmed response at all yet: render_report needs
                # a ScoreBreakdown even in the "awaiting engine" branch, but
                # that branch never touches it (see agent/reporter.py), so an
                # empty placeholder is safe here.
                from common.schema import ScoreBreakdown

                placeholder = ScoreBreakdown(
                    scenario_name=manifest.scenario_name,
                    scenario_version=manifest.scenario_version,
                    total=0,
                    results=[],
                    sla_status=[],
                    computed_at=time.time(),
                )
                html = agent.reporter.render_report(placeholder, Mode.RANKED, None)

        with open(config.report_path, "w", encoding="utf-8") as f:
            f.write(html)

        time.sleep(config.checkin_interval_s)


def main() -> None:
    config_path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_CONFIG_PATH
    config = agent.config.load_config(config_path)

    manifest = _load_manifest(config.manifest_path)
    ctx = agent.platform.detect.detect()

    if config.mode == Mode.HONOR:
        _run_honor(config, manifest, ctx)
    elif config.mode == Mode.RANKED:
        _run_ranked(config, manifest, ctx)
    else:
        raise ValueError(f"unknown mode: {config.mode!r}")


if __name__ == "__main__":
    main()
