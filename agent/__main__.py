"""Agent entrypoint. See architecture.md §15."""
import base64
import json
import os
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
from common.canon import canonicalize
from common.crypto import signing
from common.schema import (
    Bundle,
    Category,
    CheckSpec,
    Manifest,
    Mode,
    Rubric,
    RubricEntry,
    SlaParams,
    validate_manifest,
)
from common.version import AGENT_VERSION

_DEFAULT_CONFIG_PATH = "agent_config.json"
_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"


class _WallClock:
    """Clock for honor mode (box wall time; untimed, diagnostic only)."""

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
        theme=d.get("theme"),
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
        category=Category(d["category"]),
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


def _load_manifest(manifest_path: str, authoring_public_key_path: str | None) -> Manifest:
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_dict = json.load(f)

    # §16/§7: the manifest is signed by the authoring key.
    if "_signature" not in manifest_dict:
        raise ValueError(
            f"manifest at {manifest_path} is missing a '_signature' field; "
            "refusing to run on an unsigned manifest"
        )

    sig_b64 = manifest_dict["_signature"]
    unsigned_dict = {k: v for k, v in manifest_dict.items() if k != "_signature"}

    if authoring_public_key_path is None:
        print(
            "WARNING: no authoring_public_key_path configured; manifest "
            "signature verification SKIPPED. Set authoring_public_key_path "
            "in agent_config.json to enable it.",
            file=sys.stderr,
        )
    else:
        with open(authoring_public_key_path, "r", encoding="utf-8") as f:
            public_key = base64.b64decode(f.read().strip())
        canonical_bytes = canonicalize(unsigned_dict)
        sig = base64.b64decode(sig_b64)
        if not signing.verify(public_key, canonical_bytes, sig):
            raise ValueError(
                f"manifest at {manifest_path} FAILED signature verification "
                f"against {authoring_public_key_path}; refusing to run"
            )

    schema_errors = validate_manifest(unsigned_dict)
    if schema_errors:
        raise ValueError(
            f"manifest at {manifest_path} failed validation:\n  "
            + "\n  ".join(schema_errors)
        )

    return _manifest_from_dict(unsigned_dict)


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
    html = agent.reporter.render_report(
        score, Mode.HONOR, None, theme=manifest.theme, manifest=manifest
    )
    with open(config.report_path, "w", encoding="utf-8") as f:
        f.write(html)


def _enrolled_marker_path(identity_path: str) -> str:
    """Return the path of the .enrolled marker file adjacent to the identity."""
    return identity_path + ".enrolled"


def _ensure_enrolled(config, manifest, identity) -> None:
    """Ensure enrollment; retry every boot until ``.enrolled`` marker exists."""
    marker = _enrolled_marker_path(config.identity_path)
    if os.path.exists(marker):
        return

    if config.enrollment_token is None:
        raise ValueError(
            "ranked mode requires enrollment_token in agent_config.json "
            "(enrollment has not completed yet)"
        )

    try:
        agent.identity.enroll(
            manifest.engine_url, config.enrollment_token, identity,
            AGENT_VERSION, manifest.scenario_name, manifest.scenario_version,
        )
    except agent.identity.EnrollmentTokenConsumed:
        pass

    tmp = marker + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("ok")
    os.rename(tmp, marker)


def _run_ranked(config, manifest, ctx) -> None:
    queue_path = config.identity_path + ".queue"
    last_response = None  # cached CheckinResponse across loop iterations

    identity = agent.identity.load_or_create(config.identity_path)
    _ensure_enrolled(config, manifest, identity)

    while True:
        evidence = agent.collector.run_all(manifest.checks, ctx)

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

        # Persist seq before network so a crash cannot desync local state.
        identity.last_seq = bundle.seq
        agent.identity.save(config.identity_path, identity)

        client = agent.transport.TransportClient(
            manifest.engine_url, identity, queue_path=queue_path
        )
        response = client.checkin(bundle)

        if response is not None:
            last_response = response
            for directive in response.directives:
                agent.adversary.executor.execute(directive, ctx)
            html = agent.reporter.render_report(
                response.score, Mode.RANKED, response.server_time,
                theme=manifest.theme, manifest=manifest,
                next_checkin_s=response.next_checkin_s,
            )
        else:
            last_confirmed_at = (
                last_response.server_time if last_response is not None else None
            )
            score = last_response.score if last_response is not None else None
            if score is not None:
                html = agent.reporter.render_report(
                    score, Mode.RANKED, last_confirmed_at, theme=manifest.theme,
                    manifest=manifest,
                    next_checkin_s=last_response.next_checkin_s if last_response else None,
                )
            else:
                from common.schema import ScoreBreakdown

                placeholder = ScoreBreakdown(
                    scenario_name=manifest.scenario_name,
                    scenario_version=manifest.scenario_version,
                    total=0,
                    results=[],
                    sla_status=[],
                    computed_at=time.time(),
                )
                html = agent.reporter.render_report(
                    placeholder, Mode.RANKED, None, theme=manifest.theme, manifest=manifest
                )

        with open(config.report_path, "w", encoding="utf-8") as f:
            f.write(html)

        time.sleep(config.checkin_interval_s)


def main() -> None:
    config_path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_CONFIG_PATH
    config = agent.config.load_config(config_path)

    manifest = _load_manifest(config.manifest_path, config.authoring_public_key_path)
    ctx = agent.platform.detect.detect()

    if config.mode == Mode.HONOR:
        _run_honor(config, manifest, ctx)
    elif config.mode == Mode.RANKED:
        _run_ranked(config, manifest, ctx)
    else:
        raise ValueError(f"unknown mode: {config.mode!r}")


if __name__ == "__main__":
    main()
