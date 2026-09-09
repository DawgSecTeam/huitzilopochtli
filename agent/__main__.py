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
import agent.notify
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
    ForensicsQuestion,
    Manifest,
    Mode,
    Rubric,
    RubricEntry,
    SCHEMA_VERSION,
    ScoreBreakdown,
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
        forensics=[
            ForensicsQuestion(
                id=f["id"], question=f["question"], max_points=f["max_points"]
            )
            for f in d.get("forensics") or []
        ] or None,
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


def _load_manifest(manifest_path: str, authoring_public_key_path: str | None,
                   allow_unsigned: bool = False) -> Manifest:
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
        # §6.7/§16: fail closed on unverifiable input. Running an unverified
        # manifest lets anything that can replace manifest.signed.json execute
        # arbitrary checks on the box, so it requires an explicit opt-out.
        if not allow_unsigned:
            raise ValueError(
                "no authoring_public_key_path configured; refusing to run with "
                "an UNVERIFIED manifest. Set authoring_public_key_path in "
                "agent_config.json, or set \"allow_unsigned_manifest\": true "
                "to accept this risk (development only)."
            )
        print(
            "WARNING: no authoring_public_key_path configured and "
            "allow_unsigned_manifest is set; manifest signature verification "
            "SKIPPED. Do not use in production.",
            file=sys.stderr,
        )
    else:
        with open(authoring_public_key_path, "r", encoding="utf-8") as f:
            public_key = base64.b64decode(f.read().strip(), validate=True)
        canonical_bytes = canonicalize(unsigned_dict)
        sig = base64.b64decode(sig_b64, validate=True)
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


_ANSWER_BLANK = "_" * 44


def _primary_desktop_dir() -> str | None:
    """Best-effort Desktop dir of the first real interactive account.

    Mirrors the uid/shell heuristic the boxbuilder theme scripts use
    (uid >= 1000, real login shell). Returns None when nothing matches or the
    platform has no pwd module (non-POSIX).
    """
    try:
        import pwd
    except ImportError:
        return None
    for entry in pwd.getpwall():
        if entry.pw_uid < 1000:
            continue
        shell = entry.pw_shell or ""
        if shell.endswith("/nologin") or shell.endswith("/false"):
            continue
        return os.path.join(entry.pw_dir, "Desktop")
    return None


def _write_forensics_template(path: str, questions: list) -> None:
    """Write the answers template for `questions` [(ordinal, text)] at `path`.

    Callers handle write-if-missing; here we write via tmp + rename and make
    the file group/other-writable (and owned by the desktop user when it lives
    under one) because the agent typically runs as root while the answers are
    typed in by a desktop user.
    """
    lines = [
        "Forensics Questions",
        "===================",
        "",
        "Answer each question below by replacing the blank on its 'Answer:'",
        "line. Answers are collected and scored automatically each time the",
        "box re-grades: a correct answer earns the question's points, a wrong",
        "or blank answer earns nothing and never deducts.",
        "",
    ]
    for ordinal, question in questions:
        lines.append(f"Q{ordinal}: {question}")
        lines.append(f"Answer: {_ANSWER_BLANK}")
        lines.append("")

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    try:
        os.chmod(tmp, 0o666)
    except OSError:
        pass
    # When the template lands on a desktop user's Desktop, hand them
    # ownership so their editor never complains about a root-owned file.
    desktop_dir = _primary_desktop_dir()
    if desktop_dir and path.startswith(desktop_dir):
        try:
            import pwd
            for entry in pwd.getpwall():
                if os.path.join(entry.pw_dir, "Desktop") == desktop_dir:
                    os.chown(tmp, entry.pw_uid, entry.pw_gid)
                    break
        except (ImportError, OSError):
            pass
    os.rename(tmp, path)


def _prepare_forensics(manifest, config_dir: str) -> None:
    """Resolve answers-file paths and write missing templates (both modes).

    The compiled manifest defaults forensics collect_params to
    "Forensics-Questions.txt" with no directory; that sentinel resolves to the
    primary desktop user's Desktop (where teams can actually edit it), falling
    back to the agent config dir. An explicit scenario `path` is honored as-is
    (relative paths resolve against the config dir). Templates are written
    ONLY when the answers file does not exist yet — the file belongs to the
    team after that, and rewriting it would clobber their answers.
    """
    if not manifest.forensics:
        return

    default_dir = _primary_desktop_dir() or config_dir
    try:
        os.makedirs(default_dir, exist_ok=True)
    except OSError:
        default_dir = config_dir

    by_path = {}
    for spec in manifest.checks:
        if spec.type != "forensics_answer":
            continue
        path = spec.collect_params.get("path")
        if not isinstance(path, str) or not path:
            continue
        if path == "Forensics-Questions.txt":
            path = os.path.join(default_dir, path)
        elif not os.path.isabs(path):
            path = os.path.join(config_dir, path)
        spec.collect_params["path"] = path
        by_path.setdefault(path, []).append(spec)

    for path, specs in by_path.items():
        if os.path.exists(path):
            continue
        specs.sort(key=lambda s: s.collect_params.get("ordinal", 0))
        questions = [
            (s.collect_params.get("ordinal", 0), s.display_title) for s in specs
        ]
        try:
            _write_forensics_template(path, questions)
        except OSError as e:
            # Never stall the run over the template; the collector will report
            # the missing file as an error and score it unsatisfied (§9.1).
            print(
                f"WARNING: could not write forensics answers template "
                f"{path!r}: {e}",
                file=sys.stderr,
            )


def _theme_title(manifest) -> str:
    """Human-facing scenario title for notifications (theme override wins)."""
    theme = manifest.theme or {}
    return theme.get("title") or manifest.scenario_name


def _run_honor(config, manifest, ctx) -> None:
    evidence = agent.collector.run_all(manifest.checks, ctx)

    with open(config.rubric_path, "r", encoding="utf-8") as f:
        rubric_dict = json.load(f)
    rubric = _rubric_from_dict(rubric_dict)

    score = common.evaluator.evaluate(evidence, rubric, _WallClock())
    # Diff against the previous run's total (None on first run / rebuilt
    # scenario -- deliberately silent, see agent/notify.py).
    delta = agent.notify.consume_delta(
        agent.notify.state_path_for(config.report_path),
        score.total, manifest.scenario_version,
    )
    html = agent.reporter.render_report(
        score, Mode.HONOR, None, theme=manifest.theme, manifest=manifest,
        score_delta=delta,
    )
    with open(config.report_path, "w", encoding="utf-8") as f:
        f.write(html)

    if delta:
        agent.notify.announce(
            delta, score.total, title=_theme_title(manifest),
            enabled=config.notifications,
        )


def _enrolled_marker_path(identity_path: str) -> str:
    """Return the path of the .enrolled marker file adjacent to the identity."""
    return identity_path + ".enrolled"


def _mark_enrolled(identity_path: str) -> None:
    """Write the .enrolled marker atomically."""
    marker = _enrolled_marker_path(identity_path)
    if os.path.exists(marker):
        return
    tmp = marker + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("ok")
    os.rename(tmp, marker)


def _ensure_enrolled(config, manifest, identity) -> bool:
    """Ensure enrollment; retry every boot until ``.enrolled`` marker exists.

    Returns True when the engine confirmed a FRESH enrollment of this exact
    identity. A 409 (token consumed) is ambiguous — it can mean an idempotent
    re-enroll of the same box, or a token consumed by a different/new box —
    so in that case the marker is NOT written here; it is written only after
    the engine accepts a signed check-in from this keypair (see _run_ranked).
    """
    marker = _enrolled_marker_path(config.identity_path)
    if os.path.exists(marker):
        return False

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
    except agent.identity.EnrollmentTokenConsumed as e:
        print(
            f"WARNING: {e}; the enrolled-marker will only be written after a "
            f"confirmed check-in",
            file=sys.stderr,
        )
        return False
    return True


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
            schema_version=SCHEMA_VERSION,
        )

        # Persist seq before network so a crash cannot desync local state; a
        # replay-style permanent rejection below resyncs from the engine.
        identity.last_seq = bundle.seq
        agent.identity.save(config.identity_path, identity)

        client = agent.transport.TransportClient(
            manifest.engine_url, identity, queue_path=queue_path
        )
        try:
            response = client.checkin(bundle)
        except agent.transport.PermanentRejection as e:
            # The engine refused the bundle outright (§14.2: logic error, not
            # transient). The bundle is dropped; on a replay rejection the
            # engine tells us its authoritative last_seq — resync so a
            # desynced counter cannot wedge the box permanently.
            print(f"WARNING: {e}", file=sys.stderr)
            if e.last_seq is not None:
                identity.last_seq = e.last_seq
                agent.identity.save(config.identity_path, identity)
            response = None

        if response is not None:
            last_response = response
            # A confirmed check-in from this keypair settles any enrollment
            # ambiguity (e.g. a consumed token that may have been used by a
            # different box identity).
            _mark_enrolled(config.identity_path)
            for directive in response.directives:
                try:
                    agent.adversary.executor.execute(directive, ctx)
                except Exception as e:  # noqa: BLE001 — one bad directive
                    # must never stall the run (§9.1)
                    print(
                        f"WARNING: directive {directive.event_id!r} "
                        f"({directive.action!r}) failed: {e}",
                        file=sys.stderr,
                    )

        delta = None
        try:
            if last_response is not None:
                delta = agent.notify.consume_delta(
                    agent.notify.state_path_for(config.report_path),
                    last_response.score.total, manifest.scenario_version,
                )
                html = agent.reporter.render_report(
                    last_response.score, Mode.RANKED, last_response.server_time,
                    theme=manifest.theme, manifest=manifest,
                    next_checkin_s=last_response.next_checkin_s,
                    score_delta=delta,
                )
            else:
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
        except Exception as e:  # noqa: BLE001 — report rendering must never
            # stall the check-in loop (§9.1)
            print(f"WARNING: failed to render/write report: {e}", file=sys.stderr)

        if delta:
            agent.notify.announce(
                delta, last_response.score.total, title=_theme_title(manifest),
                enabled=config.notifications,
            )

        # The engine's next_checkin_s is authoritative when present (it backs
        # the reporter countdown and SLA cadence); fall back to local config.
        interval = config.checkin_interval_s
        if last_response is not None:
            nxt = last_response.next_checkin_s
            if isinstance(nxt, (int, float)) and not isinstance(nxt, bool) and nxt > 0:
                interval = nxt
        time.sleep(interval)


def main() -> None:
    config_path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_CONFIG_PATH
    config = agent.config.load_config(config_path)

    manifest = _load_manifest(
        config.manifest_path,
        config.authoring_public_key_path,
        allow_unsigned=config.allow_unsigned_manifest,
    )
    ctx = agent.platform.detect.detect()

    _prepare_forensics(
        manifest, os.path.dirname(os.path.abspath(config_path))
    )

    if config.mode == Mode.HONOR:
        _run_honor(config, manifest, ctx)
    elif config.mode == Mode.RANKED:
        _run_ranked(config, manifest, ctx)
    else:
        raise ValueError(f"unknown mode: {config.mode!r}")


if __name__ == "__main__":
    main()
