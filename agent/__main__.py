"""Agent entrypoint. See architecture.md §15."""
import base64
import json
import os
import subprocess
import sys
import time
import uuid
import zlib

import agent.answers
import agent.cli
import agent.config
import agent.collector
import agent.identity
import agent.notify
import agent.platform.detect
import agent.reporter
import agent.snapshot
import agent.transport
import agent.adversary.executor
import common.evaluator
from common.canon import canonicalize
from common.crypto import signing
from common import rubric_codec
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


def _primary_desktop_dir() -> str | None:
    """Best-effort Desktop dir of the first real interactive account.

    Mirrors the uid/shell heuristic the boxbuilder theme scripts use
    (uid >= 1000, real login shell). On Windows there is no passwd; the
    Public Desktop is the editable surface every account shares (same place
    the report is mirrored), so it is the answers-file home. Returns None
    when nothing matches (callers fall back to the agent config dir).
    """
    if os.name == "nt":
        pub = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop")
        return pub if os.path.isdir(pub) else None
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


def _grant_windows_write_acl(path: str) -> None:
    """Grant BUILTIN\\Users modify on the answers file (Windows only).

    os.chmod cannot express NTFS ACLs (at best it toggles the read-only
    attribute), and the agent runs as SYSTEM while the answers are typed by
    a desktop user whose UAC-filtered token carries no Administrators ACE --
    without this grant the file lands read-only for exactly the people who
    must edit it (their only rights would be the inherited
    INTERACTIVE:ReadAndExecute). Best-effort (§9.1): a failed grant never
    stalls a run; packaging/huitz-agent-task.ps1 re-grants every cycle.
    """
    try:
        subprocess.run(
            ["icacls", path, "/grant", "*S-1-5-32-545:M"],
            check=False, timeout=15,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _non_root_dir_owner(path: str):
    """(uid, gid) of path's directory when we run as root on POSIX and that
    directory belongs to another user; None otherwise (nothing to guard)."""
    if os.name == "nt" or os.geteuid() != 0:
        return None
    try:
        st = os.stat(os.path.dirname(os.path.abspath(path)))
    except OSError:
        return None
    if st.st_uid == 0:
        return None
    try:
        import pwd
        return st.st_uid, pwd.getpwuid(st.st_uid).pw_gid
    except (ImportError, KeyError):
        return st.st_uid, st.st_gid


def _write_forensics_template(path: str, questions: list) -> None:
    """Write the answers template for `questions` [(ordinal, text)] at `path`.

    Callers handle write-if-missing; here we write via tmp + rename and make
    the file group/other-writable (written as the desktop user when it lives
    in their directory, see _non_root_dir_owner) because the agent typically runs as root while the answers are
    typed in by a desktop user. The template format lives in agent/answers.py
    (shared with the collector and the huitz CLI).
    """
    lines = agent.answers.render_template(questions)

    # Root writing into a user-owned dir (the Desktop) must not follow any
    # symlink the user planted there (e.g. <path>.tmp -> /etc/shadow, which
    # the chmod/chown below would then hand to them): write as that user.
    owner = _non_root_dir_owner(path)
    if owner is not None:
        agent.answers.write_as_owner(path, lines, owner[0], owner[1], 0o666)
        return

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(lines)
    try:
        os.chmod(tmp, 0o666)
    except OSError:
        pass
    if os.name == "nt":
        _grant_windows_write_acl(tmp)
    os.replace(tmp, path)


def _honor_interval_s() -> int | None:
    """Report-countdown anchor for honor mode, per platform.

    POSIX: None -- the reporter's 70s default matches the systemd timer.
    Windows: the HuitzilopochtliAgent scheduled task re-grades every 5
    minutes (Task Scheduler repetition granularity bottoms out at 1 minute,
    so the 70s POSIX cadence isn't expressible); anchoring the countdown to
    the default there would read "00:00 -- checking..." for 4 of every 5
    minutes even though nothing is wrong.
    """
    return 300 if os.name == "nt" else None


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


def _sync_desktop_copies(config) -> None:
    """Mirror report.html + report.json to each user's Documents/huitzilopochtli
    dir (and drop the legacy Desktop copies), now.

    packaging/sync-report.sh's job too — but the unit's ExecStartPost fires
    when the Type=simple agent process is FORKED, not when it exits, so it
    races the grade and lands exactly one grade stale in the mirror (the
    countdown the huitz CLI renders from that copy is therefore pinned at
    zero). Syncing here is ordered after the write, so both the timer's
    grades and `huitz grade` publish their own result. Best-effort: a
    hand-rolled install without the script just skips this; the timer's
    next ExecStartPost copy is the fallback.
    """
    script = os.path.join(
        os.path.dirname(os.path.abspath(config.report_path)), "sync-report.sh")
    if not os.path.isfile(script):
        return
    try:
        subprocess.run([script], timeout=15, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        pass  # never stall a grade on the mirror; ExecStartPost still copies


def _load_rubric(config):
    """Read + decode the on-box honor-mode rubric (obfuscated or plain JSON).

    The rubric lands obfuscated as a 0600 dotfile (common/rubric_codec.py,
    written by boxbuilder at install time). Plain JSON is still accepted so
    boxes installed by an older boxbuilder keep scoring. A box that cannot
    load its rubric cannot score at all, so any failure raises ValueError
    with an actionable message -- the timer retries next interval; a raw
    TypeError/traceback helps nobody at the console.
    """
    try:
        with open(config.rubric_path, "rb") as f:
            rubric_raw = f.read()
        if rubric_codec.looks_encoded(rubric_raw):
            rubric_dict = rubric_codec.decode_rubric(rubric_raw)
        else:
            rubric_dict = json.loads(rubric_raw.decode("utf-8"))
        return _rubric_from_dict(rubric_dict)
    except (OSError, ValueError, KeyError, TypeError, EOFError,
            zlib.error) as e:
        raise ValueError(
            f"honor-mode rubric at {config.rubric_path!r} is missing, "
            f"unreadable, or corrupt ({e}) -- the box cannot score without "
            f"it; restore the file or reinstall the agent"
        ) from e


def honor_grade(config, manifest, ctx) -> tuple:
    """One full honor-mode grade: collect -> evaluate -> report + snapshot.

    This is the whole scoring pipeline the systemd timer (and `huitz
    grade`) runs. Returns (score, delta, snapshot-dict) so the CLI can
    render the fresh board without re-reading the file it just wrote.
    Scoring stays a pure function of (evidence, rubric, clock) — everything
    here is presentation or bookkeeping around that (§2.1).
    """
    rubric = _load_rubric(config)
    evidence = agent.collector.run_all(manifest.checks, ctx)

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
        honor_interval_s=_honor_interval_s(),
    )
    with open(config.report_path, "w", encoding="utf-8") as f:
        f.write(html)

    snap = agent.snapshot.build_snapshot(
        score, manifest, mode="honor", agent_version=AGENT_VERSION,
        delta=delta, computed_at=score.computed_at,
    )
    agent.snapshot.write(config.report_path, snap)

    if delta:
        agent.notify.announce(
            delta, score.total, title=_theme_title(manifest),
            enabled=config.notifications,
        )
    _sync_desktop_copies(config)
    return score, delta, snap


def _run_honor(config, manifest, ctx) -> None:
    honor_grade(config, manifest, ctx)


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
    os.replace(tmp, marker)


def _executed_directives_path(identity_path: str) -> str:
    """Event ids this box has already run, adjacent to the identity (same
    lifetime as box_id: a new identity is a new box with a new schedule)."""
    return identity_path + ".directives"


def _load_executed_directives(identity_path: str) -> set:
    try:
        with open(_executed_directives_path(identity_path), "r",
                  encoding="utf-8") as f:
            ids = json.load(f)
    except FileNotFoundError:
        return set()
    except (OSError, ValueError) as e:
        # Unreadable: fail toward NOT re-running. Re-executing an old
        # flush_firewall would undo a fix the team already made.
        raise RuntimeError(
            f"cannot read executed-directives file: {e}; refusing to run "
            f"directives until it is repaired or removed") from e
    return {str(i) for i in ids} if isinstance(ids, list) else set()


def _save_executed_directives(identity_path: str, ids: set) -> None:
    path = _executed_directives_path(identity_path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sorted(ids), f)
    os.replace(tmp, path)


def _run_directives(response, identity_path: str, ctx) -> None:
    """Execute each directive in the response at most once per event_id.

    The engine re-sends every directive it has issued (issued_directives)
    so a lost response can't lose one (at-least-once delivery); this is the
    matching dedup. Each id is recorded right after its attempt -- failed
    attempts too, or an unknown action would warn on every check-in forever.
    """
    try:
        done = _load_executed_directives(identity_path)
    except RuntimeError as e:
        print(f"WARNING: {e}", file=sys.stderr)
        return
    pending = list(response.directives) + list(
        getattr(response, "issued_directives", None) or [])
    for directive in pending:
        if directive.event_id in done:
            continue
        try:
            agent.adversary.executor.execute(directive, ctx)
        except Exception as e:  # noqa: BLE001 — one bad directive
            # must never stall the run (§9.1)
            print(
                f"WARNING: directive {directive.event_id!r} "
                f"({directive.action!r}) failed: {e}",
                file=sys.stderr,
            )
        done.add(directive.event_id)
        try:
            _save_executed_directives(identity_path, done)
        except OSError as e:
            # Can't record it, so it would re-run next check-in; stop here
            # rather than run more directives we also couldn't record.
            print(f"WARNING: could not record executed directive "
                  f"{directive.event_id!r}: {e}", file=sys.stderr)
            return


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


def _warn_if_plain_http(manifest) -> None:
    """A non-loopback plain-HTTP engine_url carries bundles (and the
    directives the box will execute) in the clear. Labs do this on purpose;
    production ranked deployments should not. Loud, but not fatal -- there
    is no self-signed-CA story yet to make HTTPS universally usable."""
    from urllib.parse import urlsplit
    url = urlsplit(getattr(manifest, "engine_url", None) or "")
    if url.scheme != "http":
        return
    if url.hostname in ("127.0.0.1", "localhost", "::1"):
        return
    print(
        f"WARNING: engine_url {manifest.engine_url!r} uses plain HTTP over a "
        f"non-loopback network: check-ins, scores and adversary directives "
        f"are readable and forgeable on-path. Set up TLS on the engine and "
        f"https in the manifest for anything beyond an isolated lab.",
        file=sys.stderr,
    )


def _run_ranked(config, manifest, ctx) -> None:
    queue_path = config.identity_path + ".queue"
    last_response = None  # cached CheckinResponse across loop iterations

    _warn_if_plain_http(manifest)
    identity = agent.identity.load_or_create(config.identity_path)
    # Retry enrollment in-process: exiting would have systemd restart us
    # every 5s (Restart=on-failure), and each start re-derives the public key
    # and re-signs -- seconds of pure-Python crypto per attempt, forever, on
    # a permanent failure like an expired token.
    while True:
        try:
            _ensure_enrolled(config, manifest, identity)
            break
        except Exception as e:  # noqa: BLE001 — network, 4xx/5xx, config
            print(f"WARNING: enrollment failed, retrying later: {e}",
                  file=sys.stderr)
            time.sleep(max(config.checkin_interval_s or 0, 60))

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
            _run_directives(response, config.identity_path, ctx)

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
                snap = agent.snapshot.build_snapshot(
                    last_response.score, manifest, mode="ranked",
                    agent_version=AGENT_VERSION, delta=delta,
                    computed_at=last_response.score.computed_at,
                    server_time=last_response.server_time,
                    next_checkin_s=last_response.next_checkin_s,
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
                snap = agent.snapshot.build_snapshot(
                    placeholder, manifest, mode="ranked",
                    agent_version=AGENT_VERSION, delta=None,
                    computed_at=placeholder.computed_at,
                    awaiting_engine=True,
                )
            with open(config.report_path, "w", encoding="utf-8") as f:
                f.write(html)
            agent.snapshot.write(config.report_path, snap)
            # Publish the user-readable mirror (Documents/huitzilopochtli):
            # the unit's ExecStartPost fires before the first check-in even
            # exists, and the install dir is 0700 root -- without this, the
            # huitz console can never see a grade in ranked mode.
            _sync_desktop_copies(config)
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
    argv = sys.argv[1:]
    # `huitz` verb dispatch (agent/cli.py): score/grade/watch/forensics.
    # A bare path still means the classic one-shot agent run. Verb-shaped
    # tokens (no path separator, no extension) route to the CLI so typos
    # like `huitz scroe` get usage help instead of a confusing
    # "config file not found"; anything path-like — including a missing
    # config path — keeps the classic behavior. When the zipapp is installed
    # under the name `huitz` (boxbuilder copies it to /usr/local/bin/huitz),
    # a bare invocation is help, not a hunt for a default config — that is
    # the player's entry point.
    invoked_as_huitz = (
        os.path.basename(sys.argv[0] or "").rsplit(".", 1)[0] == "huitz"
    )
    if argv:
        head = argv[0]
        if head in ("-h", "--help") or head in agent.cli.VERBS or (
                "/" not in head and "." not in head and "\\" not in head):
            from agent.cli import main as cli_main
            raise SystemExit(cli_main(argv))
    elif invoked_as_huitz:
        from agent.cli import main as cli_main
        raise SystemExit(cli_main([]))

    config_path = argv[0] if argv else _DEFAULT_CONFIG_PATH
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
