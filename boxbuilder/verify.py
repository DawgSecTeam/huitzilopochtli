"""Post-install verification and pre-seal cleanup.

The deploy loop has two human-judgement steps that used to live only in prose:
"is this box actually in the state I think it is?" and "is this box clean
enough to seal?". Both are mechanical, so boxbuilder does them.

Verification is split in two:

* ``collect_facts`` talks to the box once and returns a plain dict of facts
  (files, hashes, unit state, report, per-user artifacts). It makes no
  judgements.
* ``evaluate`` turns facts plus expectations into a list of :class:`Check`
  results. It touches nothing remote, so every rule is unit-testable from a
  fixture dict.

``SEAL_CHECKS`` / ``prepare_seal`` handle the irreversible half: stopping the
agent, removing per-player state, truncating ``/etc/machine-id`` and telling
the operator the remaining manual steps. ``seal-prepare`` refuses to run
unless verification passes (``--skip-verify`` overrides).

Nothing here is box-specific: expectations come from the spec (mode, scenario
theme) and from ``build-state.json`` (the manifest and key hashes compile
recorded).
"""
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Optional

from boxbuilder import artifacts as artifacts_mod
from boxbuilder.os_family import is_windows

PASS = "pass"
FAIL = "fail"
WARN = "warn"
SKIP = "skip"

# Files every install places under the sealed install dir.
REQUIRED_FILES = ("agent.pyz", "manifest.signed.json",
                  "authoring_public_key.b64", "agent_config.json")

# Journal lines that mean the agent is crash-looping. The agent logs its own
# handled errors, so a traceback or an unhandled exception is the signal.
_CRASH_MARKERS = ("Traceback (most recent call last)", "Unhandled exception",
                  "FATAL")

_LEGACY_INSTALL_DIR = "/opt/huitzilopochtli"


@dataclass
class Check:
    id: str
    status: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.status in (PASS, SKIP, WARN)


@dataclass
class Expectations:
    """What the box should look like, derived from the build inputs."""

    mode: str = "honor"
    competition: bool = False
    for_seal: bool = False
    expect_total: Optional[int] = 0
    theme: dict = field(default_factory=dict)
    expected_manifest_sha: Optional[str] = None
    expected_key_sha: Optional[str] = None
    scenario_name: Optional[str] = None


# --- facts -----------------------------------------------------------------

def _sha256_local(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _parse_kv_sections(stdout: str) -> dict:
    """Split a ``##name`` section dump into ``{name: text}``."""
    sections, current = {}, None
    for line in stdout.splitlines():
        if line.startswith("##"):
            current = line[2:].strip()
            sections[current] = []
        elif current:
            sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def _posix_state_script(install_dir: str) -> str:
    """One round-trip for the static state of an install."""
    d = install_dir
    return f"""
echo "##files"
ls -1A {d} 2>/dev/null
echo "##manifest-sha"
sha256sum {d}/manifest.signed.json 2>/dev/null | cut -d' ' -f1
echo "##key-sha"
sha256sum {d}/authoring_public_key.b64 2>/dev/null | cut -d' ' -f1
echo "##config"
cat {d}/agent_config.json 2>/dev/null
echo "##machine-id"
cat /etc/machine-id 2>/dev/null
echo "##motd"
test -f {artifacts_mod.MOTD_PATH} && echo yes || echo no
echo "##theme"
ls -1 /usr/local/share/huitzilopochtli-theme 2>/dev/null
echo "##legacy"
test -d {_LEGACY_INSTALL_DIR} && echo yes || echo no
""".strip()


_POSIX_INIT_SCRIPT = """
if command -v systemctl >/dev/null 2>&1; then
  echo "##unit-active"; systemctl is-active huitzilopochtli-agent.service 2>/dev/null
  echo "##unit-enabled"; systemctl is-enabled huitzilopochtli-agent.service 2>/dev/null
  echo "##timer-active"; systemctl is-active huitzilopochtli-agent.timer 2>/dev/null
  echo "##timer-enabled"; systemctl is-enabled huitzilopochtli-agent.timer 2>/dev/null
elif command -v rc-service >/dev/null 2>&1; then
  echo "##unit-active"; rc-service huitzilopochtli-agent status >/dev/null 2>&1 && echo active || echo inactive
  echo "##unit-enabled"; rc-update show default 2>/dev/null | grep -q huitzilopochtli-agent && echo enabled || echo disabled
else
  echo "##unit-active"; unknown
  echo "##unit-enabled"; unknown
fi
""".strip()


def _posix_users_script() -> str:
    """Interactive accounts plus the per-user mirrors a player will see."""
    return r"""
awk -F: '($3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/ && $6 ~ /^\//) {print $1"|"$6}' /etc/passwd
echo "##artifacts"
while IFS='|' read -r name home; do
  [ -d "$home" ] || continue
  n=$(ls -1 "$home/Desktop"/*.desktop 2>/dev/null | wc -l)
  report=no; [ -f "$home/Documents/huitzilopochtli/report.json" ] && report=yes
  readme=no; [ -f "$home/Documents/huitzilopochtli/README.html" ] && readme=yes
  echo "$name|$home|$n|$report|$readme"
done <<EOF
$(awk -F: '($3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/ && $6 ~ /^\//) {print $1"|"$6}' /etc/passwd)
EOF
""".strip()


def _parse_agent_config(text: str) -> Optional[dict]:
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def collect_facts(handle, spec, artifacts_dir: str = "artifacts") -> dict:
    """Probe the box once and return the facts ``evaluate`` needs."""
    os_name = getattr(handle, "os_name", None) or "posix"
    install_dir = artifacts_mod.install_dir_for(os_name)
    if is_windows(os_name):
        return _collect_windows(handle, install_dir)

    state = _parse_kv_sections(handle.run(_posix_state_script(install_dir)).stdout)
    init = _parse_kv_sections(handle.run(_POSIX_INIT_SCRIPT).stdout)
    journal = handle.run("journalctl -u huitzilopochtli-agent.service "
                         "-n 200 --no-pager 2>/dev/null").stdout
    report_text = handle.run(f"cat {install_dir}/report.json 2>/dev/null").stdout
    users_raw = handle.run(_posix_users_script()).stdout

    report, report_error = None, None
    if report_text.strip():
        try:
            report = json.loads(report_text)
            if not isinstance(report, dict):
                report, report_error = None, "report.json is not a JSON object"
        except ValueError as exc:
            report_error = f"report.json is not valid JSON: {exc}"
    else:
        report_error = "no report.json in the install dir"

    users, per_user = [], {}
    for line in users_raw.splitlines():
        if line.count("|") == 4:
            name, home, count, mirror, readme = line.split("|")
            users.append({"name": name, "home": home})
            try:
                desktop_entries = int(count)
            except ValueError:
                desktop_entries = 0
            per_user[name] = {"desktop_entries": desktop_entries,
                              "report_mirror": mirror == "yes",
                              "readme_mirror": readme == "yes"}

    return {
        "os": "posix",
        "install_dir": install_dir,
        "files": [n for n in (state.get("files") or "").splitlines() if n],
        "manifest_sha": (state.get("manifest-sha") or "").strip() or None,
        "key_sha": (state.get("key-sha") or "").strip() or None,
        "agent_config": _parse_agent_config(state.get("config") or ""),
        "machine_id": (state.get("machine-id") or "").strip() or None,
        "motd": (state.get("motd") or "").strip() == "yes",
        "theme_files": [n for n in (state.get("theme") or "").splitlines() if n],
        "legacy_dir": (state.get("legacy") or "").strip() == "yes",
        "init": {
            "active": (init.get("unit-active") or "").strip() or None,
            "enabled": (init.get("unit-enabled") or "").strip() or None,
            "timer_active": (init.get("timer-active") or "").strip() or None,
            "timer_enabled": (init.get("timer-enabled") or "").strip() or None,
        },
        "journal": journal or None,
        "report": report,
        "report_error": report_error,
        "users": users,
        "user_artifacts": per_user,
        "desktop_pixels": _desktop_pixels(handle),
    }


def _desktop_pixels(handle) -> Optional[int]:
    """Bytes captured from the live X root window, or None when unmeasurable.

    This is the only check that proves the desktop actually paints: a VNC
    console can show a live cursor over a black framebuffer. `xwd` capture
    bypasses the VNC layer entirely.
    """
    res = handle.run("command -v xwd >/dev/null 2>&1 || exit 127; "
                     "DISPLAY=:0 timeout 10 xwd -root -silent 2>/dev/null | wc -c",
                     timeout=30)
    if res.exit_status == 127:
        return None
    try:
        return int(res.stdout.strip())
    except (ValueError, AttributeError):
        return None


def _collect_windows(handle, install_dir: str) -> dict:
    """The subset of facts a Windows guest can report cheaply."""
    ps = (
        f"$d='{install_dir}'; "
        f"if (Test-Path $d) {{ Get-ChildItem -LiteralPath $d -Force | "
        f"Select-Object -ExpandProperty Name }}; "
        "\"##config\"; if (Test-Path \"$d\\agent_config.json\") "
        "{ Get-Content -LiteralPath \"$d\\agent_config.json\" -Raw }; "
        "\"##manifest-sha\"; if (Test-Path \"$d\\manifest.signed.json\") "
        "{(Get-FileHash -LiteralPath \"$d\\manifest.signed.json\" -Algorithm SHA256).Hash}; "
        "\"##key-sha\"; if (Test-Path \"$d\\authoring_public_key.b64\") "
        "{(Get-FileHash -LiteralPath \"$d\\authoring_public_key.b64\" -Algorithm SHA256).Hash}; "
        "\"##task\"; (Get-ScheduledTask -TaskName 'HuitzilopochtliAgent' "
        "-ErrorAction SilentlyContinue).State"
    )
    out = handle.run_ps(ps).stdout
    findings = _parse_kv_sections("##files\n" + out)
    files = [n.strip() for n in (findings.get("files") or "").splitlines() if n.strip()]
    task_state = (findings.get("task") or "").strip().lower() or None
    return {
        "os": "windows",
        "install_dir": install_dir,
        "files": files,
        "manifest_sha": (findings.get("manifest-sha") or "").strip().lower() or None,
        "key_sha": (findings.get("key-sha") or "").strip().lower() or None,
        "agent_config": _parse_agent_config(findings.get("config") or ""),
        "machine_id": None,
        "motd": False,
        "theme_files": [],
        "legacy_dir": False,
        "init": {"active": task_state, "enabled": task_state,
                 "timer_active": None, "timer_enabled": None},
        "journal": None,
        "report": None,
        "report_error": "not collected on Windows",
        "users": [],
        "user_artifacts": {},
        "desktop_pixels": None,
    }


# --- evaluation ------------------------------------------------------------

def _check(check_id: str, ok: bool, detail: str, *, status_fail: str = FAIL) -> Check:
    return Check(check_id, PASS if ok else status_fail, detail)


def evaluate(facts: dict, exp: Expectations) -> list:
    """Turn facts into pass/fail/warn/skip results. Pure; no remote access."""
    checks = []
    present = set(facts.get("files") or [])
    is_win = facts.get("os") == "windows"

    # 1. the install is complete
    missing = [name for name in REQUIRED_FILES if name not in present]
    checks.append(_check("install.files",
                         not missing,
                         "all required files present" if not missing
                         else f"missing: {', '.join(missing)}"))

    # 2. honour ships the rubric on-box; ranked must never.
    has_rubric = artifacts_mod.RUBRIC_BASENAME in present
    if exp.mode == "honor":
        checks.append(_check("install.rubric", has_rubric,
                             "rubric present (honor)" if has_rubric
                             else "honor box is missing its rubric"))
    else:
        checks.append(_check("install.no-rubric", not has_rubric,
                             "no rubric on the box (ranked)"
                             if not has_rubric else "ranked box carries a rubric!"))

    # 3. the box is running the build we verified locally
    expected = (exp.expected_manifest_sha or "").lower()
    got = (facts.get("manifest_sha") or "").lower()
    if not expected:
        checks.append(Check("lineage.manifest", SKIP,
                            "no manifest hash in build-state.json (recompile to record it)"))
    else:
        checks.append(_check("lineage.manifest", expected == got,
                             "manifest matches the compiled artifact"
                             if expected == got else
                             f"on-box {got[:12] or '(none)'} != built {expected[:12]}"))

    expected_key = (exp.expected_key_sha or "").lower()
    got_key = (facts.get("key_sha") or "").lower()
    if not expected_key:
        checks.append(Check("lineage.key", SKIP,
                            "no authoring-key hash in build-state.json"))
    else:
        checks.append(_check("lineage.key", expected_key == got_key,
                             "authoring public key matches this lineage"
                             if expected_key == got_key else
                             f"on-box key {got_key[:12] or '(none)'} != "
                             f"lineage key {expected_key[:12]}"))

    # 4. the agent is configured for the target we asked for
    cfg = facts.get("agent_config") or {}
    cfg_mode = cfg.get("mode")
    if not cfg:
        checks.append(Check("config.mode", FAIL, "agent_config.json missing or unparsable"))
    else:
        checks.append(_check("config.mode", cfg_mode == exp.mode,
                             f"mode={cfg_mode!r}"))
        if exp.mode == "ranked":
            checks.append(_check("config.engine", bool(cfg.get("engine_url")),
                                 f"engine_url={cfg.get('engine_url')!r}"))
            token = cfg.get("enrollment_token")
            if exp.competition:
                checks.append(_check("config.token", token is None,
                                     "competition box carries no enrollment token"
                                     if token is None else
                                     "competition box carries an enrollment token"))
            else:
                checks.append(Check("config.token", PASS if token else WARN,
                                    "enrollment token minted" if token
                                    else "no enrollment token (box cannot enroll)"))
        else:
            checks.append(_check("config.rubric-path", bool(cfg.get("rubric_path")),
                                 f"rubric_path={cfg.get('rubric_path')!r}"))

    # 5. init state matches the mode
    init = facts.get("init") or {}
    active = str(init.get("active") or "").strip().lower()
    if not is_win and active in ("", "unknown"):
        checks.append(Check("init.state", SKIP, "no supported init system detected"))
    elif exp.competition:
        checks.append(_check("init.state", active in ("inactive", "stopped", "ready", "disabled"),
                             f"unit is {active or 'absent'} (started by `huitz join`)"))
    else:
        checks.append(_check("init.state", active == "active",
                             f"unit is {active or 'absent'}"))
    if exp.mode == "honor" and not is_win:
        timer = str(init.get("timer_active") or "").strip().lower()
        if timer:
            checks.append(_check("init.timer", timer == "active",
                                 f"re-grade timer is {timer}"))
    elif exp.mode == "ranked" and not is_win:
        timer = str(init.get("timer_active") or "").strip().lower()
        if timer == "active":
            checks.append(Check("init.timer", FAIL,
                                "honor re-grade timer is active on a ranked box"))

    # 6. the agent is not crash-looping
    journal = facts.get("journal")
    if not journal:
        checks.append(Check("agent.journal", SKIP, "no journal available"))
    else:
        hits = [line for line in journal.splitlines()
                if any(marker in line for marker in _CRASH_MARKERS)]
        checks.append(_check("agent.journal", not hits,
                             "no tracebacks in the last 200 lines" if not hits
                             else f"{len(hits)} crash marker(s): {hits[0][:120]}"))

    # 7. the report is the one this box should produce
    report = facts.get("report")
    if exp.competition:
        checks.append(Check("report.state", SKIP,
                            "competition box produces its first report after `huitz join`"))
    elif report is None:
        checks.append(Check("report.state", FAIL,
                            facts.get("report_error") or "no report"))
    else:
        problems = []
        if report.get("snapshot_version") != 1:
            problems.append(f"snapshot_version={report.get('snapshot_version')!r}")
        if report.get("mode") != exp.mode:
            problems.append(f"mode={report.get('mode')!r}")
        if exp.scenario_name and report.get("scenario_name") != exp.scenario_name:
            problems.append(f"scenario={report.get('scenario_name')!r}")
        if not isinstance(report.get("total"), int):
            problems.append(f"total={report.get('total')!r} (awaiting engine?)")
        elif exp.expect_total is not None and report["total"] != exp.expect_total:
            problems.append(f"total={report['total']} (expected {exp.expect_total})")
        checks.append(_check("report.state", not problems,
                             "report is valid" if not problems else "; ".join(problems)))
        if isinstance(report.get("total"), int) and isinstance(report.get("max_possible"), int):
            checks.append(_check("report.max", report["max_possible"] > 0,
                                 f"max_possible={report['max_possible']}"))

    # 8. the player-facing mirrors exist
    per_user = facts.get("user_artifacts") or {}
    if exp.competition:
        checks.append(Check("report.mirror", SKIP, "no run yet"))
    elif not per_user:
        checks.append(Check("report.mirror", SKIP, "no interactive accounts found"))
    else:
        with_mirror = [name for name, arts in per_user.items() if arts.get("report_mirror")]
        checks.append(_check("report.mirror", bool(with_mirror),
                             f"mirror in: {', '.join(with_mirror)}" if with_mirror
                             else "no user has Documents/huitzilopochtli/report.json"))

    # 9. themed artifacts
    theme = exp.theme or {}
    wallpaper = theme.get("wallpaper")
    if wallpaper:
        base = os.path.basename(str(wallpaper))
        found = [n for n in (facts.get("theme_files") or []) if n.endswith(base)]
        checks.append(_check("theme.wallpaper", bool(found),
                             f"installed: {', '.join(found)}" if found
                             else f"no *{base} under the theme dir"))
    if theme.get("readme"):
        readers = [name for name, arts in per_user.items() if arts.get("readme_mirror")]
        checks.append(_check("theme.readme", bool(readers),
                             f"README.html in: {', '.join(readers)}" if readers
                             else "no user has Documents/huitzilopochtli/README.html"))
    has_shortcuts = bool(theme) and (
        bool(theme.get("desktop_shortcuts"))
        or theme.get("include_report_shortcut") is not False)
    if has_shortcuts:
        expected_entries = len(theme.get("desktop_shortcuts") or [])
        if theme.get("include_report_shortcut") is not False:
            expected_entries += 1
        counts = {name: arts.get("desktop_entries", 0) for name, arts in per_user.items()}
        if counts:
            best = max(counts.values())
            checks.append(_check("theme.shortcuts", best >= expected_entries,
                                 f"desktop entries: {counts} (expected >= {expected_entries})"))
        else:
            checks.append(Check("theme.shortcuts", SKIP, "no interactive accounts"))
    elif not is_win:
        checks.append(Check("theme.shortcuts", SKIP, "scenario has no theme shortcuts"))

    # 10. the desktop actually paints
    pixels = facts.get("desktop_pixels")
    if pixels is None:
        checks.append(Check("desktop.renders", SKIP,
                            "xwd unavailable (no local X session or tool missing)"))
    else:
        checks.append(_check("desktop.renders", pixels > 100_000,
                             f"framebuffer capture is {pixels} bytes"))

    # 11. seal hygiene
    if exp.for_seal:
        machine_id = facts.get("machine_id")
        if machine_id is None:
            checks.append(Check("seal.machine-id", SKIP, "not reported by this platform"))
        else:
            checks.append(_check("seal.machine-id", len(machine_id) > 0,
                                 f"machine-id has {len(machine_id)} chars "
                                 f"(wipe it as the last seal step)"))
        checks.append(_check("seal.legacy-dir", not facts.get("legacy_dir"),
                             "no legacy /opt/huitzilopochtli" if not facts.get("legacy_dir")
                             else "legacy /opt/huitzilopochtli is still present"))
        identity = "identity.json" in present
        if identity:
            checks.append(Check("seal.identity", WARN,
                                "identity.json present; seal-prepare removes it"))
        else:
            checks.append(Check("seal.identity", PASS, "no per-player identity on the box"))

    return checks


def summarise(checks: list) -> dict:
    counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0}
    for check in checks:
        counts[check.status] = counts.get(check.status, 0) + 1
    return {"ok": counts[FAIL] == 0, "counts": counts,
            "checks": [{"id": c.id, "status": c.status, "detail": c.detail}
                       for c in checks]}


# --- expectations ----------------------------------------------------------

def expectations_from(spec, artifacts_dir: str, *, competition: bool = False,
                       expect_total: Optional[int] = None,
                       for_seal: bool = False) -> Expectations:
    state = {}
    path = os.path.join(artifacts_dir, "build-state.json")
    if os.path.isfile(path):
        try:
            state = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            state = {}
    mode = spec.mode
    default_total = 0 if mode == "honor" and not competition else None
    return Expectations(
        mode=mode,
        competition=competition,
        for_seal=for_seal,
        expect_total=default_total if expect_total is None else expect_total,
        theme=spec.theme,
        expected_manifest_sha=state.get("manifest_sha256"),
        expected_key_sha=state.get("authoring_public_key_sha256"),
        scenario_name=(spec.scenario.get("scenario") or {}).get("name"),
    )


# --- seal ------------------------------------------------------------------

@dataclass
class SealStep:
    id: str
    status: str  # "done" | "skipped" | "failed"
    detail: str


def _seal_script(install_dir: str, mode: str) -> str:
    return f"""
echo "##stop"
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now huitzilopochtli-agent.timer >/dev/null 2>&1
  systemctl disable --now huitzilopochtli-agent.service >/dev/null 2>&1
  echo ok
elif command -v rc-service >/dev/null 2>&1; then
  rc-update del huitzilopochtli-agent default >/dev/null 2>&1
  rc-service huitzilopochtli-agent stop >/dev/null 2>&1
  echo ok
else
  echo skipped
fi
echo "##purge"
rm -f {install_dir}/identity.json {install_dir}/identity.json.* \
      {install_dir}/.enrolled {install_dir}/report.json {install_dir}/report.html \
      {install_dir}/.last_score {install_dir}/.grade.lock 2>/dev/null
rm -rf {_LEGACY_INSTALL_DIR} 2>/dev/null
echo ok
echo "##mirrors"
find /home -maxdepth 4 -path '*/Documents/huitzilopochtli/report.*' -delete 2>/dev/null
find /home -maxdepth 3 -path '*/Desktop/report.*' -delete 2>/dev/null
rm -rf /home/*/Documents/huitzilopochtli/README.html.tmp 2>/dev/null
echo ok
echo "##machine-id"
: > /etc/machine-id 2>/dev/null && echo ok || echo failed
echo "##size"
wc -c < /etc/machine-id 2>/dev/null
""".strip()


def prepare_seal(handle, spec, artifacts_dir: str = "artifacts",
                 skip_verify: bool = False, expect_total: Optional[int] = None,
                 log=print) -> dict:
    """Remove per-player state and neutralize the box so it can be sealed."""
    exp = expectations_from(spec, artifacts_dir, competition=True,
                             expect_total=expect_total, for_seal=True)
    verify_report = None
    if not skip_verify:
        facts = collect_facts(handle, spec, artifacts_dir)
        verify_report = summarise(evaluate(facts, exp))
        if not verify_report["ok"]:
            return {"ok": False, "step": "seal-prepare", "reason": "verify failed",
                    "verify": verify_report}

    os_name = getattr(handle, "os_name", None) or "posix"
    install_dir = artifacts_mod.install_dir_for(os_name)
    steps = []
    if is_windows(os_name):
        out = handle.run_ps(
            f"$d='{install_dir}'; "
            "schtasks.exe /End /TN 'HuitzilopochtliAgent' 2>$null | Out-Null; "
            "schtasks.exe /Change /TN 'HuitzilopochtliAgent' /DISABLE 2>$null | Out-Null; "
            "Remove-Item -LiteralPath \"$d\\identity.json\" -Force -ErrorAction Ignore; "
            "Remove-Item -LiteralPath \"$d\\report.json\" -Force -ErrorAction Ignore; "
            "Remove-Item -LiteralPath \"$d\\report.html\" -Force -ErrorAction Ignore; "
            "Write-Output 'ok'")
        steps.append(SealStep("agent", "done" if out.ok else "failed",
                              (out.stdout or out.stderr).strip()[:200]))
        steps.append(SealStep("machine-id", "skipped", "Windows has no machine-id"))
    else:
        sections = _parse_kv_sections(handle.run(_seal_script(install_dir, spec.mode)).stdout)
        steps.append(SealStep("agent", "done" if sections.get("stop") == "ok" else "skipped",
                              "stopped and disabled" if sections.get("stop") == "ok"
                              else "no supported init system"))
        steps.append(SealStep("state", "done" if sections.get("purge") == "ok" else "failed",
                              "identity, enrollment and report state removed"))
        steps.append(SealStep("mirrors", "done" if sections.get("mirrors") == "ok" else "failed",
                              "per-user report mirrors removed"))
        size = (sections.get("size") or "").strip()
        steps.append(SealStep("machine-id",
                              "done" if sections.get("machine-id") == "ok" and size == "0"
                              else "failed",
                              f"/etc/machine-id is {size or '?'} bytes (must be 0)"))

    return {
        "ok": all(step.status != "failed" for step in steps),
        "step": "seal-prepare",
        "steps": [s.__dict__ for s in steps],
        "verify": verify_report,
        "lineage": {
            "manifest_sha256": exp.expected_manifest_sha,
            "authoring_public_key_sha256": exp.expected_key_sha,
        },
        "next": [
            "record the lineage hashes above with the template",
            "power off cleanly",
            "convert the VM to a template and rename it",
            "keep the previous template until this one is field-confirmed",
        ],
    }
