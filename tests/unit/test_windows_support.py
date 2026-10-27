"""Windows target support: artifacts layout, win32 check branches (mocked),
check types, the Windows theme branch, and the -win seed definitions.

Nothing here names a box: the parametrized cases discover whatever Windows
boxes exist under boxes/."""
import json
import os
import subprocess

import pytest

from boxbuilder import artifacts
from common.schema import Category, CheckSpec, CollectorStatus


def _spec(check_type, collect, cid="c1"):
    return CheckSpec(
        id=cid, type=check_type, category=Category.VULN, host_id="localhost",
        collect_params=collect, display_title="t", display_max_points=10,
    )


# --- artifacts: target-OS install layout -------------------------------------

def test_install_dir_for():
    assert artifacts.install_dir_for("posix") == "/opt/.huitzilopochtli"
    assert artifacts.install_dir_for("windows") == "C:\\ProgramData\\huitzilopochtli"
    assert artifacts.INSTALL_DIR == "/opt/.huitzilopochtli"  # historical default


def test_windows_agent_config_paths():
    cfg = artifacts.agent_config_dict("demo", "honor", os_name="windows")
    assert cfg["manifest_path"].startswith("C:\\ProgramData\\huitzilopochtli\\")
    assert cfg["rubric_path"].endswith(f"\\{artifacts.RUBRIC_BASENAME}")
    assert cfg["report_path"].endswith("\\report.html")
    # POSIX unchanged
    posix = artifacts.agent_config_dict("demo", "honor")
    assert posix["manifest_path"].startswith("/opt/.huitzilopochtli/")


def test_on_box_files_windows_drops_sync_report(tmp_path):
    rubric = tmp_path / "rubric.json"
    rubric.write_text('{"entries": []}', encoding="utf-8")
    compile_result = {
        "agent_pyz": str(tmp_path / "agent.pyz"),
        "manifest": str(tmp_path / "manifest.signed.json"),
        "authoring_public_key": str(tmp_path / "key.b64"),
        "rubric": str(rubric),
    }
    cfg = artifacts.agent_config_dict("demo", "honor", os_name="windows")
    files = artifacts.on_box_files(compile_result, "honor", cfg, os_name="windows")
    remotes = [f.remote for f in files]
    assert f"{artifacts.install_dir_for('windows')}\\agent.pyz" in remotes
    assert not any("sync-report" in r for r in remotes)
    # POSIX keeps it
    files_posix = artifacts.on_box_files(compile_result, "honor", cfg)
    assert any("sync-report" in f.remote for f in files_posix)


# --- powershell_json collector (mocked PowerShell) ----------------------------

class _FakeProc:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


def test_powershell_json_ok(monkeypatch):
    import agent.checks.powershell_json as psj

    monkeypatch.setattr(psj, "run_ps", lambda script, timeout: _FakeProc('{"a": 1}'))
    ev = psj.PowerShellJsonCheck().collect(_spec("powershell_json", {"script": "x"}), None)
    assert ev.status == CollectorStatus.OK
    assert ev.raw["data"] == {"a": 1}


def test_powershell_json_scalar_bool(monkeypatch):
    import agent.checks.powershell_json as psj

    monkeypatch.setattr(psj, "run_ps", lambda script, timeout: _FakeProc("true"))
    ev = psj.PowerShellJsonCheck().collect(_spec("powershell_json", {"script": "x"}), None)
    assert ev.raw["data"] is True


def test_powershell_json_non_json_is_error(monkeypatch):
    import agent.checks.powershell_json as psj

    monkeypatch.setattr(psj, "run_ps", lambda script, timeout: _FakeProc("not json"))
    ev = psj.PowerShellJsonCheck().collect(_spec("powershell_json", {"script": "x"}), None)
    assert ev.status == CollectorStatus.ERROR


def test_powershell_json_timeout_and_missing_script(monkeypatch):
    import agent.checks.powershell_json as psj

    def _boom(script, timeout):
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=timeout)

    monkeypatch.setattr(psj, "run_ps", _boom)
    ev = psj.PowerShellJsonCheck().collect(_spec("powershell_json", {"script": "x"}), None)
    assert ev.status == CollectorStatus.ERROR

    ev = psj.PowerShellJsonCheck().collect(_spec("powershell_json", {}), None)
    assert ev.status == CollectorStatus.ERROR


# --- registry_value collector (Linux fails closed; hive validation) ----------

def test_registry_value_requires_windows():
    import agent.checks.registry_value as rv

    ev = rv.RegistryValueCheck().collect(
        _spec("registry_value", {"hive": "HKLM", "key": "SOFTWARE\\X", "value": "Y"}), None)
    # On the Linux dev/test machine winreg is absent -> ERROR evidence.
    assert ev.status == CollectorStatus.ERROR


def test_registry_value_param_validation():
    import agent.checks.registry_value as rv

    ev = rv.RegistryValueCheck().collect(_spec("registry_value", {}), None)
    assert ev.status == CollectorStatus.ERROR
    ev = rv.RegistryValueCheck().collect(
        _spec("registry_value", {"hive": "HKXX", "key": "A"}), None)
    assert ev.status == CollectorStatus.ERROR and "unknown hive" in ev.reason


def test_registry_type_names():
    from agent.checks.registry_value import _type_name
    assert _type_name(4) == "REG_DWORD"
    assert _type_name(1) == "REG_SZ"
    assert "REG_UNKNOWN" in _type_name(99)


# --- win32 branches of the shared checks (mocked) -----------------------------

def test_user_group_windows_branch(monkeypatch):
    import agent.checks.user_group as ug

    monkeypatch.setattr(ug, "_collect_windows",
                        lambda: (["sysadmin", "mharding"],
                                 {"Administrators": ["sysadmin", "mharding"]}))
    ev = ug.UserGroupCheck._collect_windows_evidence(
        ug.UserGroupCheck(), _spec("user_group", {}))
    assert ev.status == CollectorStatus.OK
    assert ev.raw["users"] == ["sysadmin", "mharding"]
    # Matchers operate on the identical raw shape as POSIX evidence.
    from common.matchers import evaluate_matcher
    ok, _ = evaluate_matcher({"user_absent": True, "username": "jweaver"}, ev.raw)
    assert ok
    ok, _ = evaluate_matcher(
        {"group_members_subset_of": True, "group": "Administrators",
         "allowed": ["sysadmin"]}, ev.raw)
    assert not ok  # mharding is an extra admin


def test_user_group_windows_error_is_error_evidence(monkeypatch):
    import agent.checks.user_group as ug

    def _boom():
        raise RuntimeError("no powershell")

    monkeypatch.setattr(ug, "_collect_windows", _boom)
    ev = ug.UserGroupCheck._collect_windows_evidence(
        ug.UserGroupCheck(), _spec("user_group", {}))
    assert ev.status == CollectorStatus.ERROR


def test_process_state_windows_branch(monkeypatch):
    import agent.checks.process_state as pstate
    import agent.platform.windows as win

    monkeypatch.setattr(win, "run_ps", lambda script, timeout: _FakeProc(
        json.dumps([
            {"p": 100, "c": r"powershell.exe -File C:\ProgramData\Subsystems\keysvc.ps1", "n": "powershell.exe"},
            {"p": 200, "c": None, "n": "svchost.exe"},
        ])))
    ev = pstate.ProcessStateCheck._collect_windows(
        pstate.ProcessStateCheck(), _spec("process_state", {"pattern": "keysvc"}), "keysvc")
    assert ev.status == CollectorStatus.OK
    assert ev.raw["running"] is True
    assert ev.raw["pids"] == [100]

    ev = pstate.ProcessStateCheck._collect_windows(
        pstate.ProcessStateCheck(), _spec("process_state", {"pattern": "nomatch"}), "nomatch")
    assert ev.raw["running"] is False


def test_process_state_windows_single_dict_result(monkeypatch):
    # ConvertTo-Json wraps a single object WITHOUT a list -- must be handled.
    import agent.checks.process_state as pstate
    import agent.platform.windows as win

    monkeypatch.setattr(win, "run_ps", lambda script, timeout: _FakeProc(
        json.dumps({"p": 100, "c": "keysvc.ps1", "n": "powershell.exe"})))
    ev = pstate.ProcessStateCheck._collect_windows(
        pstate.ProcessStateCheck(), _spec("process_state", {"pattern": "keysvc"}), "keysvc")
    assert ev.raw["count"] == 1


def test_windows_platform_context_contract(monkeypatch):
    """The WindowsContext maps CIM state/mode onto the PlatformContext contract."""
    import agent.platform.windows as win

    monkeypatch.setattr(win, "_service_info",
                        lambda name: {"State": "Running", "StartMode": "Auto"})
    ctx = win.WindowsContext()
    assert ctx.service_active("X") is True
    assert ctx.service_enabled("X") is True

    monkeypatch.setattr(win, "_service_info",
                        lambda name: {"State": "Stopped", "StartMode": "Disabled"})
    assert ctx.service_active("X") is False
    assert ctx.service_enabled("X") is False

    monkeypatch.setattr(win, "_service_info", lambda name: None)
    assert ctx.service_active("X") is False and ctx.service_enabled("X") is False


def test_service_info_rejects_quote_injection():
    import agent.platform.windows as win

    assert win._service_info("a'b") is None


# --- notify: windows toast escaping -------------------------------------------

def test_ps_escape():
    from agent.notify import _ps_escape
    assert _ps_escape("plain") == "'plain'"
    assert _ps_escape("it's") == "'it''s'"


# --- theme: windows branch -----------------------------------------------------

def test_target_is_windows():
    from boxbuilder.theme import _target_is_windows
    from boxbuilder.spec import BoxSpec

    def spec_with(os_value):
        return BoxSpec(
            scenario_path="x", nakon_config_path="x",
            nakon_config={"machines": [{"name": "records-01", "os": os_value}]},
        )

    assert _target_is_windows(spec_with("windows-server")) is True
    assert _target_is_windows(spec_with("win10")) is True
    assert _target_is_windows(spec_with("ubuntu-xfce")) is False


def test_windows_shortcut_pairs_report_target():
    from boxbuilder.theme import _shortcut_pairs
    pairs = _shortcut_pairs({}, windows=True)
    names = [n for n, _ in pairs]
    assert "Scoring Report" in names
    exec_cmd = dict(pairs)["Scoring Report"]
    # The report mirror lives off the Desktop (Public Documents) so the Public
    # Desktop stays at exactly the forensics answers file + shortcuts, but it
    # must still be a plain %PUBLIC% path every account's browser can read.
    assert exec_cmd == r"%PUBLIC%\Documents\huitzilopochtli\report.html"


SEED_DIRS = [
    "boxbuilder/vulndb_vuln_configs",
    "boxbuilder/vulndb_theme_configs",
]


def test_win_seeds_schema():
    import glob
    import os

    seeds = sorted(
        f for d in SEED_DIRS for f in glob.glob(os.path.join(d, "*-win.json"))
    )
    assert len(seeds) >= 18
    for path in seeds:
        d = json.load(open(path, encoding="utf-8"))
        assert d["name"] == os.path.basename(path)[:-5], path
        assert d["platform"] == "windows", path
        assert d["type"] == "powershell", path
        assert d["run_as"] == "Administrator", path
        assert d["script"].strip(), path
        assert isinstance(d["depends_on"], list), path
        assert "$args" not in d["script"], f"{path}: $args is a reserved automatic variable"


def test_deploy_config_passthrough_windows():
    from boxbuilder.nakon import derive_deploy_config

    cfg = {"machines": [{"id": 1, "name": "records-01", "ip": "REPLACED",
                         "os": "windows-server", "user": "u", "password": "p",
                         "port": 22, "configurations": ["uac-disabled-win"]}]}
    derived = derive_deploy_config(cfg, "records-01", host="192.0.2.5",
                                   user="sysadmin", password="pw", port=22)
    assert derived["machines"][0]["os"] == "windows-server"
    assert derived["machines"][0]["ip"] == "192.0.2.5"


def test_primary_desktop_dir_windows_uses_public_desktop(monkeypatch, tmp_path):
    """On Windows the forensics answers file belongs on the Public Desktop
    (the only editable surface shared by all accounts), not the sealed agent
    config dir."""
    import agent.__main__ as main_mod

    pub = tmp_path / "Public" / "Desktop"
    pub.mkdir(parents=True)
    monkeypatch.setattr(main_mod.os, "name", "nt")
    monkeypatch.setattr(main_mod.os.environ, "get",
                        lambda k, d=None: str(tmp_path / "Public") if k == "PUBLIC" else d)
    assert main_mod._primary_desktop_dir() == str(pub)

    # No Public dir -> None (caller falls back to the config dir).
    monkeypatch.setattr(main_mod.os.path, "isdir", lambda p: False)
    assert main_mod._primary_desktop_dir() is None


def test_primary_desktop_dir_posix_unchanged(monkeypatch):
    """The POSIX heuristic must keep its pwd-based behavior (no win32 leak)."""
    import agent.__main__ as main_mod

    monkeypatch.setattr(main_mod.os, "name", "posix")
    import types, sys as _sys
    fake_pwd = types.ModuleType("pwd")
    fake_pwd.getpwall = lambda: []
    monkeypatch.setitem(_sys.modules, "pwd", fake_pwd)
    assert main_mod._primary_desktop_dir() is None


def test_honor_interval_s_platform_split(monkeypatch):
    """Windows re-grades every 300s (schtask cadence); POSIX keeps the
    reporter's 70s default. The countdown anchor must match the platform."""
    import agent.__main__ as main_mod

    monkeypatch.setattr(main_mod.os, "name", "nt")
    assert main_mod._honor_interval_s() == 300
    monkeypatch.setattr(main_mod.os, "name", "posix")
    assert main_mod._honor_interval_s() is None


def test_windows_hardening_script_kills_the_known_popups():
    """packaging/huitz-hardening-win.ps1 must address every documented popup:
    Edge first-run, the Shutdown Event Tracker modal, Server Manager auto-open
    (in the Default user hive -- SSH HKCU writes don't survive sealing), and
    the python MSI advertised-shortcut self-repair trap."""
    script = open("packaging/huitz-hardening-win.ps1", encoding="utf-8").read()
    # Edge onboarding
    assert "Policies\\Microsoft\\Edge" in script
    assert "HideFirstRunExperience" in script and "AutoImportAtFirstRun" in script
    # software rendering: GPU text compositing smears under remote encoders
    assert "HardwareAccelerationModeEnabled" in script
    # Shutdown Event Tracker
    assert "ShutdownReasonOn" in script and "ShutdownReasonUI" in script
    # Server Manager in C:\Users\Default\NTUSER.DAT via reg load/unload
    assert "NTUSER.DAT" in script and "DoNotOpenAtLogon" in script
    assert "reg load" in script and "reg unload" in script
    # python advertised shortcuts : repair + remove the Start-menu
    # folder, with the repair bounded so a slow msiexec cannot stall a build.
    assert "/faus" in script and "Start Menu\\Programs\\Python" in script
    assert "WaitForExit(120000)" in script and "Stop-Process" in script
    # Best-effort contract: every section guarded, script always exits 0.
    assert script.rstrip().endswith("exit 0")
    assert script.count("WARNING:") >= 3


def test_pipeline_installs_hardening_on_windows_only():
    """pipeline.install_box must place + run the hardening script inside its
    windows branch (between the hardening marker and the POSIX-only motd
    section) -- POSIX machines never see the hardening SFTP/run."""
    import inspect
    from boxbuilder import pipeline
    src = inspect.getsource(pipeline.install_box)
    assert "huitz-hardening-win.ps1" in src
    _, _, tail = src.partition("# --- Windows logon/browser hardening")
    block = tail[:tail.find("# --- first-login motd")]
    assert 'is_windows(os_name)' in block
    assert "harden_remote" in block and "harden_local" in block


def test_pipeline_stops_old_windows_agent_before_reinstall_clean():
    """A template clone can inherit a running SYSTEM agent holding
    .grade.lock; install_box must stop the task/agent before Remove-Item or
    every reinstall fails with a sharing violation."""
    import inspect
    from boxbuilder import pipeline
    src = inspect.getsource(pipeline.install_box)
    assert "schtasks.exe /End" in src
    assert "taskkill.exe /F /IM python.exe" in src
    assert ".grade.lock" in src


def test_win_task_script_mirrors_to_public_documents():
    """The scheduled-task wrapper maintains the report mirror in the Public
    Documents dir (off the Desktop) and purges the legacy Public Desktop copies;
    the forensics ACL re-grant is untouched."""
    ps1 = open("packaging/huitz-agent-task.ps1", encoding="utf-8").read()
    assert "Documents\\huitzilopochtli" in ps1
    assert "Desktop\\report.html" in ps1 and "Desktop\\report.json" in ps1
    assert "icacls $forensics /grant '*S-1-5-32-545:M'" in ps1

# --- generic, box-agnostic Windows contracts --------------------------------
#
# These iterate whatever boxes exist; nothing here names a box. A new Windows
# box gets the coverage automatically, and deleting one needs no test edit.

def _box_dirs():
    import glob
    return sorted(d for d in glob.glob("boxes/*/") if os.path.isfile(d + "nakon.json"))


def _declared_os(box_dir):
    cfg = json.load(open(box_dir + "nakon.json", encoding="utf-8"))
    return cfg["machines"][0].get("os")


def _windows_box_dirs():
    from boxbuilder.os_family import is_windows
    return [d for d in _box_dirs() if is_windows(_declared_os(d))]


def test_there_is_at_least_one_windows_box():
    assert _windows_box_dirs(), "the Windows contract tests would silently pass"


@pytest.mark.parametrize("box_dir", _windows_box_dirs())
def test_windows_box_theme_is_wired(box_dir):
    """A Windows box without a theme ships no wallpaper/handbook at all."""
    import yaml
    from boxbuilder.spec import load_spec
    from boxbuilder.theme import _target_is_windows

    scenario = yaml.safe_load(open(box_dir + "scenario.yaml", encoding="utf-8"))
    theme = scenario.get("theme") or {}
    for key in ("title", "wallpaper", "readme"):
        assert theme.get(key), f"{box_dir} theme missing {key}"
        if key != "title":
            assert os.path.isfile(box_dir + theme[key]), f"{box_dir}: missing {theme[key]}"

    spec = load_spec(box_dir + "box.yaml")
    assert _target_is_windows(spec), f"{box_dir} must resolve as a windows target"


@pytest.mark.parametrize("box_dir", _windows_box_dirs())
def test_windows_shortcut_pairs_are_complete(box_dir):
    import yaml
    from boxbuilder.theme import _shortcut_pairs

    scenario = yaml.safe_load(open(box_dir + "scenario.yaml", encoding="utf-8"))
    theme = scenario.get("theme") or {}
    pairs = _shortcut_pairs(theme, windows=True)
    names = [name for name, _ in pairs]
    assert "Scoring Report" in names, box_dir
    for shortcut in theme.get("desktop_shortcuts") or []:
        assert shortcut["name"] in names, f"{box_dir}: {shortcut['name']} dropped"
    report_exec = dict(pairs)["Scoring Report"]
    assert report_exec.endswith(r"\report.html"), box_dir


def test_account_checks_score_the_disabled_flag():
    """An account check must grade the Disabled flag, not an account's
    absence: a deleted account can otherwise score nothing while an untouched
    one scores full points, and evidence a forensics question asks about is
    destroyed by the fix."""
    import yaml
    checked = 0
    for box_dir in _box_dirs():
        scenario = yaml.safe_load(open(box_dir + "scenario.yaml", encoding="utf-8"))
        for check in scenario.get("checks") or []:
            script = (check.get("collect") or {}).get("script") or ""
            # Only per-account checks (they name an account); a policy-wide
            # count of blank-password accounts has no single account to require.
            if ".Disabled" not in script or "Name='" not in script:
                continue
            checked += 1
            assert check["expect"].get("equals") is True, check["id"]
            assert check["expect"].get("field") == "data", check["id"]
    assert checked, "no account checks found -- the rule is no longer enforced"
