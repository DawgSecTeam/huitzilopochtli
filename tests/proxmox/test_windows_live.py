r"""Live Windows verification: every Windows-first check type on a real
Windows Server clone, plus a real boxbuilder install (scheduled task, ACL
seal, first report).

This is the Windows counterpart to test_all_check_types_live.py. It closes
the "Windows is only statically mocked" gap by running the real agent zipapp
under a real Windows Python against real registry/service/WMI state.

The 953 template ships OpenSSH but no Python, so the fixture installs Python
3.12 from python.org and bootstraps a local admin exactly the way
boxbuilder/REDEPLOY.md's Windows round describes. Files are pushed over SFTP
(the guest-agent file-write API cannot reassemble the ~270KB agent.pyz:
its chunked path shells out to /bin/sh, which Windows does not have).

The second test uses the same clone and drives boxbuilder.pipeline.install_box
end to end through the ssh provider -- the path that registers the SYSTEM
HuitzilopochtliAgent scheduled task and seals C:\ProgramData\huitzilopochtli.
"""
import base64
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

from tests.proxmox import proxmox_helper as ph  # noqa: E402

INSTALL_DIR = r"C:\ProgramData\huitz-livetest"
INSTALL_DIR_SFTP = "C:/ProgramData/huitz-livetest"
HTTP_PORT = 8765
PYTHON = r"C:\Python312\python.exe"


@pytest.fixture(scope="module")
def proxmox():
    return ph.get_proxmox_client()


def _ps(client, script: str, timeout_s: float = 120) -> dict:
    """Run PowerShell via -EncodedCommand (cmd.exe cannot mangle it)."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return ph.ssh_exec(
        client,
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {encoded}",
        timeout_s=timeout_s,
    )


def _scenario_yaml():
    return f"""
scenario:
  name: "WindowsLiveChecks"
  version: 1
  mode: honor
  hosts: ["localhost"]

checks:
  - id: banner_ok
    type: file_regex
    category: vuln
    display: "Banner present"
    max_points: 10
    collect:
      path: '{INSTALL_DIR}\\banner.txt'
      extract: '(SECURE_BANNER)'
    expect:
      equals: "SECURE_BANNER"
      points: 10

  - id: cmd_present
    type: permission
    category: vuln
    display: "cmd.exe present"
    max_points: 10
    collect:
      path: 'C:\\Windows\\System32\\cmd.exe'
    expect:
      equals: true
      field: exists
      points: 10

  - id: admins_subset
    type: user_group
    category: vuln
    display: "Only authorized admins"
    max_points: 10
    timeout_s: 30
    collect: {{}}
    expect:
      group_members_subset_of: true
      group: Administrators
      allowed: [sysadmin, Administrator]
      points: 10

  - id: sshd_active
    type: service_state
    category: vuln
    display: "sshd service active"
    max_points: 10
    timeout_s: 30
    collect:
      service: sshd
    expect:
      equals: true
      field: active
      points: 10

  - id: sshd_running
    type: process_state
    category: vuln
    display: "sshd process running"
    max_points: 10
    timeout_s: 30
    collect:
      pattern: sshd
    expect:
      equals: true
      field: running
      points: 10

  - id: uac_enabled
    type: registry_value
    category: vuln
    display: "UAC enabled"
    max_points: 10
    collect:
      hive: HKLM
      key: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
      value: EnableLUA
    expect:
      equals: 1
      field: value
      points: 10

  - id: firewall_on
    type: powershell_json
    category: vuln
    display: "Firewall enabled on all profiles"
    max_points: 10
    timeout_s: 30
    collect:
      script: |
        $off = @(Get-NetFirewallProfile | Where-Object {{ -not $_.Enabled }}).Count
        ($off -eq 0) | ConvertTo-Json -Compress
    expect:
      equals: true
      field: data
      points: 10

  - id: http_up
    type: http_uptime
    category: vuln
    display: "local http server reachable"
    max_points: 10
    timeout_s: 20
    collect:
      url: "http://127.0.0.1:{HTTP_PORT}/"
    expect:
      equals: 200
      field: status
      points: 10

  - id: ssh_socket_open
    type: db_query
    category: vuln
    display: "sshd socket reachable"
    max_points: 10
    collect:
      host: 127.0.0.1
      port: 22
    expect:
      equals: true
      field: ok
      points: 10
"""


def _build_artifacts(tmp_path):
    import yaml

    from authoring.compile import compile_scenario
    from common.crypto import signing

    scenario_text = _scenario_yaml()
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(scenario_text, encoding="utf-8")
    scenario = yaml.safe_load(scenario_text)

    nakon_config = {
        "machines": [{
            "name": "win-live",
            "os": "windows-server",
            "configurations": [],
        }]
    }
    nakon_path = tmp_path / "nakon.json"
    nakon_path.write_text(json.dumps(nakon_config), encoding="utf-8")

    kp = signing.keypair()
    out_dir = tmp_path / "compiled"
    out_dir.mkdir()
    outputs = compile_scenario(str(scenario_path), str(out_dir), kp[0])

    zipapp_path = tmp_path / "agent.pyz"
    subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "packaging", "build_zipapp.py"),
         str(zipapp_path)],
        cwd=REPO_ROOT, check=True, timeout=60,
    )

    config = {
        "mode": "honor",
        "manifest_path": f"{INSTALL_DIR}\\manifest.signed.json",
        "authoring_public_key_path": f"{INSTALL_DIR}\\authoring_public_key.b64",
        "rubric_path": f"{INSTALL_DIR}\\rubric.json",
        "identity_path": None,
        "report_path": f"{INSTALL_DIR}\\report.html",
        "checkin_interval_s": None,
    }
    files = {
        "agent.pyz": zipapp_path.read_bytes(),
        "manifest.signed.json": open(outputs["manifest"], "rb").read(),
        "authoring_public_key.b64": open(outputs["authoring_public_key"], "rb").read(),
        "rubric.json": open(outputs["rubric"], "rb").read(),
        "agent_config.json": json.dumps(config).encode(),
        "banner.txt": b"SECURE_BANNER\n",
    }
    return {
        "files": files,
        "scenario_path": str(scenario_path),
        "nakon_path": str(nakon_path),
        "scenario": scenario,
        "nakon_config": nakon_config,
        "manifest": outputs["manifest"],
        "rubric": outputs["rubric"],
        "authoring_public_key": outputs["authoring_public_key"],
        "agent_pyz": str(zipapp_path),
    }


def _http_status(client):
    r = _ps(client, (
        f"try {{ (Invoke-WebRequest -UseBasicParsing "
        f"'http://127.0.0.1:{HTTP_PORT}/' -TimeoutSec 5).StatusCode }} "
        f"catch {{ 0 }}"
    ), timeout_s=20)
    return r["out"].strip().splitlines()[-1] if r["out"].strip() else "0"


def _start_http_server(client):
    if _http_status(client).strip() == "200":
        return
    # A plain Start-Process child dies when the SSH session closes (Windows
    # OpenSSH tears down the job). Register the server as a SYSTEM scheduled
    # task instead so it survives across the separate SSH commands that run
    # the agent.
    started = _ps(client, (
        f"if (-not (Test-Path '{PYTHON}')) {{ 'NO_PYTHON'; exit 3 }}; "
        f"$action = New-ScheduledTaskAction -Execute '{PYTHON}' "
        f"-Argument '-m http.server {HTTP_PORT} --bind 127.0.0.1' "
        f"-WorkingDirectory '{INSTALL_DIR}'; "
        f"$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' "
        f"-LogonType ServiceAccount -RunLevel Highest; "
        f"Register-ScheduledTask -TaskName 'huitz-livetest-http' "
        f"-Action $action -Principal $principal -Force | Out-Null; "
        f"Start-ScheduledTask -TaskName 'huitz-livetest-http'; 'STARTED'"
    ), timeout_s=60)
    import time
    for _ in range(30):
        if _http_status(client).strip() == "200":
            return
        time.sleep(1)
    log = _ps(client, (
        f"$info = Get-ScheduledTaskInfo -TaskName 'huitz-livetest-http' "
        f"-ErrorAction SilentlyContinue | Select-Object LastTaskResult | "
        f"ConvertTo-Json -Compress; "
        f"$state = (Get-ScheduledTask -TaskName 'huitz-livetest-http' "
        f"-ErrorAction SilentlyContinue).State; "
        f"'TASK=' + $state + ' RESULT=' + $info"
    ), timeout_s=20)
    raise AssertionError(
        f"local HTTP server did not start on the Windows guest; "
        f"start={started!r} task={log!r}")

@pytest.fixture(scope="module")
def windows_vm(proxmox):
    template_vmid = int(os.environ.get("TEST_TEMPLATE_VMID_WINDOWS", "953"))
    vmid = ph.clone_vm(proxmox, template_vmid, "windows-live")
    client = None
    try:
        prepared = os.environ.get("TEST_WINDOWS_PREPARED") == "1"
        ph.wait_for_agent(proxmox, vmid, timeout_s=300)
        ip = ph.wait_for_ip(proxmox, vmid, timeout_s=180)
        if prepared:
            # A prepared Windows template (see tests/README.md) already has
            # sysadmin, the sshd firewall rule, and Python. Skip qemu-ga
            # bootstrap/install entirely; qga is this image's least reliable
            # component and is not needed once the template is prepped.
            client = ph.ssh_connect(
                ip, "sysadmin", password=ph.TEST_VM_PASSWORD,
                timeout_s=240)
        else:
            client = ph.ensure_windows_ssh(proxmox, vmid, ip, timeout_s=300)
            client = ph.ensure_windows_python(client, timeout_s=900)
            try:
                ip = ph.wait_for_ip(proxmox, vmid, timeout_s=60)
            except Exception:
                pass
        yield {"vmid": vmid, "ip": ip, "client": client}
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        ph.destroy_vm(proxmox, vmid)


def test_all_check_types_on_real_windows_vm(windows_vm, tmp_path):
    client = windows_vm["client"]
    built = _build_artifacts(tmp_path)

    r = _ps(client, f"New-Item -ItemType Directory -Force -Path '{INSTALL_DIR}' | Out-Null")
    assert r["exitcode"] == 0, r
    for filename, content in built["files"].items():
        ph.sftp_put_bytes(client, f"{INSTALL_DIR_SFTP}/{filename}", content)

    _start_http_server(client)

    run = ph.ssh_exec(
        client,
        f'"{PYTHON}" "{INSTALL_DIR}\\agent.pyz" '
        f'"{INSTALL_DIR}\\agent_config.json"',
        timeout_s=240,
    )
    assert run["exitcode"] == 0, run

    report = ph.sftp_read_bytes(client, f"{INSTALL_DIR_SFTP}/report.html").decode("utf-8")
    assert "Total: 90" in report, report


@pytest.mark.skipif(
    not os.environ.get("TEST_WINDOWS_INSTALL_HOST"),
    reason="set TEST_WINDOWS_INSTALL_HOST to a prepared Windows box "
           "(sysadmin + sshd firewall rule + Python on PATH) to run the "
           "install-path test; the clone-based check-type test runs without it",
)
def test_boxbuilder_installs_on_live_windows_host(tmp_path, monkeypatch):
    """Drive boxbuilder's real ssh-provider install against a prepared Windows
    box: place+seal files, register the SYSTEM scheduled task, run it once,
    and verify the first report.

    Opt-in (TEST_WINDOWS_INSTALL_HOST) because it needs a host with sysadmin,
    the sshd firewall rule, and Python -- exactly what the prepared template
    provides. It does not clone or destroy anything.
    """
    from boxbuilder.pipeline import _input_fingerprint, install_box
    from boxbuilder.spec import BoxSpec

    monkeypatch.setenv("HUITZILOPOCHTLI_INSECURE_HOST_KEYS", "1")
    monkeypatch.setenv("HUITZILOPOCHTLI_SKIP_WINDOWS_HARDENING", "1")
    host = os.environ["TEST_WINDOWS_INSTALL_HOST"]
    password = os.environ.get("TEST_WINDOWS_INSTALL_PASSWORD",
                              ph.TEST_VM_PASSWORD)
    client = ph.ssh_connect(host, "sysadmin", password=password, timeout_s=120)
    try:
        built = _build_artifacts(tmp_path)
        r = _ps(client, f"New-Item -ItemType Directory -Force -Path '{INSTALL_DIR}' | Out-Null")
        assert r["exitcode"] == 0, r
        for filename, content in built["files"].items():
            ph.sftp_put_bytes(client, f"{INSTALL_DIR_SFTP}/{filename}", content)

        spec = BoxSpec(
            scenario_path=built["scenario_path"],
            nakon_config_path=built["nakon_path"],
            provider={
                "name": "ssh", "host": host, "port": 22,
                "user": "sysadmin", "password": password,
            },
            scenario=built["scenario"],
            nakon_config=built["nakon_config"],
        )
        compile_result = {
            "mode": "honor",
            "scenario_name": built["scenario"]["scenario"]["name"],
            "engine_url": None,
            "manifest": built["manifest"],
            "rubric": built["rubric"],
            "authoring_public_key": built["authoring_public_key"],
            "agent_pyz": built["agent_pyz"],
            "input_fingerprint": _input_fingerprint(spec),
        }
        result = install_box(
            spec, str(tmp_path / "artifacts"), compile_result=compile_result,
            init_kind=None, log=lambda *a: None,
        )
        assert result["ok"] is True, result
        assert result["init"] == "windows", result
        assert any(p.lower().endswith("agent.pyz") for p in result["files"]), result

        task = _ps(client,
                   "Get-ScheduledTask -TaskName 'HuitzilopochtliAgent' | "
                   "Select-Object TaskName,State | ConvertTo-Json -Compress")
        assert task["exitcode"] == 0 and "HuitzilopochtliAgent" in task["out"], task
        info = _ps(client,
                   "(Get-ScheduledTaskInfo -TaskName 'HuitzilopochtliAgent')."
                   "LastTaskResult | ConvertTo-Json -Compress")
        # 0 = ran cleanly; 267011 (0x41303) = SCHED_S_TASK_HAS_NOT_RUN. The
        # installer runs the task script directly once for the first report;
        # the registered task itself does not fire until its 5-minute trigger.
        assert info["out"].strip() in ("0", "267011"), info

        sealed = _ps(client,
                     "(Get-Acl 'C:\\ProgramData\\huitzilopochtli')."
                     "AreAccessRulesProtected | ConvertTo-Json -Compress")
        assert sealed["out"].strip() == "true", sealed

        report = ph.sftp_read_bytes(
            client, "C:/ProgramData/huitzilopochtli/report.html").decode("utf-8")
        # No HTTP server in this test: the 8 non-HTTP checks score 80.
        assert "Total: 80" in report, report
        score = _ps(client,
                    "Test-Path 'C:\\ProgramData\\huitzilopochtli\\.score.dat' | "
                    "ConvertTo-Json -Compress")
        assert score["out"].strip() == "true", score
    finally:
        client.close()
