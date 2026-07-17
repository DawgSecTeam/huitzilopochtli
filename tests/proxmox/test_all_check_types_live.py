"""Real-VM verification of EVERY check type against genuinely separate,
freshly-cloned Ubuntu and Fedora VMs -- not just file_regex.

test_local_honor_distribution.py proves the .pyz/zipapp distribution path
works end to end, but only exercises one check type (file_regex). The other
six (permission, user_group, service_state, package, http_uptime, db_query)
have never been run against a real OS -- only against mocked
subprocess/filesystem in tests/unit/. This file closes that gap by running
a scenario that hits all seven in a single pass on a real box.

Same SCOPE NOTE as test_local_honor_distribution.py applies: installs to
/tmp/huitzilopochtli (not /opt) and runs the agent directly via guest-exec,
because the guest-agent process is SELinux-confined on the Fedora template
and cannot write usr_t-labeled paths.
"""
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

from tests.proxmox import proxmox_helper as ph  # noqa: E402

INSTALL_DIR = "/tmp/huitzilopochtli_allchecks"
HTTP_PORT = 8765


@pytest.fixture(scope="module")
def proxmox():
    return ph.get_proxmox_client()


def _build_artifacts(tmp_path, cron_service: str, cron_package: str):
    sys.path.insert(0, REPO_ROOT)
    from authoring.compile import compile_scenario
    from common.crypto import signing

    banner_vm_path = f"{INSTALL_DIR}/banner.txt"
    scenario_yaml = f"""
scenario:
  name: "ProxmoxAllChecksTest"
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
      path: {banner_vm_path}
      extract: '(SECURE_BANNER)'
    expect:
      equals: "SECURE_BANNER"
      points: 10

  - id: passwd_perm
    type: permission
    category: vuln
    display: "/etc/passwd is world-readable, not writable"
    max_points: 10
    collect:
      path: /etc/passwd
    expect:
      mode_at_most: true
      field: mode
      max_mode: "0644"
      points: 10

  - id: root_present
    type: user_group
    category: vuln
    display: "root user present"
    max_points: 10
    collect: {{}}
    expect:
      user_present: true
      username: root
      points: 10

  - id: cron_active
    type: service_state
    category: vuln
    display: "cron service active"
    max_points: 10
    collect:
      service: {cron_service}
    expect:
      equals: true
      field: active
      points: 10

  - id: ssh_installed
    type: package
    category: vuln
    display: "openssh-server installed"
    max_points: 10
    collect:
      package: openssh-server
    expect:
      equals: true
      field: installed
      points: 10

  - id: http_up
    type: http_uptime
    category: vuln
    display: "local http server reachable"
    max_points: 10
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
    yaml_path = tmp_path / "scenario.yaml"
    yaml_path.write_text(scenario_yaml)

    kp = signing.keypair()
    out_dir = tmp_path / "compiled"
    out_dir.mkdir()
    outputs = compile_scenario(str(yaml_path), str(out_dir), kp[0])

    zipapp_path = tmp_path / "agent.pyz"
    subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "packaging", "build_zipapp.py"), str(zipapp_path)],
        cwd=REPO_ROOT, check=True, timeout=60,
    )

    config = {
        "mode": "honor",
        "manifest_path": f"{INSTALL_DIR}/manifest.signed.json",
        "authoring_public_key_path": f"{INSTALL_DIR}/authoring_public_key.b64",
        "rubric_path": f"{INSTALL_DIR}/rubric.json",
        "identity_path": None,
        "report_path": f"{INSTALL_DIR}/report.html",
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
    return files


@pytest.mark.parametrize(
    "label,template_env_var,cron_service,cron_package,expected_total",
    [
        # Ubuntu 24.04: all 7 checks pass for real (cron running by default,
        # openssh-server installed, and the guest-agent-spawned agent.pyz
        # process can make outbound connections) -- confirmed empirically,
        # 70/70.
        ("ubuntu", "TEST_TEMPLATE_VMID_UBUNTU", "cron", "cron", 70),
        # Fedora 44: only the first 3 checks (file_regex/permission/user_group,
        # none of which need a subprocess or network) score points here.
        # Confirmed empirically, all three infra-level, not product bugs:
        #  - crond is not active by default on this minimal cloud template
        #    (cron_active correctly collects/scores active=False).
        #  - `rpm` is not on the guest-agent's PATH in this exec context, so
        #    package_installed() correctly falls through to (False, None)
        #    rather than erroring (agent/platform/pkg.py already handles a
        #    missing package-manager binary gracefully).
        #  - http_uptime and db_query both get errno 13 (Permission denied)
        #    on outbound connect() -- the same SELinux `virt_qemu_ga_t`
        #    confinement documented in tests/README.md as blocking
        #    agent.identity.enroll()'s urllib POST in ranked mode, now
        #    confirmed to block ANY outbound connect() from a process the
        #    guest agent spawns, not just that one call site.
        ("fedora", "TEST_TEMPLATE_VMID_FEDORA", "crond", "cronie", 30),
    ],
)
def test_all_check_types_on_real_vm(proxmox, tmp_path, label, template_env_var, cron_service, cron_package, expected_total):
    template_vmid = int(os.environ[template_env_var])
    files = _build_artifacts(tmp_path, cron_service, cron_package)

    vmid = ph.clone_vm(proxmox, template_vmid, f"allchecks-{label}")
    try:
        ph.wait_for_agent(proxmox, vmid, timeout_s=180)

        ph.guest_exec(proxmox, vmid, ["mkdir", "-p", INSTALL_DIR])
        for filename, content in files.items():
            ph.guest_file_write(proxmox, vmid, f"{INSTALL_DIR}/{filename}", content)

        # http_uptime needs something listening on HTTP_PORT before the agent runs.
        serve_cmd = (
            f"cd {INSTALL_DIR} && nohup python3 -m http.server {HTTP_PORT} "
            f"--bind 127.0.0.1 > /tmp/http_server.log 2>&1 & echo started"
        )
        serve_result = ph.guest_exec(proxmox, vmid, ["/bin/sh", "-c", serve_cmd])
        assert serve_result["exitcode"] == 0, serve_result

        run_result = ph.guest_exec(
            proxmox, vmid,
            ["python3", f"{INSTALL_DIR}/agent.pyz", f"{INSTALL_DIR}/agent_config.json"],
            timeout_s=60,
        )
        assert run_result["exitcode"] == 0, (
            f"agent.pyz failed on real {label} VM: {run_result}"
        )

        report_bytes = ph.guest_file_read(proxmox, vmid, f"{INSTALL_DIR}/report.html")
        report_html = report_bytes.decode("utf-8")
        assert f"Total: {expected_total}" in report_html, report_html
    finally:
        ph.destroy_vm(proxmox, vmid)
