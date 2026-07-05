"""Real-VM verification of the local (honor-mode) distribution path: the
actual packaged .pyz, run by a real python3 interpreter, on a genuinely
separate, freshly-cloned Ubuntu and Fedora VM. See tests/README.md.

SCOPE NOTE (read before extending this file): the qemu-guest-agent process
on these templates runs as root but is SELinux-confined to the
`virt_qemu_ga_t` domain, which is only permitted to write `tmp_t`-labeled
paths. Writing to /opt (usr_t) or /etc/systemd/system fails with a generic
500 from the guest-agent file-write API even as root -- confirmed via `id`
(uid=0) and `ls -Z` showing the DAC bits would otherwise allow it. Because
of this, this test installs to /tmp/dawgscore instead of the production
/opt/dawgscore path (packaging/README.md), and runs the agent directly via
guest-exec rather than registering the real systemd unit. This still
exercises the thing process-level testing on the dev machine cannot: a
real .pyz executed by a real system python3 on a genuinely separate,
freshly-provisioned host. Getting full systemd-unit-registration coverage
would require adjusting the shared template's SELinux policy (e.g. an
`semanage fcontext` rule for /opt/dawgscore), which is a real change to
shared infrastructure and out of scope here -- flag to the user if that
level of fidelity is wanted later.

Alpine is skipped for now per explicit instruction.
"""
import json
import os
import subprocess
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

from tests.proxmox import proxmox_helper as ph  # noqa: E402

INSTALL_DIR = "/tmp/dawgscore"


@pytest.fixture(scope="module")
def proxmox():
    return ph.get_proxmox_client()


def _build_artifacts(tmp_path):
    """Compile a trivial honor-mode scenario + build the zipapp, all on the
    host (this dev machine) -- only the resulting bytes get pushed to the VM.
    Returns a dict of {vm_filename: bytes} plus the expected total score."""
    sys.path.insert(0, REPO_ROOT)
    from authoring.compile import compile_scenario
    from common.crypto import signing

    banner_vm_path = f"{INSTALL_DIR}/banner.txt"
    scenario_yaml = f"""
scenario:
  name: "ProxmoxHonorTest"
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
    return files, 10


@pytest.mark.parametrize(
    "label,template_env_var",
    [
        ("ubuntu", "TEST_TEMPLATE_VMID_UBUNTU"),
        ("fedora", "TEST_TEMPLATE_VMID_FEDORA"),
    ],
)
def test_honor_mode_runs_on_real_vm(proxmox, tmp_path, label, template_env_var):
    template_vmid = int(os.environ[template_env_var])
    files, expected_total = _build_artifacts(tmp_path)

    vmid = ph.clone_vm(proxmox, template_vmid, label)
    try:
        ph.wait_for_agent(proxmox, vmid, timeout_s=180)

        # Confirm python3 is present without any special provisioning step
        # (both Ubuntu 24.04 and Fedora ship it by default -- this is
        # exactly the Alpine caveat packaging/README.md documents, which is
        # why Alpine needs `apk add python3` and these two don't).
        py_check = ph.guest_exec(proxmox, vmid, ["python3", "--version"])
        assert py_check["exitcode"] == 0, py_check

        ph.guest_exec(proxmox, vmid, ["mkdir", "-p", INSTALL_DIR])
        for filename, content in files.items():
            ph.guest_file_write(proxmox, vmid, f"{INSTALL_DIR}/{filename}", content)

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
        assert f"Total: {expected_total}" in report_html, report_html[:2000]
    finally:
        ph.destroy_vm(proxmox, vmid)
