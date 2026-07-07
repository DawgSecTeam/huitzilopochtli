"""Real two-machine verification of the ranked-mode ("online") path: the
engine and the agent on two genuinely separate, freshly-cloned VMs,
crossing a real network boundary (not loopback). See tests/README.md.

This dev machine, the Proxmox host, and its cloned VMs all sit on the same
routable network (confirmed empirically), so this test talks to the
engine-host VM's exposed port directly from the test process for the
admin/health/leaderboard calls, and only uses the QEMU guest agent
(file-write/exec) to push code onto each VM and start each process. See
test_local_honor_distribution.py's module docstring for the same
SELinux/guest-agent scope note (install paths here are under /tmp too).
"""
import base64
import io
import json
import os
import socket
import sys
import tarfile
import time

import pytest
import requests

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

from tests.proxmox import proxmox_helper as ph  # noqa: E402

ENGINE_DIR = "/tmp/huitzilopochtli_engine"
AGENT_DIR = "/tmp/huitzilopochtli_agent"
ADMIN_TOKEN = "proxmox-test-admin-token"
ENGINE_PORT = 8080


@pytest.fixture(scope="module")
def proxmox():
    return ph.get_proxmox_client()


def _build_engine_bundle_tar() -> bytes:
    """Tar up just common/ + engine/ (all engine/server.py needs -- no
    agent/ or authoring/) for pushing onto the engine-host VM."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for pkg in ("common", "engine"):
            tar.add(os.path.join(REPO_ROOT, pkg), arcname=pkg)
    return buf.getvalue()


def _wait_for_http(url: str, timeout_s: float = 60) -> None:
    deadline = time.time() + timeout_s
    last_exc = None
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(2)
    raise TimeoutError(f"{url} did not respond within {timeout_s}s (last error: {last_exc})")


def test_ranked_mode_across_two_real_machines(proxmox, tmp_path):
    # Deliberately DIFFERENT templates for the two roles: cloning the same
    # template twice was found (empirically, see tests/README.md) to yield
    # two VMs with an identical DHCP-assigned IP -- almost certainly the
    # Ubuntu template's /etc/machine-id (and thus DHCP client-id) was never
    # reset before it was converted to a template, so every clone presents
    # the same client-id to the DHCP server regardless of MAC address. Using
    # two different OS templates sidesteps this without touching the shared
    # production template. The engine role needs Ubuntu specifically (it
    # must bind/listen -- confirmed working there; Fedora's guest-agent is
    # SELinux-confined in a way that may block port binding, untested here
    # since the agent role never binds a port, only makes outbound calls).
    engine_vmid = ph.clone_vm(proxmox, int(os.environ["TEST_TEMPLATE_VMID_UBUNTU"]), "engine")
    agent_vmid = ph.clone_vm(proxmox, int(os.environ["TEST_TEMPLATE_VMID_FEDORA"]), "agent")
    try:
        ph.wait_for_agent(proxmox, engine_vmid, timeout_s=180)
        ph.wait_for_agent(proxmox, agent_vmid, timeout_s=180)
        engine_ip = ph.wait_for_ip(proxmox, engine_vmid, timeout_s=60)

        # --- stand up the engine on its own VM ---
        ph.guest_exec(proxmox, engine_vmid, ["mkdir", "-p", ENGINE_DIR])
        ph.guest_file_write(
            proxmox, engine_vmid, f"{ENGINE_DIR}/bundle.tar.gz", _build_engine_bundle_tar()
        )
        untar = ph.guest_exec(
            proxmox, engine_vmid,
            ["tar", "xzf", f"{ENGINE_DIR}/bundle.tar.gz", "-C", ENGINE_DIR],
        )
        assert untar["exitcode"] == 0, untar

        start_cmd = (
            f"cd {ENGINE_DIR} && "
            f"PYTHONPATH={ENGINE_DIR} HUITZILOPOCHTLI_PORT={ENGINE_PORT} "
            f"HUITZILOPOCHTLI_ADMIN_TOKEN={ADMIN_TOKEN} "
            f"nohup python3 -m engine.server > /tmp/engine.log 2>&1 & echo started"
        )
        start_result = ph.guest_exec(proxmox, engine_vmid, ["/bin/sh", "-c", start_cmd])
        assert start_result["exitcode"] == 0, start_result

        engine_base = f"http://{engine_ip}:{ENGINE_PORT}"
        _wait_for_http(f"{engine_base}/health", timeout_s=60)

        # --- compile a ranked-mode scenario against the engine's real IP ---
        sys.path.insert(0, REPO_ROOT)
        from authoring.compile import compile_scenario
        from common.crypto import signing

        banner_path = f"{AGENT_DIR}/banner.txt"
        scenario_yaml = f"""
scenario:
  name: "ProxmoxRankedTest"
  version: 1
  mode: ranked
  engine_url: "{engine_base}"
  hosts: ["localhost"]

checks:
  - id: banner_ok
    type: file_regex
    category: vuln
    display: "Banner present"
    max_points: 10
    collect:
      path: {banner_path}
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

        engine_record = json.load(open(outputs["engine_record"]))
        resp = requests.post(
            f"{engine_base}/admin/scenarios",
            json=engine_record,
            headers={"X-HUITZILOPOCHTLI-Admin-Token": ADMIN_TOKEN},
            timeout=10,
        )
        assert resp.status_code == 200, resp.text

        resp = requests.post(
            f"{engine_base}/admin/tokens",
            json={"scenario_name": "ProxmoxRankedTest", "ttl_s": 3600},
            headers={"X-HUITZILOPOCHTLI-Admin-Token": ADMIN_TOKEN},
            timeout=10,
        )
        assert resp.status_code == 200, resp.text
        enrollment_token = resp.json()["token"]

        # --- stand up the agent on its own, separate VM ---
        import subprocess

        zipapp_path = tmp_path / "agent.pyz"
        subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "packaging", "build_zipapp.py"), str(zipapp_path)],
            cwd=REPO_ROOT, check=True, timeout=60,
        )

        agent_config = {
            "mode": "ranked",
            "manifest_path": f"{AGENT_DIR}/manifest.signed.json",
            "authoring_public_key_path": f"{AGENT_DIR}/authoring_public_key.b64",
            "rubric_path": None,
            "identity_path": f"{AGENT_DIR}/identity.json",
            "report_path": f"{AGENT_DIR}/report.html",
            "checkin_interval_s": 2,
            "enrollment_token": enrollment_token,
        }

        ph.guest_exec(proxmox, agent_vmid, ["mkdir", "-p", AGENT_DIR])
        files = {
            "agent.pyz": zipapp_path.read_bytes(),
            "manifest.signed.json": open(outputs["manifest"], "rb").read(),
            "authoring_public_key.b64": open(outputs["authoring_public_key"], "rb").read(),
            "agent_config.json": json.dumps(agent_config).encode(),
            "banner.txt": b"SECURE_BANNER\n",
        }
        for filename, content in files.items():
            ph.guest_file_write(proxmox, agent_vmid, f"{AGENT_DIR}/{filename}", content)

        agent_start_cmd = (
            f"cd {AGENT_DIR} && "
            f"nohup python3 {AGENT_DIR}/agent.pyz {AGENT_DIR}/agent_config.json "
            f"> /tmp/agent.log 2>&1 & echo started"
        )
        agent_start = ph.guest_exec(proxmox, agent_vmid, ["/bin/sh", "-c", agent_start_cmd])
        assert agent_start["exitcode"] == 0, agent_start

        # Ed25519 sign/verify in this codebase costs ~1.5-2s/call (see
        # tests/README.md) -- budget generously for enroll + a couple of
        # real check-in round trips across a genuine network hop. Poll
        # tolerantly: a transient connection hiccup mid-wait should retry,
        # not blow up the whole test (this crashed a prior run outright).
        deadline = time.time() + 90
        leaderboard_rows = []
        while time.time() < deadline:
            try:
                resp = requests.get(
                    f"{engine_base}/leaderboard", params={"scenario": "ProxmoxRankedTest"}, timeout=5
                )
                if resp.status_code == 200:
                    leaderboard_rows = resp.json()
                    if leaderboard_rows and leaderboard_rows[0]["total"] == 10:
                        break
            except requests.exceptions.RequestException:
                pass
            time.sleep(3)

        if not leaderboard_rows or leaderboard_rows[0]["total"] != 10:
            engine_log = ph.guest_file_read(proxmox, engine_vmid, "/tmp/engine.log").decode(errors="replace")
            agent_log = ph.guest_file_read(proxmox, agent_vmid, "/tmp/agent.log").decode(errors="replace")
            pytest.fail(
                f"leaderboard did not show total=10 within the deadline; "
                f"leaderboard_rows={leaderboard_rows}\n"
                f"--- engine.log ---\n{engine_log}\n--- agent.log ---\n{agent_log}"
            )

        # Pull the engine's own log for a sanity check that this really was
        # a distinct box, not a fluke from stale state.
        log_bytes = ph.guest_file_read(proxmox, engine_vmid, "/tmp/engine.log")
        assert "Traceback" not in log_bytes.decode("utf-8", errors="replace")
    finally:
        ph.destroy_vm(proxmox, agent_vmid)
        ph.destroy_vm(proxmox, engine_vmid)
