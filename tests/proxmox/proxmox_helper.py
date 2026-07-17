"""Shared helper for the tests/proxmox/ tier. See tests/README.md for the
setup this tier needs before it can run.

Not a copy of, or import from, workshop-vm-distribution -- that's a separate,
unrelated repo/tool. This reads its own local .env (gitignored, loaded by
tests/proxmox/conftest.py) with the same credential shape, so the two
projects stay fully decoupled.

All VM interaction goes through the QEMU guest agent API (file-write,
file-read, exec) rather than SSH -- no login credentials needed, and it
works identically across Ubuntu/Fedora/Alpine as long as qemu-guest-agent
is installed (already required by workshop-vm-distribution's own template
convention).
"""
import base64
import os
import time
import uuid

REQUIRED_ENV_VARS = (
    "PROXMOX_URL",
    "PROXMOX_USER",
    "PROXMOX_TOKEN_NAME",
    "PROXMOX_TOKEN_SECRET",
    "PROXMOX_NODE",
)

# Mirrors workshop-vm-distribution's own "workshop-" safety prefix so
# cleanup here can never touch an unrelated VM.
TEST_VM_PREFIX = "dawgtest-"


def proxmox_env_available() -> bool:
    """True if every required credential env var is set. Tests should
    pytest.skip(...) rather than fail when this is False, so the fast
    tiers stay green without this tier being configured."""
    return all(os.environ.get(key) for key in REQUIRED_ENV_VARS)


def get_proxmox_client():
    """Returns a proxmoxer.ProxmoxAPI client built from the env vars above."""
    if not proxmox_env_available():
        raise RuntimeError(
            "Proxmox credentials not configured; see tests/README.md's "
            "'tests/proxmox/ -- opt-in, live infrastructure required' "
            "section for the exact env vars needed."
        )
    from proxmoxer import ProxmoxAPI

    url = os.environ["PROXMOX_URL"]
    scheme = "https"
    if url.startswith("http://"):
        scheme = "http"
        url = url[len("http://"):]
    elif url.startswith("https://"):
        url = url[len("https://"):]

    proxmox = ProxmoxAPI(
        url,
        user=os.environ["PROXMOX_USER"],
        token_name=os.environ["PROXMOX_TOKEN_NAME"],
        token_value=os.environ["PROXMOX_TOKEN_SECRET"],
        verify_ssl=False,
    )
    if scheme == "http":
        proxmox._store["base_url"] = proxmox._store["base_url"].replace(
            "https://", "http://", 1
        )
    return proxmox


def node():
    return os.environ["PROXMOX_NODE"]


def _wait_for_task(proxmox, upid: str, timeout_s: float = 120) -> None:
    """Proxmox API calls that create/modify VMs (clone, start, ...) return a
    task UPID immediately and run asynchronously -- polling this is required
    before treating the operation as done. Without it, clone_vm() previously
    raced ahead to start/configure a VM whose clone task hadn't actually
    finished yet (confirmed empirically: config.get() came back with net0
    entirely absent because the clone was still in progress)."""
    n = node()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status = proxmox.nodes(n).tasks(upid).status.get()
        if status.get("status") == "stopped":
            if status.get("exitstatus") != "OK":
                raise RuntimeError(f"proxmox task {upid} failed: {status}")
            return
        time.sleep(1)
    raise TimeoutError(f"proxmox task {upid} did not finish within {timeout_s}s")


def clone_vm(proxmox, template_vmid: int, label: str) -> int:
    """Linked-clone `template_vmid`, name it `dawgtest-<label>-<short-uuid>`,
    wait for the (asynchronous) clone task to finish, start it, wait for the
    start task too, and return the new vmid. Caller is responsible for
    teardown via destroy_vm() -- always call it in a finally/fixture-teardown
    block."""
    n = node()
    used_vmids = {vm["vmid"] for vm in proxmox.nodes(n).qemu.get()}
    new_vmid = int(proxmox.cluster.nextid.get())
    while new_vmid in used_vmids:
        new_vmid += 1

    name = f"{TEST_VM_PREFIX}{label}-{uuid.uuid4().hex[:8]}"
    clone_upid = proxmox.nodes(n).qemu(template_vmid).clone.post(
        newid=new_vmid, name=name, full=0
    )
    _wait_for_task(proxmox, clone_upid, timeout_s=180)

    start_upid = proxmox.nodes(n).qemu(new_vmid).status.start.post()
    _wait_for_task(proxmox, start_upid, timeout_s=60)
    return new_vmid


def destroy_vm(proxmox, vmid: int) -> None:
    """Best-effort teardown: stop then delete. Never raises -- called from
    finally blocks where the VM may already be in a weird state."""
    n = node()
    try:
        proxmox.nodes(n).qemu(vmid).status.stop.post()
    except Exception:
        pass
    for _ in range(30):
        try:
            status = proxmox.nodes(n).qemu(vmid).status.current.get()
            if status.get("status") == "stopped":
                break
        except Exception:
            break
        time.sleep(1)
    try:
        proxmox.nodes(n).qemu(vmid).delete()
    except Exception:
        pass


def wait_for_agent(proxmox, vmid: int, timeout_s: float = 120) -> None:
    """Poll the guest agent until it responds to a ping."""
    n = node()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            proxmox.nodes(n).qemu(vmid).agent.post("ping")
            return
        except Exception:
            time.sleep(3)
    raise TimeoutError(f"guest agent on vmid={vmid} did not respond within {timeout_s}s")


def _with_retry(fn, attempts: int = 3, delay_s: float = 3):
    """The Proxmox API connection in this environment occasionally hits a
    transient read timeout unrelated to the guest/VM state -- retry a
    couple times before giving up."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 -- deliberately broad, network flakiness
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


# Proxmox's agent/file-write API rejects any single call whose (already
# base64-encoded) `content` field exceeds 61440 characters -- confirmed
# empirically (400 "value may only be 61440 characters long") when pushing
# a multi-hundred-KB engine bundle tarball. The endpoint is a one-shot
# open+write+close wrapper with no append/offset parameter, so a payload
# over this limit must be split into raw chunks small enough that each
# base64-encodes under the cap, written to separate temp paths, and
# reassembled with a guest-side `cat` -- there is no way to append via the
# agent API alone.
_FILE_WRITE_MAX_CHUNK_BYTES = 45000


def guest_file_write(proxmox, vmid: int, path: str, content: bytes) -> None:
    n = node()

    def _write_chunk(dest_path: str, chunk: bytes) -> None:
        encoded = base64.b64encode(chunk).decode("ascii")
        _with_retry(lambda: proxmox.nodes(n).qemu(vmid).agent("file-write").post(
            file=dest_path, content=encoded, encode=0
        ))

    if len(content) <= _FILE_WRITE_MAX_CHUNK_BYTES:
        _write_chunk(path, content)
        return

    part_paths = []
    for i in range(0, len(content), _FILE_WRITE_MAX_CHUNK_BYTES):
        part_path = f"{path}.part{len(part_paths)}"
        _write_chunk(part_path, content[i:i + _FILE_WRITE_MAX_CHUNK_BYTES])
        part_paths.append(part_path)

    result = guest_exec(proxmox, vmid, ["sh", "-c", f"cat {' '.join(part_paths)} > {path} && rm -f {' '.join(part_paths)}"])
    if result.get("exitcode") != 0:
        raise RuntimeError(f"failed to reassemble chunked file {path}: {result}")


def guest_file_read(proxmox, vmid: int, path: str) -> bytes:
    """Returns the file's content as bytes.

    Proxmox's agent/file-read API returns `content` as an already-decoded
    string (NOT base64, unlike file-write's `content` input, which we send
    as base64 with encode=0) -- confirmed empirically. Re-encode to bytes
    via UTF-8 with surrogateescape so any non-UTF-8 bytes in the source
    file survive the str round-trip instead of raising or silently
    corrupting data.
    """
    n = node()
    result = _with_retry(lambda: proxmox.nodes(n).qemu(vmid).agent("file-read").get(file=path))
    return result["content"].encode("utf-8", errors="surrogateescape")


def wait_for_ip(proxmox, vmid: int, timeout_s: float = 120) -> str:
    """Poll the guest agent's network-get-interfaces until a real, routable
    IPv4 address is found (mirrors workshop-vm-distribution's own
    get_vm_ip logic -- independently implemented here, not imported)."""
    n = node()
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            interfaces = proxmox.nodes(n).qemu(vmid).agent.get("network-get-interfaces")
            for iface in interfaces.get("result", []):
                if iface["name"] in ("lo", "docker0"):
                    continue
                for ip_info in iface.get("ip-addresses", []):
                    if ip_info["ip-address-type"] == "ipv4":
                        ip = ip_info["ip-address"]
                        if ip.startswith("127.") or ip.startswith("169.254") or ip.startswith("172.17"):
                            continue
                        return ip
        except Exception:
            pass
        time.sleep(3)
    raise TimeoutError(f"no routable IPv4 found for vmid={vmid} within {timeout_s}s")


def guest_exec(proxmox, vmid: int, command: list, timeout_s: float = 60) -> dict:
    """Run `command` (argv list) inside the guest via the guest agent, poll
    for completion, and return {"exitcode": int, "out-data": str,
    "err-data": str}. Raises TimeoutError if it doesn't finish in time."""
    n = node()
    result = _with_retry(lambda: proxmox.nodes(n).qemu(vmid).agent("exec").post(command=command))
    pid = result["pid"]

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status = _with_retry(
            lambda: proxmox.nodes(n).qemu(vmid).agent("exec-status").get(pid=pid)
        )
        if status.get("exited"):
            return status
        time.sleep(2)
    raise TimeoutError(f"guest-exec pid={pid} on vmid={vmid} did not finish within {timeout_s}s")
