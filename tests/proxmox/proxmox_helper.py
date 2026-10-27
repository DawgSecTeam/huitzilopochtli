"""Shared helper for the tests/proxmox/ tier. See tests/README.md for the
setup this tier needs before it can run.

Not a copy of, or import from, workshop-vm-distribution -- that's a separate,
unrelated repo/tool. This reads its own local .env (gitignored, loaded by
tests/proxmox/conftest.py) with the same credential shape, so the two
projects stay fully decoupled.

Most VM interaction goes through the QEMU guest agent API (file-write,
file-read, exec) rather than SSH -- no login credentials needed, and it
works identically across Ubuntu/Fedora/Alpine as long as qemu-guest-agent
is installed (already required by workshop-vm-distribution's own template
convention).

Two live-test paths need SSH instead:
  * Fedora's guest agent runs SELinux-confined to `virt_qemu_ga_t`, which
    denies outbound `connect()` (and even reads of some system files), so an
    agent spawned through guest-exec cannot exercise http_uptime/db_query or
    the package check. A root SSH session is unconfined and is how the agent
    runs on a real box.
  * Windows guests need Python and an SSH login for the boxbuilder/agent
    install, and the guest-agent file-write path cannot reassemble the
    ~270KB agent.pyz (its chunked write shells out to /bin/sh).
"""
import base64
import os
import shlex
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
        # The API occasionally drops a connection mid-task-poll; retry the
        # transport, not the operation.
        status = _retry_transport(
            lambda: proxmox.nodes(n).tasks(upid).status.get())
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
    used_vmids = {vm["vmid"] for vm in _retry_transport(
        lambda: proxmox.nodes(n).qemu.get())}
    new_vmid = int(_retry_transport(lambda: proxmox.cluster.nextid.get()))
    while new_vmid in used_vmids:
        new_vmid += 1

    name = f"{TEST_VM_PREFIX}{label}-{uuid.uuid4().hex[:8]}"
    clone_upid = _retry_transport(
        lambda: proxmox.nodes(n).qemu(template_vmid).clone.post(
            newid=new_vmid, name=name, full=0))
    _wait_for_task(proxmox, clone_upid, timeout_s=180)

    start_upid = _retry_transport(
        lambda: proxmox.nodes(n).qemu(new_vmid).status.start.post())
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


def regen_machine_id(proxmox, vmid: int, timeout_s: float = 180) -> None:
    """Give a clone its own /etc/machine-id, then reboot so DHCP leases a
    distinct IP. A template sealed without wiping machine-id hands every
    clone the same DHCP client id, so two clones -- or a clone and any other
    live clone of that template -- collide on one IP."""
    guest_exec(proxmox, vmid, ["/bin/sh", "-c",
                               "rm -f /etc/machine-id /var/lib/dbus/machine-id"
                               " && systemd-machine-id-setup"])
    try:
        proxmox.nodes(node()).qemu(vmid).status.reboot.post()
    except Exception:
        pass
    time.sleep(10)
    wait_for_agent(proxmox, vmid, timeout_s=timeout_s)


def _retry_transport(fn, attempts: int = 3, delay_s: float = 3):
    """The Proxmox API connection in this environment occasionally hits a
    transient read timeout unrelated to the guest/VM state -- retry a couple
    times before giving up.

    Transport-level failures ONLY. Guest-agent errors arrive as HTTP error
    statuses (proxmoxer ResourceException) and are usually DETERMINISTIC --
    exec on a broken agent fails identically every attempt -- so blind
    retries just multiply failed spawns. That multiplication is the "exec
    storm" after which the Windows qga process wedges until a full VM
    reboot; never retry an answer the API actually gave us."""
    import requests

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as exc:
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
        _retry_transport(lambda: proxmox.nodes(n).qemu(vmid).agent("file-write").post(
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
    result = _retry_transport(lambda: proxmox.nodes(n).qemu(vmid).agent("file-read").get(file=path))
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


def wait_for_tcp(host: str, port: int = 22, timeout_s: float = 120) -> None:
    """Poll a TCP port without authenticating (no SSH penalty risk)."""
    import socket

    deadline = time.time() + timeout_s
    last_exc = None
    while time.time() < deadline:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
            return
        except OSError as exc:
            last_exc = exc
            time.sleep(2)
    raise TimeoutError(f"TCP {host}:{port} not listening within {timeout_s}s: {last_exc}")


def vm_name(proxmox, vmid: int) -> str:
    return proxmox.nodes(node()).qemu(vmid).config.get().get("name") or ""


def guest_exec(proxmox, vmid: int, command: list, timeout_s: float = 60) -> dict:
    """Run `command` (argv list) inside the guest via the guest agent, poll
    for completion, and return {"exitcode": int, "out-data": str,
    "err-data": str}. Raises TimeoutError if it doesn't finish in time."""
    n = node()
    # _retry_transport, NOT a blind retry: a failing agent fails every
    # attempt identically, and retrying exec triples the failed-spawn load
    # that historically wedged qga (see _retry_transport docstring).
    result = _retry_transport(lambda: proxmox.nodes(n).qemu(vmid).agent("exec").post(command=command))
    pid = result["pid"]

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status = _retry_transport(
            lambda: proxmox.nodes(n).qemu(vmid).agent("exec-status").get(pid=pid)
        )
        if status.get("exited"):
            return status
        time.sleep(2)
    raise TimeoutError(f"guest-exec pid={pid} on vmid={vmid} did not finish within {timeout_s}s")


# --- SSH transport (Fedora + Windows live tests) -----------------------------
#
# The guest-agent channel is ideal for throwaway Linux probes, but two live
# paths genuinely need a real SSH session:
#   * Fedora's qemu-ga is SELinux-confined to virt_qemu_ga_t and cannot make
#     outbound connections or read some system files, so an agent spawned via
#     guest-exec scores http_uptime/db_query/package as zero. SSH sessions are
#     unconfined_t, exactly like the systemd service on a real box.
#   * Windows needs Python (installed at test time) and SFTP for files larger
#     than the guest-agent write cap.
# Both helpers below bootstrap SSH on a disposable clone; they never touch a
# template.

# Live-test password for throwaway clones. Set $TEST_VM_PASSWORD in
# tests/proxmox/.env (gitignored); nothing real is committed here.
TEST_VM_PASSWORD = os.environ.get("TEST_VM_PASSWORD", "")


def _agent_set_password(proxmox, vmid: int, username: str,
                        password: str = TEST_VM_PASSWORD) -> None:
    """Set a guest account's password through qemu-ga (works even when
    /etc/shadow is unreadable from the confined virt_qemu_ga_t domain)."""
    n = node()
    _retry_transport(lambda: proxmox.nodes(n).qemu(vmid).agent(
        "set-user-password").post(username=username, password=password,
                                  crypted=0))


def generate_ssh_key(path: str) -> str:
    """Write an ephemeral Ed25519 keypair to `path` (+ `.pub`); return the
    public-key line. Uses cryptography (a paramiko dependency) so the proxmox
    tier does not depend on an ssh-keygen binary."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    with open(path, "wb") as f:
        f.write(private)
    os.chmod(path, 0o600)
    line = public.decode("ascii") + " dawgtest\n"
    with open(path + ".pub", "w", encoding="ascii") as f:
        f.write(line)
    return line.strip()


def ssh_connect(host: str, username: str, password: str = None,
                key_path: str = None, timeout_s: float = 180, port: int = 22):
    """Connect (bounded retries; Windows/Fedora SSH resets while sshd and the
    user database settle). Returns a live paramiko.SSHClient."""
    import paramiko

    deadline = time.time() + timeout_s
    last_exc = None
    while time.time() < deadline:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {}
        if key_path:
            kwargs["key_filename"] = key_path
        elif password is not None:
            kwargs["password"] = password
        try:
            client.connect(
                host, port=port, username=username, timeout=10,
                banner_timeout=20, auth_timeout=20, allow_agent=False,
                look_for_keys=False, **kwargs,
            )
            return client
        except Exception as exc:  # auth/reset races during boot
            last_exc = exc
            try:
                client.close()
            except Exception:
                pass
            time.sleep(3)
    raise TimeoutError(f"SSH to {host}:{port} as {username} failed within "
                       f"{timeout_s}s: {last_exc}")


def ssh_exec(client, command: str, timeout_s: float = 120) -> dict:
    """Run a shell command over an established SSH session. Returns
    {"exitcode", "out", "err"} with text decoded leniently."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout_s)
    try:
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
    finally:
        try:
            stdin.close()
        except Exception:
            pass
    return {"exitcode": rc, "out": out, "err": err}


def sftp_put_bytes(client, remote_path: str, content: bytes, mode: int = None) -> None:
    sftp = client.open_sftp()
    try:
        with sftp.file(remote_path, "wb") as f:
            f.write(content)
        if mode is not None:
            sftp.chmod(remote_path, mode)
    finally:
        sftp.close()


def sftp_read_bytes(client, remote_path: str) -> bytes:
    sftp = client.open_sftp()
    try:
        with sftp.file(remote_path, "rb") as f:
            return f.read()
    finally:
        sftp.close()


def enable_root_ssh(proxmox, vmid: int, host: str, key_path: str,
                    login_user: str = "fedora",
                    password: str = TEST_VM_PASSWORD,
                    timeout_s: float = 120,
                    expected_hostname: str = None):
    """Give a Fedora/Ubuntu clone a root SSH key.

    Sets passwords through qemu-ga, logs in as the cloud user, then uses a PTY
    `su` (password on the tty) to append the ephemeral public key to
    /root/.ssh/authorized_keys. Returns a root SSHClient authenticated by the
    key. Root login itself is `prohibit-password` on both templates, which is
    exactly public-key-only -- no sshd_config rewrite needed.
    """
    pub = open(key_path + ".pub", encoding="ascii").read().strip()

    # A freshly-cloned Fedora box can still be finishing cloud-init: it may
    # (re)create the cloud user and lock its password seconds after the guest
    # agent answers. Wait for sshd at the TCP layer first (that is not an auth
    # failure, so it cannot trip OpenSSH 10's PerSourcePenalties), then set the
    # password and try a small number of logins with generous gaps. Repeating
    # password failures quickly is what turns a transient race into a
    # source-IP block.
    wait_for_tcp(host, 22, timeout_s=min(timeout_s, 180))
    time.sleep(10)
    user_client = None
    last_exc = None
    for attempt in range(3):
        _agent_set_password(proxmox, vmid, login_user, password)
        _agent_set_password(proxmox, vmid, "root", password)
        try:
            user_client = ssh_connect(host, login_user, password=password,
                                      timeout_s=12)
            break
        except TimeoutError as exc:
            last_exc = exc
            time.sleep(30)
    if user_client is None:
        raise last_exc
    if expected_hostname:
        got = ssh_exec(user_client, "hostname", timeout_s=15)["out"].strip()
        if got != expected_hostname:
            raise RuntimeError(
                f"SSH at {host} answered as {got!r}, expected "
                f"{expected_hostname!r} -- another guest is using the same "
                f"DHCP address (clone IP collision)")
    try:
        inner = (
            "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
            "touch /root/.ssh/authorized_keys && "
            f"grep -qF {shlex.quote(pub)} /root/.ssh/authorized_keys 2>/dev/null || "
            f"printf '%s\\n' {shlex.quote(pub)} >> /root/.ssh/authorized_keys; "
            "chmod 600 /root/.ssh/authorized_keys; "
            "restorecon -R /root/.ssh 2>/dev/null; "
            "echo __DAWG_ROOT_READY_$(id -u)__"
        )
        command = f"su -c {shlex.quote(inner)} root\n"
        chan = user_client.invoke_shell(width=200, height=50)
        try:
            chan.settimeout(5)
            time.sleep(0.5)
            chan.send(command)
            buf = ""
            deadline = time.time() + 15
            while "Password:" not in buf and time.time() < deadline:
                try:
                    buf += chan.recv(65535).decode("utf-8", errors="replace")
                except Exception:
                    pass
            chan.send(password + "\n")
            # The marker must be produced by the root shell, not merely
            # echoed back with the command line: `$(id -u)` expands to 0 only
            # inside the su session, and the literal echo text never contains
            # "__DAWG_ROOT_READY_0__". (The old plain marker matched the PTY
            # echo immediately, so we closed the channel and killed su before
            # it wrote authorized_keys.)
            deadline = time.time() + 30
            while "__DAWG_ROOT_READY_0__" not in buf and time.time() < deadline:
                try:
                    buf += chan.recv(65535).decode("utf-8", errors="replace")
                except Exception:
                    pass
            if "__DAWG_ROOT_READY_0__" not in buf:
                raise RuntimeError(f"could not install root SSH key via su: {buf[-1500:]!r}")
        finally:
            chan.close()
    finally:
        user_client.close()

    # cloud-init can lock the root account again after the su above; key auth
    # is refused while the account is locked (even with PermitRootLogin
    # prohibit-password). Re-assert the password and retry the key login.
    last_exc = None
    for attempt in range(3):
        _agent_set_password(proxmox, vmid, "root", password)
        try:
            return ssh_connect(host, "root", key_path=key_path,
                               timeout_s=12)
        except TimeoutError as exc:
            last_exc = exc
            time.sleep(30)
    raise last_exc


def _windows_reboot_and_wait(proxmox, vmid: int, timeout_s: float = 600) -> None:
    """Hard-cycle a Windows clone and wait for qemu-ga to answer again.

    ACPI reboot through the API is unreliable once qemu-ga has died (the
    guest can ignore it and never bring the agent back); stop/start is the
    documented recovery and works regardless of guest responsiveness.
    """
    n = node()
    try:
        proxmox.nodes(n).qemu(vmid).status.stop.post()
    except Exception:
        pass
    for _ in range(90):
        try:
            state = proxmox.nodes(n).qemu(vmid).status.current.get().get("status")
        except Exception:
            state = None
        if state == "stopped":
            break
        time.sleep(2)
    time.sleep(3)
    try:
        proxmox.nodes(n).qemu(vmid).status.start.post()
    except Exception:
        pass
    time.sleep(10)
    wait_for_agent(proxmox, vmid, timeout_s=timeout_s)


def _windows_recover_agent(proxmox, vmid: int, timeout_s: float = 600) -> None:
    """Wait for qemu-ga, rebooting the Windows guest if it stays dead.

    The Windows image's qemu-ga sometimes exits under load (the standalone
    installer is the usual trigger); a full reboot is the documented
    recovery, and Windows clones lose nothing from it.
    """
    try:
        wait_for_agent(proxmox, vmid, timeout_s=120)
        return
    except Exception:
        pass
    _windows_reboot_and_wait(proxmox, vmid, timeout_s=timeout_s)


def windows_guest_exec(proxmox, vmid: int, command: list,
                       timeout_s: float = 120) -> dict:
    """guest_exec with qemu-ga-death recovery (reboot + one retry)."""
    try:
        return guest_exec(proxmox, vmid, command, timeout_s=timeout_s)
    except Exception:
        _windows_recover_agent(proxmox, vmid)
        return guest_exec(proxmox, vmid, command, timeout_s=timeout_s)


def ssh_ps(client, script: str, timeout_s: float = 120) -> dict:
    """Run PowerShell over SSH with -EncodedCommand (cmd.exe-safe)."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return ssh_exec(
        client,
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {encoded}",
        timeout_s=timeout_s,
    )


def _ssh_python_ok(client) -> bool:
    try:
        probe = ssh_exec(client, "cmd /c python --version", timeout_s=20)
        return probe.get("exitcode") == 0
    except Exception:
        return False


def ensure_windows_python(client, timeout_s: float = 900):
    """Install Python 3.12 over SSH if it is absent, and put a `python` shim
    on PATH.

    The download+install runs as a SYSTEM scheduled task, not in the SSH
    channel: a 27MB `Invoke-WebRequest` outlives a command timeout, and
    killing the channel can leave a 0-byte installer (observed). The task
    completes independently; separate SSH polls watch for python.exe.
    """
    if _ssh_python_ok(client):
        return client
    script = r"""
$ErrorActionPreference = 'Stop'
$url = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe'
$out = 'C:\Windows\Temp\dawgtest-python-installer.exe'
Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
Start-Process -FilePath $out -ArgumentList '/quiet','InstallAllUsers=1','PrependPath=1','Include_test=0','TargetDir=C:\Python312' -Wait
"""
    sftp_put_bytes(client, "C:/Windows/Temp/dawgtest-python.ps1", script.encode())
    reg = ssh_ps(client, r"""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\dawgtest-python.ps1'
$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' `
  -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'huitz-livetest-python' -Action $action `
  -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'huitz-livetest-python'
""", timeout_s=60)
    if reg.get("exitcode") != 0:
        raise RuntimeError(f"could not start the Python install task: {reg}")

    deadline = time.time() + timeout_s
    installed = False
    while time.time() < deadline:
        try:
            probe = ssh_exec(
                client,
                "cmd /c if exist C:\\Python312\\python.exe echo YES",
                timeout_s=20,
            )
            if "YES" in probe.get("out", ""):
                installed = True
                break
        except Exception:
            pass
        time.sleep(10)
    if not installed:
        raise RuntimeError(f"Python 3.12 did not install within {timeout_s}s")

    # Let the MSI finish its own registration before touching PATH.
    time.sleep(15)
    shim = r"""
$cmd = "@echo off`r`n`"C:\Python312\python.exe`" %*`r`n"
Set-Content -Path 'C:\Windows\System32\python.cmd' -Value $cmd -Encoding ASCII
$machine = [Environment]::GetEnvironmentVariable('Path','Machine')
if ($machine -notlike '*C:\Python312*') {
  [Environment]::SetEnvironmentVariable('Path', $machine + ';C:\Python312','Machine')
}
"""
    ssh_ps(client, shim, timeout_s=60)
    if not _ssh_python_ok(client):
        raise RuntimeError("python shim installed but 'python --version' still fails")
    return client


def ensure_windows_ssh(proxmox, vmid: int, host: str,
                       user: str = "sysadmin",
                       password: str = TEST_VM_PASSWORD,
                       timeout_s: float = 300):
    """Create the local admin and its sshd firewall rule, then return a live
    SSH session.

    The Windows image ships sshd running, but no admin password and no inbound
    firewall rule. This is deliberately ONE short `cmd /c` command (netsh +
    net user), not a PowerShell script: guest-exec on this image is a
    one-shot and qemu-ga can die after (or while) the spawn, so the command
    must be quick and the success test is "SSH works", not "qemu-ga answered".
    """
    cmd = (
        "netsh advfirewall firewall add rule name=sshdin dir=in action=allow "
        "protocol=TCP localport=22 & "
        f"net user {user} {password} /add & "
        f"net localgroup Administrators {user} /add & "
        f"net user {user} {password} & "
        f"net user {user} /passwordreq:yes"
    )
    for attempt in range(2):
        try:
            # Fire-and-forget: do NOT poll exec-status. On this image the
            # polling loop is what wakes the qga crash; the short netsh/net
            # user command either ran or it did not, and SSH is the judge.
            proxmox.nodes(node()).qemu(vmid).agent("exec").post(
                command=["cmd", "/c", cmd])
        except Exception:
            pass
        time.sleep(5)
        try:
            wait_for_tcp(host, 22, timeout_s=120)
            return ssh_connect(host, user, password=password, timeout_s=180)
        except TimeoutError:
            if attempt == 0:
                _windows_reboot_and_wait(proxmox, vmid)
                try:
                    host = wait_for_ip(proxmox, vmid, timeout_s=180)
                except Exception:
                    pass
    raise TimeoutError(
        f"Windows SSH bootstrap did not come up on vmid={vmid} ({host})")
