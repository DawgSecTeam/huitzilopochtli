"""SshProvider: reach a box that is already running over SSH (paramiko).

v1 concrete provider. cfg = {"host","port"?,"user","password"}. The box must
already be booted and network-reachable; this provider does not create VMs.

export() cannot self-export a remote box it doesn't own, so it returns
mode="manual" with hypervisor-agnostic instructions. A future qemu/proxmox
provider will produce a real image.
"""
import os
import shlex
import sys
from typing import Optional

from boxbuilder.artifacts import INSTALL_DIR  # noqa: F401 — re-exported for callers
from boxbuilder.providers.base import (
    BoxHandle, BoxProvider, ExportResult, RunResult, register_provider,
)

# packaging/ lives at <repo_root>/packaging/; we reference its init templates.
_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
_PACKAGING = os.path.join(_REPO_ROOT, "packaging")


class SshProviderError(RuntimeError):
    """Raised when an SSH/SFTP operation against the box fails."""


@register_provider
class SshProvider(BoxProvider):
    name = "ssh"

    def start(self, cfg: dict) -> "SshHandle":
        for key in ("host", "user", "password"):
            if not cfg.get(key):
                raise ValueError(f"ssh provider requires '{key}'")
        return SshHandle(
            name=cfg.get("name", "box"),
            addr=cfg["host"],
            user=cfg["user"],
            password=cfg["password"],
            port=int(cfg.get("port", 22)),
            known_hosts=cfg.get("known_hosts"),
        ).connect()


def _host_key_policy(client, known_hosts, addr, port):
    """Pin host keys when a known_hosts file is available; otherwise fail
    closed-ish with a loud warning about AutoAddPolicy (a silent trust-on-
    first-use would let a MITM intercept the plaintext box password)."""
    import paramiko

    if known_hosts:
        client.load_host_keys(known_hosts)  # explicit pins take precedence
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return
    env_kh = os.environ.get("HUITZILOPOCHTLI_KNOWN_HOSTS")
    if env_kh and os.path.isfile(env_kh):
        client.load_host_keys(env_kh)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return
    print(
        f"WARNING: ssh provider trusting ANY host key for {addr}:{port} "
        f"(AutoAddPolicy) while sending a plaintext password. Pass "
        f"provider.known_hosts (or set HUITZILOPOCHTLI_KNOWN_HOSTS) to pin "
        f"the host key.",
        file=sys.stderr,
    )
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


class SshHandle(BoxHandle):
    """A live SSH connection to a box (paramiko)."""

    def __init__(self, name: str, addr: str, user: str, password: str, port: int = 22,
                 known_hosts: Optional[str] = None):
        self.name = name
        self.addr = addr
        self.user = user
        self.password = password
        self.port = port
        self.known_hosts = known_hosts
        self._client = None  # paramiko.SSHClient, lazily connected

    def connect(self) -> "SshHandle":
        try:
            import paramiko  # imported lazily so boxbuilder imports without [deploy]
        except ImportError as e:
            raise RuntimeError(
                "ssh provider requires paramiko; install with nakon[deploy] or pip install paramiko"
            ) from e

        client = paramiko.SSHClient()
        _host_key_policy(client, self.known_hosts, self.addr, self.port)
        # password auth, as nakon uses (config.json carries plaintext creds).
        try:
            client.connect(
                self.addr, port=self.port, username=self.user, password=self.password,
                timeout=30, allow_agent=False, look_for_keys=False,
            )
        except Exception as e:
            raise SshProviderError(
                f"could not SSH to {self.user}@{self.addr}:{self.port}: {e}"
            ) from e
        self._client = client

        # Reachability + python3 presence. Alpine ships without python3; install
        # it so the agent.pyz can run (see packaging/README.md, "Alpine" note).
        py = self.run("command -v python3 >/dev/null 2>&1 && echo ok", sudo=False)
        if not py.ok or "ok" not in py.stdout:
            # Try to install (apt or apk); ignore failures -- surface a clear
            # error when the agent install step actually needs it.
            self.run(
                "(apt-get update -qq && apt-get install -y -qq python3) 2>/dev/null "
                "|| apk add --no-cache python3 2>/dev/null || true",
                sudo=True, timeout=120,
            )
            py = self.run("command -v python3 >/dev/null 2>&1 && echo ok", sudo=False)
            if not py.ok or "ok" not in py.stdout:
                raise RuntimeError(
                    f"python3 is not present on {self.addr} and could not be installed; "
                    "the huitzilopochtli agent.pyz requires it"
                )
        return self

    # --- BoxHandle API ---------------------------------------------------
    def run(self, cmd: str, *, timeout: int = 1800, sudo: bool = True) -> RunResult:
        if self._client is None:
            raise SshProviderError("SSH connection is not open; call connect() first")
        # Use /bin/sh (POSIX), NOT bash: minimal Alpine ships only busybox /bin/sh,
        # and the openrc init script targets exactly those boxes. Every command we
        # issue here is POSIX; shlex.quote() emits POSIX-safe quoting.
        if sudo and self.user != "root":
            # Feed the password to sudo -S over stdin (paramiko exec can write
            # to the channel stdin). Avoids tty allocation needed for -S.
            full = f"sudo -S -p '' /bin/sh -c {shlex.quote(cmd)}"
            stdin, stdout, stderr = self._client.exec_command(full, timeout=timeout)
            stdin.write(self.password + "\n")
            stdin.flush()
            # Close the write side so the remote shell sees EOF on stdin.
            # Without this, a command that reads stdin (a prompt, a here-doc)
            # blocks forever and recv_exit_status() below never returns.
            stdin.channel.shutdown_write()
        else:
            full = f"/bin/sh -c {shlex.quote(cmd)}"
            stdin, stdout, stderr = self._client.exec_command(full, timeout=timeout)
            # Same latent hang applies to non-sudo commands that read stdin.
            stdin.channel.shutdown_write()
        try:
            # recv_exit_status() waits on a channel event that the timeout
            # given to exec_command does NOT bound; if the channel dies
            # without delivering a status it would block forever. A watchdog
            # thread bounds it (daemon: never blocks interpreter exit).
            import threading
            status = {}
            watcher = threading.Thread(
                target=lambda: status.__setitem__(
                    "exit", stdout.channel.recv_exit_status()
                ),
                daemon=True,
            )
            watcher.start()
            watcher.join(timeout)
            if watcher.is_alive():
                raise SshProviderError(
                    f"command on {self.addr} produced no exit status within "
                    f"{timeout}s: {cmd!r}"
                )
            exit_status = status["exit"]
        except SshProviderError:
            raise
        except Exception as e:
            raise SshProviderError(
                f"command failed on {self.addr} (channel error): {cmd!r}: {e}"
            ) from e
        return RunResult(
            exit_status=exit_status,
            stdout=stdout.read().decode("utf-8", "replace"),
            stderr=stderr.read().decode("utf-8", "replace"),
        )

    def put(self, local: str, remote: str, mode: Optional[int] = None) -> None:
        if self._client is None:
            raise SshProviderError("SSH connection is not open; call connect() first")
        try:
            sftp = self._client.open_sftp()
        except Exception as e:
            raise SshProviderError(
                f"could not open SFTP to {self.addr}: {e}"
            ) from e
        try:
            sftp.put(local, remote)
            if mode is not None:
                sftp.chmod(remote, mode)
        except Exception as e:
            raise SshProviderError(
                f"failed to place {local} -> {self.addr}:{remote}: {e}"
            ) from e
        finally:
            sftp.close()

    def install_init(self, kind: str, mode: str = "honor") -> None:
        if kind == "none":
            return
        # Ensure the install dir exists, then copy + enable the unit. We SFTP the
        # template up and let the box's own init system install it, per
        # the templates in packaging/.)
        # The target dirs (/etc/systemd/system, /etc/init.d) are root-owned, so a
        # non-root SSH user cannot SFTP into them. Stage the unit under /tmp (any
        # user can write there), then sudo-install it into place.
        if kind == "systemd":
            local = os.path.join(_PACKAGING, "huitzilopochtli-agent.service")
            tmp = "/tmp/huitzilopochtli-agent.service"
            self.put(local, tmp)
            res = self.run(
                f"install -m 644 {tmp} /etc/systemd/system/huitzilopochtli-agent.service && "
                "systemctl daemon-reload && "
                "systemctl enable --now huitzilopochtli-agent.service"
            )
            if not res.ok:
                raise RuntimeError(f"failed to enable systemd unit: {res.stderr.strip()}")
            if mode == "honor":
                # Honor mode's agent process runs once and exits (see the
                # unit's own comments); pair it with a timer so the report
                # re-checks periodically instead of staying a single
                # install-time snapshot forever. Ranked mode's agent already
                # loops forever on its own and doesn't need this.
                timer_local = os.path.join(_PACKAGING, "huitzilopochtli-agent.timer")
                timer_tmp = "/tmp/huitzilopochtli-agent.timer"
                self.put(timer_local, timer_tmp)
                res = self.run(
                    f"install -m 644 {timer_tmp} /etc/systemd/system/huitzilopochtli-agent.timer && "
                    "systemctl daemon-reload && "
                    "systemctl enable --now huitzilopochtli-agent.timer"
                )
                if not res.ok:
                    raise RuntimeError(f"failed to enable systemd timer: {res.stderr.strip()}")
        elif kind == "openrc":
            local = os.path.join(_PACKAGING, "huitzilopochtli-agent.openrc")
            tmp = "/tmp/huitzilopochtli-agent"
            self.put(local, tmp)
            res = self.run(
                f"install -m 755 {tmp} /etc/init.d/huitzilopochtli-agent && "
                "rc-update add huitzilopochtli-agent default && "
                "rc-service huitzilopochtli-agent start"
            )
            if not res.ok:
                raise RuntimeError(f"failed to enable openrc service: {res.stderr.strip()}")
        else:
            raise ValueError(f"unknown init kind {kind!r}; want systemd|openrc|none")

    def export(self, out_path: str, fmt: str = "ova") -> ExportResult:
        # A remote box over SSH can't snapshot itself; the operator must export
        # from the hypervisor that owns its disk. Be explicit about that.
        return ExportResult(
            mode="manual",
            instructions=(
                f"The ssh provider cannot self-export {self.addr}. From the box's "
                f"hypervisor, shut it down and export the disk as .{fmt} "
                f"(e.g. `qm template`/`qemu-img convert` for Proxmox/qemu, "
                f"`VBoxManage export` for VirtualBox). A future qemu/proxmox "
                f"provider will automate this."
            ),
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def detect_init(handle: SshHandle) -> str:
    """Best-effort init-system detection: 'systemd' | 'openrc' | 'none'."""
    if handle.run("command -v systemctl >/dev/null 2>&1", sudo=False).ok:
        return "systemd"
    if handle.run("command -v rc-service >/dev/null 2>&1", sudo=False).ok:
        return "openrc"
    return "none"
