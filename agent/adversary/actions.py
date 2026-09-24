"""Closed adversary action vocabulary. See architecture.md §12.2.

No action may open an outbound connection — there is no network-egress
primitive in this module. Do not add a generic "run command" primitive.
"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable

ACTIONS: dict[str, Callable] = {}

#: Directory confining ``drop_inert_artifact`` — resolved paths never escape it.
#: POSIX uses a root-owned dir, not /tmp: in a world-writable parent a local
#: user could pre-create the base (or symlinks inside it) and redirect the
#: root write onto any file. SYSTEM's temp dir on Windows is already private.
_DEFAULT_ARTIFACT_DIR = (
    os.path.join(tempfile.gettempdir(), "huitzilopochtli-adversary")
    if os.name == "nt" else "/var/lib/huitzilopochtli/adversary"
)

#: What a service/unit name may look like. The first character cannot be
#: ``-``, so a params value is never parsed as an option by systemctl /
#: rc-service; ``/``, whitespace, ``$`` etc. are excluded outright. Real
#: names (``nginx.service``, ``php8.2-fpm``, ``openvpn@server``) all pass.
_SERVICE_NAME_RE = re.compile(r"[A-Za-z0-9_.@+][A-Za-z0-9_.@+-]*\Z")


def _artifact_base() -> str:
    return os.environ.get("HUITZILOPOCHTLI_ARTIFACT_DIR", _DEFAULT_ARTIFACT_DIR)


def _resolve_artifact_path(base: str, requested: str):
    """Resolve ``requested`` inside ``base``; return None if it would escape."""
    base_abs = os.path.abspath(base)
    rel = requested.replace("\\", "/").lstrip("/")
    candidate = os.path.abspath(os.path.join(base_abs, rel))
    if candidate != base_abs and not candidate.startswith(base_abs + os.sep):
        return None
    return candidate


def _open_confined_posix(base: str, requested: str):
    """Open ``requested`` for writing inside ``base`` without following any
    symlink; return an fd, or None if the path or the base is unsafe.

    The base must be a real directory owned by us and not group/other-
    writable; each path component is opened relative to its parent with
    O_NOFOLLOW, so a symlink anywhere in the chain fails (ELOOP/ENOTDIR)
    instead of being traversed.
    """
    parts = [p for p in requested.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    os.makedirs(base, mode=0o700, exist_ok=True)
    st = os.lstat(base)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o022):
        return None
    dfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for comp in parts[:-1]:
            try:
                os.mkdir(comp, 0o700, dir_fd=dfd)
            except FileExistsError:
                pass
            nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=dfd)
            os.close(dfd)
            dfd = nfd
        return os.open(parts[-1],
                       os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                       0o644, dir_fd=dfd)
    finally:
        os.close(dfd)


def register(name: str):
    def deco(fn):
        ACTIONS[name] = fn
        return fn
    return deco


@register("flush_firewall")
def _flush_firewall(params: dict, ctx: "agent.platform.base.PlatformContext") -> None:
    """Flush local packet filter rules. Tries iptables then nft; no-op if absent."""
    if shutil.which("iptables"):
        flush_ok = False
        try:
            flush = subprocess.run(["iptables", "-F"], check=False,
                                   capture_output=True, timeout=10)
            flush_ok = flush.returncode == 0
            if flush_ok:
                subprocess.run(["iptables", "-X"], check=False,
                               capture_output=True, timeout=10)
        except Exception:
            flush_ok = False
        if flush_ok:
            return
    if shutil.which("nft"):
        try:
            subprocess.run(["nft", "flush", "ruleset"], check=False,
                            capture_output=True, timeout=10)
        except Exception:
            pass
        return
    # Neither tool present: no-op, not an error.


@register("kill_service")
def _kill_service(params: dict, ctx: "agent.platform.base.PlatformContext") -> None:
    """Stop a named service (adversary is the only writer; see §12)."""
    service = params.get("service")
    if not service:
        return
    if not isinstance(service, str) or not _SERVICE_NAME_RE.fullmatch(service):
        print(
            f"WARNING: refusing kill_service: invalid service name "
            f"{service!r}",
            file=sys.stderr,
        )
        return
    try:
        if os.path.exists("/run/systemd/system"):
            subprocess.run(["systemctl", "stop", service], check=False,
                            capture_output=True, timeout=15)
        else:
            subprocess.run(["rc-service", service, "stop"], check=False,
                            capture_output=True, timeout=15)
    except Exception:
        # Ignore failures: a failed kill just means the box is more secure
        # than expected, not an executor error.
        pass


@register("drop_inert_artifact")
def _drop_inert_artifact(params: dict, ctx: "agent.platform.base.PlatformContext") -> None:
    """Writes a benign, inert marker file. Never an executable payload,
    never a callback.

    params = {"path": <file path>}. Content is a fixed, non-executable,
    plain-text marker string; permissions are explicitly set to 0o644
    (never executable).
    """
    requested = params.get("path")
    if not requested:
        return
    base = _artifact_base()
    content = "HUITZILOPOCHTLI adversary marker - inert, non-executable\n"
    if os.name != "nt":
        try:
            fd = _open_confined_posix(base, requested)
        except OSError:
            fd = None  # e.g. ELOOP: a symlink in the chain; refuse
        if fd is None:
            print(
                f"WARNING: refusing drop_inert_artifact path outside sandbox "
                f"(or through a symlink): {requested!r}",
                file=sys.stderr,
            )
            return
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass
        return
    target = _resolve_artifact_path(base, requested)
    if target is None:
        print(
            f"WARNING: refusing drop_inert_artifact path outside sandbox: "
            f"{requested!r}",
            file=sys.stderr,
        )
        return
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(target, 0o644)
    except Exception:
        pass
