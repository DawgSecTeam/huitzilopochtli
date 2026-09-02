"""Closed adversary action vocabulary. See architecture.md §12.2.

No action may open an outbound connection — there is no network-egress
primitive in this module. Do not add a generic "run command" primitive.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Callable

ACTIONS: dict[str, Callable] = {}

#: Directory confining ``drop_inert_artifact`` — resolved paths never escape it.
_DEFAULT_ARTIFACT_DIR = os.path.join(tempfile.gettempdir(), "huitzilopochtli-adversary")


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
    target = _resolve_artifact_path(base, requested)
    if target is None:
        print(
            f"WARNING: refusing drop_inert_artifact path outside sandbox: "
            f"{requested!r}",
            file=sys.stderr,
        )
        return
    content = "HUITZILOPOCHTLI adversary marker - inert, non-executable\n"
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(target, 0o644)
    except Exception:
        pass
