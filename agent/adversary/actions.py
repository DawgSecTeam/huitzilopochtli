"""Closed adversary action vocabulary. See architecture.md §12.2.

FROZEN registry mechanism. This module implements the 3 allowlisted actions.

Hard constraint (§2.7): no action may open an outbound connection to any host
other than the engine. There is no network-egress primitive anywhere in this
module — that is a structural property, not a policy to be enforced at
runtime. Do not add a generic "run command" primitive.
"""
import os
import shutil
import subprocess
from typing import Callable

ACTIONS: dict[str, Callable] = {}


def register(name: str):
    def deco(fn):
        ACTIONS[name] = fn
        return fn
    return deco


@register("flush_firewall")
def _flush_firewall(params: dict, ctx: "agent.platform.base.PlatformContext") -> None:
    """Flush the local packet filter rules. Best-effort, local-only.

    Tries iptables first (flush rules + delete custom chains), falls back to
    nft, and does nothing gracefully if neither tool is present. This is not
    itself a security boundary -- it's a best-effort local adversary action.
    """
    try:
        if shutil.which("iptables"):
            subprocess.run(["iptables", "-F"], check=False,
                            capture_output=True, timeout=10)
            subprocess.run(["iptables", "-X"], check=False,
                            capture_output=True, timeout=10)
            return
        if shutil.which("nft"):
            subprocess.run(["nft", "flush", "ruleset"], check=False,
                            capture_output=True, timeout=10)
            return
        # Neither tool present: no-op, not an error.
    except Exception:
        # Best-effort action; a failure here just means the box is more
        # secure than expected, not an executor error.
        pass


@register("kill_service")
def _kill_service(params: dict, ctx: "agent.platform.base.PlatformContext") -> None:
    """Stop the named service via a direct subprocess call.

    Stopping a service is a mutation, which is why this bypasses the
    read-only PlatformContext ABC (§9.1) -- the adversary executor is the
    one component explicitly permitted to mutate system state (§2.7/§12).
    Detection mirrors agent/platform/detect.py's systemd-vs-OpenRC check.
    """
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
    path = params.get("path")
    if not path:
        return
    content = "DAWGSCORE adversary marker - inert, non-executable\n"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o644)
    except Exception:
        # Best-effort local action; failure to write is not a security event.
        pass
