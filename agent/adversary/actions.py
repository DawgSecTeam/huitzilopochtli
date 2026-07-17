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
import sys
import tempfile
from typing import Callable

ACTIONS: dict[str, Callable] = {}

#: Dedicated directory the drop_inert_artifact action is confined to. A
#: directive's `path` is always resolved *inside* this base and may never
#: escape it, so a compromised/buggy engine cannot direct the agent to
#: overwrite arbitrary files (/etc/shadow, authorized_keys, ...). Overridable
#: via env for operators who want a specific location.
_DEFAULT_ARTIFACT_DIR = os.path.join(tempfile.gettempdir(), "huitzilopochtli-adversary")


def _artifact_base() -> str:
    return os.environ.get("HUITZILOPOCHTLI_ARTIFACT_DIR", _DEFAULT_ARTIFACT_DIR)


def _resolve_artifact_path(base: str, requested: str):
    """Resolve `requested` as a path *inside* `base`, or return None if it would
    escape. Leading separators/drive are stripped so an absolute-looking path
    (e.g. "/etc/shadow") is re-anchored under base rather than honored, and the
    normalized result is verified to stay within base (blocking `..` traversal)."""
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
    """Flush the local packet filter rules. Best-effort, local-only.

    Tries iptables first (flush rules + delete custom chains), falls back to
    nft, and does nothing gracefully if neither tool is present. This is not
    itself a security boundary -- it's a best-effort local adversary action.

    The iptables -> nft fallback is per-tool: if iptables is present but the
    flush call itself raises (PermissionError, the binary vanishing between
    shutil.which and run, etc.) we still try nft rather than swallowing the
    error and giving up -- an earlier version wrapped both branches in one
    try/except, so any iptables failure short-circuited the nft fallback.
    """
    if shutil.which("iptables"):
        try:
            subprocess.run(["iptables", "-F"], check=False,
                            capture_output=True, timeout=10)
            subprocess.run(["iptables", "-X"], check=False,
                            capture_output=True, timeout=10)
            return
        except Exception:
            # iptables present but unusable: fall through to nft below rather
            # than giving up (the box's real firewall may well be nft).
            pass
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
    requested = params.get("path")
    if not requested:
        return
    base = _artifact_base()
    target = _resolve_artifact_path(base, requested)
    if target is None:
        # The requested path escapes the artifact sandbox. Refuse rather than
        # traverse -- a directive must never write outside the dedicated
        # adversary artifact directory. This is a security boundary, so it is
        # not silently swallowed like a best-effort write failure below.
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
        # Best-effort local action; failure to write is not a security event.
        pass
