"""`huitz join` — bind a ranked competition box to a player slot.

The box image carries a signed ranked manifest and no enrollment token. The
player gets a one-time code from the competition site; this command signs a
/join request with the box key and starts the ranked agent unit.
"""
import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

import agent.config
import agent.identity
from common import canon
from common.crypto import signing
from common.version import AGENT_VERSION


class JoinError(Exception):
    pass


def _post_join(engine_url: str, body: dict, private_key: bytes,
               timeout: float = 15.0) -> dict:
    canonical = canon.canonicalize(body)
    sig = signing.sign(private_key, canonical)
    req = urllib.request.Request(
        engine_url.rstrip("/") + "/join", data=canonical, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode("ascii"),
            "X-HUITZILOPOCHTLI-Box": body["box_id"],
        },
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw)
            msg = parsed.get("error") or raw
        except ValueError:
            msg = raw or f"HTTP {exc.code}"
        raise JoinError(f"join rejected ({exc.code}): {msg}") from exc
    except urllib.error.URLError as exc:
        raise JoinError(f"could not reach engine at {engine_url}: {exc}") from exc


def _start_agent() -> None:
    """Start the ranked agent after a successful join.

    Linux: enable+start the systemd unit. Windows: the box ships with the
    SYSTEM scheduled task registered but disabled, so joining enables and
    runs it. Failures are ignored -- the join itself already succeeded.
    """
    if os.name == "nt":
        # Ranked Windows boxes ship with the SYSTEM task registered but
        # disabled; joining turns it on so check-ins begin. Best effort: the
        # task's 5-minute repetition starts it even if the immediate /Run is
        # denied.
        for args in (["schtasks", "/Change", "/TN", "HuitzilopochtliAgent",
                      "/ENABLE"],
                     ["schtasks", "/Run", "/TN", "HuitzilopochtliAgent"]):
            try:
                subprocess.run(args, capture_output=True, text=True,
                               timeout=20)
            except Exception:
                continue
    else:
        for unit in ("huitzilopochtli-agent.service",
                     "huitzilopochtli-agent"):
            try:
                proc = subprocess.run(
                    ["systemctl", "enable", "--now", unit],
                    capture_output=True, text=True, timeout=20)
                if proc.returncode == 0:
                    break
            except Exception:
                continue


def join(config_path: str, code: str, start_service: bool = True) -> dict:
    code = (code or "").strip().upper()
    if not code:
        raise JoinError("a join code is required (get it from the competition page)")
    try:
        config = agent.config.load_config(config_path)
    except (OSError, ValueError, KeyError) as exc:
        raise JoinError(f"cannot load agent config {config_path!r}: {exc}") from exc
    if config.mode.value != "ranked":
        raise JoinError("this box is not a ranked competition box")
    import agent.__main__ as agent_main
    try:
        manifest = agent_main._load_manifest(
            config.manifest_path, config.authoring_public_key_path,
            allow_unsigned=config.allow_unsigned_manifest)
    except (OSError, ValueError) as exc:
        raise JoinError(f"cannot load signed manifest: {exc}") from exc
    if not manifest.engine_url:
        raise JoinError("the manifest has no engine_url")
    identity = agent.identity.load_or_create(config.identity_path)
    body = {
        "join_code": code,
        "box_id": identity.box_id,
        "public_key": base64.b64encode(identity.public_key).decode("ascii"),
        "agent_version": AGENT_VERSION,
        "scenario_name": manifest.scenario_name,
        "scenario_version": manifest.scenario_version,
    }
    result = _post_join(manifest.engine_url, body, identity.private_key)
    identity.last_seq = 0
    agent.identity.save(config.identity_path, identity)
    marker = config.identity_path + ".enrolled"
    try:
        with open(marker, "w", encoding="utf-8") as f:
            f.write("enrolled\n")
    except OSError:
        pass
    if start_service:
        _start_agent()
    return result
