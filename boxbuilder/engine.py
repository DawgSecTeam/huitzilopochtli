"""Ranked-mode engine wiring: upload the scenario record + mint an enrollment token.

Uses the engine's admin HTTP API (engine/server.py), gated by the
X-HUITZILOPOCHTLI-Admin-Token header:
  POST /admin/scenarios   {rubric, adversary}   -> {ok, scenario_name}
  POST /admin/tokens      {scenario_name, ttl_s} -> {token, expires_at}

stdlib http.client only (like the agent transport), so boxbuilder adds no HTTP
dependency. TLS is used when engine_url is https://.

This module is ranked-only; honor mode never imports it.
"""
import json
import os
import ssl
from typing import Optional
from urllib.parse import urlsplit


class EngineError(Exception):
    def __init__(self, message: str, *, status_code: int = 0, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _split_url(engine_url: str):
    parts = urlsplit(engine_url)
    if parts.scheme not in ("http", "https"):
        raise EngineError(f"engine_url must be http(s)://, got {engine_url!r}")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, host, port


def _request(scheme: str, host: str, port: int, method: str, path: str,
             admin_token: str, body: Optional[dict] = None, timeout: int = 30) -> dict:
    """One HTTP request to the engine admin API. Returns parsed JSON response."""
    import http.client

    payload = json.dumps(body).encode("utf-8") if body is not None else b""
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(payload)),
        "X-HUITZILOPOCHTLI-Admin-Token": admin_token,
    }
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", "replace")
        finally:
            conn.close()
    except OSError as e:
        raise EngineError(f"could not reach engine at {scheme}://{host}:{port}: {e}") from e

    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"raw": raw}

    if resp.status >= 400:
        msg = parsed.get("error") or parsed.get("raw") or f"HTTP {resp.status}"
        # 503 means admin endpoints are disabled (no admin token on the engine).
        hint = ""
        if resp.status == 503:
            hint = " (is HUITZILOPOCHTLI_ADMIN_TOKEN set on the engine?)"
        raise EngineError(f"engine {method} {path} failed: {msg}{hint}",
                          status_code=resp.status, body=raw)
    return parsed


def upload_scenario(engine_url: str, admin_token: str, engine_record_path: str,
                    timeout: int = 30) -> dict:
    """POST /admin/scenarios with the compiled engine_record.json.

    `engine_record_path` is produced by authoring/compile.py (rubric + adversary).
    Returns the engine's {"ok", "scenario_name"} response.
    """
    if not admin_token:
        raise EngineError(
            "admin token is required to upload the scenario record; set "
            "HUITZILOPOCHTLI_ADMIN_TOKEN (the engine's admin token)"
        )
    try:
        with open(engine_record_path, "r", encoding="utf-8") as f:
            record = json.load(f)
    except FileNotFoundError as e:
        raise EngineError(
            f"compiled engine record not found: {engine_record_path} "
            f"(run `compile` first)"
        ) from e
    except json.JSONDecodeError as e:
        raise EngineError(
            f"engine record at {engine_record_path} is not valid JSON: {e}"
        ) from e
    # The endpoint expects exactly {rubric, adversary}; engine_record has that shape.
    scheme, host, port = _split_url(engine_url)
    return _request(scheme, host, port, "POST", "/admin/scenarios", admin_token,
                    body=record, timeout=timeout)


def mint_enrollment_token(engine_url: str, admin_token: str, scenario_name: str,
                          ttl_s: int = 86400, timeout: int = 30) -> str:
    """POST /admin/tokens -> return the one-time enrollment token string.

    The token is embedded in agent_config.json.enrollment_token and consumed
    once by the agent on its first ranked boot (see agent/config.py).
    """
    if not admin_token:
        raise EngineError("admin token is required to mint an enrollment token")
    scheme, host, port = _split_url(engine_url)
    resp = _request(scheme, host, port, "POST", "/admin/tokens", admin_token,
                    body={"scenario_name": scenario_name, "ttl_s": ttl_s}, timeout=timeout)
    token = resp.get("token")
    if not token:
        raise EngineError(
            f"engine returned no enrollment token for scenario {scenario_name!r}: {resp!r}",
            status_code=200, body=str(resp),
        )
    return token


def resolve_admin_token(explicit: Optional[str]) -> str:
    """explicit arg > $HUITZILOPOCHTLI_ADMIN_TOKEN. Empty if neither set (caller
    decides whether that's fatal; ranked install requires it)."""
    return explicit or os.environ.get("HUITZILOPOCHTLI_ADMIN_TOKEN", "")
