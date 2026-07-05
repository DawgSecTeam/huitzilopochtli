"""Integration tests for engine/server.py's TLS activation and
server_secret persistence behavior (see main()/_resolve_server_secret()).

These tests launch the real engine.server module as a subprocess (so we
exercise the actual argv/env-driven startup path, not just importable
functions) and talk to it over the network / inspect its sqlite DB
directly.
"""
import base64
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.store import Store  # noqa: E402  (after sys.path setup via conftest)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(url_prefix: str, port: int, timeout: float = 10.0, use_ssl_ctx=None):
    """Poll GET {url_prefix}127.0.0.1:{port}/health until it responds 200
    or the timeout elapses. Returns True on success, False on timeout."""
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            if use_ssl_ctx is not None:
                resp = urllib.request.urlopen(
                    f"{url_prefix}127.0.0.1:{port}/health", timeout=1, context=use_ssl_ctx
                )
            else:
                resp = urllib.request.urlopen(f"{url_prefix}127.0.0.1:{port}/health", timeout=1)
            if resp.status == 200:
                return True
        except Exception as e:  # noqa: BLE001 - keep polling on connection errors
            last_err = e
            time.sleep(0.1)
    if last_err is not None:
        print(f"last error while waiting for health: {last_err}")
    return False


def _spawn_engine(env_overrides: dict, port: int) -> subprocess.Popen:
    """Spawn `python -m engine.server` with a controlled environment.

    Any key in env_overrides mapped to None is removed from the inherited
    environment (rather than set to the string "None"), so callers can
    reliably force TLS/secret env vars off regardless of what the ambient
    test environment happens to have set.
    """
    env = os.environ.copy()
    for key, value in env_overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    env["DAWGSCORE_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, "-m", "engine.server"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc


def _terminate(proc: subprocess.Popen):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


# --- 1. server_secret persistence -------------------------------------------


def test_server_secret_persists_across_restarts(tmp_path):
    db_path = str(tmp_path / "dawgscore.db")
    port1 = _free_port()

    env = {
        "DAWGSCORE_DB_PATH": db_path,
        "DAWGSCORE_SERVER_SECRET": None,
        "DAWGSCORE_TLS_CERT": None,
        "DAWGSCORE_TLS_KEY": None,
    }

    proc1 = _spawn_engine(env, port1)
    try:
        assert _wait_for_health("http://", port1), (
            "first engine instance never became healthy: "
            + (proc1.stdout.read() if proc1.stdout else "")
        )
        # Give the store a brief moment beyond health to ensure the meta
        # row write (which happens before serve_forever) has landed.
        store_after_first_run = Store(db_path)
        secret_1 = store_after_first_run.get_meta("server_secret")
        assert secret_1 is not None, "server_secret was not persisted to engine_meta"
    finally:
        _terminate(proc1)

    port2 = _free_port()
    proc2 = _spawn_engine(env, port2)
    try:
        assert _wait_for_health("http://", port2), (
            "second engine instance never became healthy: "
            + (proc2.stdout.read() if proc2.stdout else "")
        )
        store_after_second_run = Store(db_path)
        secret_2 = store_after_second_run.get_meta("server_secret")
        assert secret_2 is not None
    finally:
        _terminate(proc2)

    assert secret_1 == secret_2, (
        "server_secret changed across restarts against the same DB path; "
        "the adversary schedule derived from it would not be stable"
    )
    # Sanity: it really is base64 of 32 random bytes, not an empty/placeholder value.
    assert len(base64.b64decode(secret_1)) == 32


# --- 2. TLS enabled -----------------------------------------------------------


def test_tls_enabled_serves_https_and_rejects_plain_http(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available in this environment")

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "1", "-subj", "/CN=localhost",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"openssl cert generation failed: {result.stderr}")

    db_path = str(tmp_path / "dawgscore.db")
    port = _free_port()
    env = {
        "DAWGSCORE_DB_PATH": db_path,
        "DAWGSCORE_TLS_CERT": str(cert_path),
        "DAWGSCORE_TLS_KEY": str(key_path),
    }

    proc = _spawn_engine(env, port)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        assert _wait_for_health("https://", port, use_ssl_ctx=ctx), (
            "TLS-enabled engine never became healthy over https: "
            + (proc.stdout.read() if proc.stdout else "")
        )

        # A plain HTTP request to the same port should fail: either the
        # connection is refused/reset, or it degrades to a protocol/parsing
        # error, but it must NOT succeed as a normal HTTP 200 response.
        plain_http_succeeded = False
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            if resp.status == 200:
                plain_http_succeeded = True
        except Exception:
            plain_http_succeeded = False
        finally:
            try:
                conn.close()
            except Exception:
                pass

        assert not plain_http_succeeded, (
            "plain HTTP request to a TLS-enabled engine unexpectedly succeeded"
        )
    finally:
        _terminate(proc)


# --- 3. TLS disabled (default) -------------------------------------------------


def test_tls_disabled_by_default_serves_plain_http(tmp_path):
    db_path = str(tmp_path / "dawgscore.db")
    port = _free_port()
    env = {
        "DAWGSCORE_DB_PATH": db_path,
        "DAWGSCORE_TLS_CERT": None,
        "DAWGSCORE_TLS_KEY": None,
    }

    proc = _spawn_engine(env, port)
    try:
        assert _wait_for_health("http://", port), (
            "plain-HTTP engine never became healthy: "
            + (proc.stdout.read() if proc.stdout else "")
        )
    finally:
        _terminate(proc)
