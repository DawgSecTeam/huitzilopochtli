"""Integration tests for boxbuilder.engine against the REAL engine server.

Spawns engine.server as a subprocess (like test_admin_endpoints.py does), then
exercises boxbuilder.engine.upload_scenario + mint_enrollment_token over real
HTTP. This validates the full ranked-mode wiring path against the actual
admin endpoints, not a stub.

These tests do not modify anything outside this file.
"""
import json
import os
import socket
import subprocess
import sys
import time

import pytest

from boxbuilder import engine

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
ADMIN_TOKEN = "test-admin-token-xyz"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(url, timeout=10.0):
    import urllib.request
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception as e:
            last = str(e)
        time.sleep(0.2)
    pytest.fail(f"engine did not become healthy at {url}: {last}")


@pytest.fixture
def engine_server(tmp_path):
    port = _free_port()
    db = tmp_path / "e.db"
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_DB_PATH": str(db),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": ADMIN_TOKEN,
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "engine.server"],
        cwd=REPO_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_health(url)
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _engine_record():
    """A minimal valid engine_record.json (rubric + empty adversary)."""
    return {
        "rubric": {
            "schema_version": 1,
            "scenario_name": "demo-ranked",
            "scenario_version": 1,
            "entries": [
                {"check_id": "ssh_no_root", "category": "vuln",
                 "matcher": {"tag": "equals", "value": "no"},
                 "points": 5, "sla": None},
            ],
        },
        "adversary": {"events": []},
    }


def test_upload_scenario_and_mint_token(engine_server, tmp_path):
    rec_path = tmp_path / "engine_record.json"
    rec_path.write_text(json.dumps(_engine_record()))
    url = engine_server

    resp = engine.upload_scenario(url, ADMIN_TOKEN, str(rec_path))
    assert resp["ok"] is True
    assert resp["scenario_name"] == "demo-ranked"

    token = engine.mint_enrollment_token(url, ADMIN_TOKEN, "demo-ranked", ttl_s=3600)
    assert isinstance(token, str) and len(token) > 10


def test_upload_scenario_rejects_bad_admin_token(engine_server, tmp_path):
    rec_path = tmp_path / "engine_record.json"
    rec_path.write_text(json.dumps(_engine_record()))
    with pytest.raises(engine.EngineError) as ei:
        engine.upload_scenario(engine_server, "wrong-token", str(rec_path))
    assert ei.value.status_code == 403


def test_mint_token_rejects_missing_token(engine_server):
    with pytest.raises(engine.EngineError, match="admin token is required"):
        engine.mint_enrollment_token(engine_server, "", "demo-ranked")


def test_upload_rejects_malformed_rubric(engine_server, tmp_path):
    bad = {"rubric": {"scenario_name": "bad", "entries": "not-a-list"}, "adversary": {"events": []}}
    rec_path = tmp_path / "bad.json"
    rec_path.write_text(json.dumps(bad))
    with pytest.raises(engine.EngineError) as ei:
        engine.upload_scenario(engine_server, ADMIN_TOKEN, str(rec_path))
    assert ei.value.status_code == 400


def test_resolve_admin_token_env(monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_ADMIN_TOKEN", "from-env")
    assert engine.resolve_admin_token(None) == "from-env"
    assert engine.resolve_admin_token("explicit") == "explicit"


def test_resolve_admin_token_empty(monkeypatch):
    monkeypatch.delenv("HUITZILOPOCHTLI_ADMIN_TOKEN", raising=False)
    assert engine.resolve_admin_token(None) == ""
