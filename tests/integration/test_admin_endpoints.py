"""Integration tests for engine/server.py's /admin/tokens and
/admin/scenarios endpoints, plus the per-scenario rubric lookup they feed
into on /checkin.

These tests launch the real engine.server module as a subprocess (exercising
the actual env-driven startup path) and talk to it over real HTTP on
127.0.0.1, polling /health rather than sleeping a fixed amount. Each test
gets its own tmp_path-scoped sqlite DB and a freshly-allocated free port so
concurrent test runs never collide.

Per task instructions, this file must not modify anything outside itself;
any bug found in engine/server.py or engine/store.py is flagged in comments
here rather than fixed.
"""
import base64
import dataclasses
import os
import socket
import subprocess
import sys
import time

import pytest
import requests

from authoring.compile import compile_scenario
from common import canon
from common.crypto import signing
from common.schema import Bundle, CollectorStatus, Evidence

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REQUEST_TIMEOUT = 5.0


# --- process / networking helpers -------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_health(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            resp = requests.get(f"http://127.0.0.1:{port}/health", timeout=1)
            if resp.status_code == 200:
                return True
        except Exception as e:  # noqa: BLE001 - keep polling on connection errors
            last_err = e
            time.sleep(0.1)
    if last_err is not None:
        print(f"last error while waiting for health: {last_err}")
    return False


def _spawn_engine(env_overrides: dict, port: int) -> subprocess.Popen:
    """Spawn `python -m engine.server` with a controlled environment.

    A value of None in env_overrides removes that key from the inherited
    environment entirely (rather than setting it to the string "None"), so
    tests can reliably force e.g. HUITZILOPOCHTLI_ADMIN_TOKEN off.
    """
    env = os.environ.copy()
    for key, value in env_overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    env["HUITZILOPOCHTLI_PORT"] = str(port)
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


@pytest.fixture
def engine(tmp_path):
    """Start a real engine.server subprocess with HUITZILOPOCHTLI_ADMIN_TOKEN set.

    Yields (base_url, admin_token, db_path, proc).
    """
    db_path = str(tmp_path / "huitzilopochtli.db")
    port = _free_port()
    admin_token = "test-admin-token-abc123"
    env = {
        "HUITZILOPOCHTLI_DB_PATH": db_path,
        "HUITZILOPOCHTLI_ADMIN_TOKEN": admin_token,
        "HUITZILOPOCHTLI_TLS_CERT": None,
        "HUITZILOPOCHTLI_TLS_KEY": None,
    }
    proc = _spawn_engine(env, port)
    try:
        ok = _wait_for_health(port)
        assert ok, (
            "engine never became healthy: "
            + (proc.stdout.read() if proc.stdout else "")
        )
        yield f"http://127.0.0.1:{port}", admin_token, db_path, proc
    finally:
        _terminate(proc)


@pytest.fixture
def engine_no_admin_token(tmp_path):
    """Start a real engine.server subprocess with NO HUITZILOPOCHTLI_ADMIN_TOKEN
    set at all, so admin endpoints must respond 503."""
    db_path = str(tmp_path / "huitzilopochtli.db")
    port = _free_port()
    env = {
        "HUITZILOPOCHTLI_DB_PATH": db_path,
        "HUITZILOPOCHTLI_ADMIN_TOKEN": None,
        "HUITZILOPOCHTLI_TLS_CERT": None,
        "HUITZILOPOCHTLI_TLS_KEY": None,
    }
    proc = _spawn_engine(env, port)
    try:
        ok = _wait_for_health(port)
        assert ok, (
            "engine never became healthy: "
            + (proc.stdout.read() if proc.stdout else "")
        )
        yield f"http://127.0.0.1:{port}", proc
    finally:
        _terminate(proc)


# --- scenario-building helper ------------------------------------------------


def _build_engine_record(tmp_path, scenario_name: str, expected_value: str = "yes",
                          points: int = 10) -> dict:
    """Compile a minimal single-check ranked scenario via the real
    authoring/compile.py pipeline and return the resulting engine_record.json
    dict (the exact shape POST /admin/scenarios expects:
    {"rubric": {...}, "adversary": {...}}).

    The check uses the "equals" matcher against evidence.raw["matched"]
    (the default field), so a checkin can be made to pass/fail deterministically.
    """
    yaml_src = f"""
scenario:
  name: {scenario_name}
  version: 1
  mode: ranked
  engine_url: "https://example.invalid"
  hosts:
    - localhost

checks:
  - id: check1
    type: file_regex
    category: vuln
    host_id: localhost
    display: "Test check"
    max_points: {points}
    collect: {{}}
    expect:
      equals: "{expected_value}"
      points: {points}

adversary: {{}}
"""
    yaml_path = tmp_path / f"{scenario_name}.yaml"
    yaml_path.write_text(yaml_src)
    out_dir = tmp_path / f"{scenario_name}_out"
    priv_key, _pub_key = signing.keypair()
    outputs = compile_scenario(str(yaml_path), str(out_dir), priv_key)

    import json
    with open(outputs["engine_record"]) as f:
        return json.load(f)


# --- enroll/checkin helpers over real HTTP -----------------------------------


def _enroll_box(base_url: str, admin_token: str, scenario_name: str, box_id: str):
    """Create an enrollment token via the admin endpoint, then perform a real
    signed /enroll for a fresh box keypair. Returns (private_key, public_key_b64)."""
    resp = requests.post(
        f"{base_url}/admin/tokens",
        json={"scenario_name": scenario_name, "ttl_s": 3600},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": admin_token},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text
    enrollment_token = resp.json()["token"]

    priv_key, pub_key = signing.keypair()
    pub_key_b64 = base64.b64encode(pub_key).decode("ascii")

    body = {
        "enrollment_token": enrollment_token,
        "box_id": box_id,
        "public_key": pub_key_b64,
        "agent_version": "test-agent-1.0",
        "scenario_name": scenario_name,
    }
    sig = signing.sign(priv_key, canon.canonicalize(body))
    resp = requests.post(
        f"{base_url}/enroll",
        json=body,
        headers={"X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode("ascii")},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text
    return priv_key, pub_key_b64


def _make_checkin_body(box_id: str, scenario_name: str, seq: int, matched_value: str) -> dict:
    bundle = Bundle(
        box_id=box_id,
        seq=seq,
        boot_id="boot-1",
        agent_version="test-agent-1.0",
        scenario_name=scenario_name,
        scenario_version=1,
        evidence=[
            Evidence(
                check_id="check1",
                check_type="file_regex",
                host_id="localhost",
                status=CollectorStatus.OK,
                raw={"matched": matched_value},
                reason="",
                collected_monotonic=1.0,
                collected_wall_claim=time.time(),
            )
        ],
        created_wall_claim=time.time(),
    )
    return dataclasses.asdict(bundle)


def _signed_checkin(base_url: str, priv_key: bytes, body: dict):
    sig = signing.sign(priv_key, canon.canonicalize(body))
    return requests.post(
        f"{base_url}/checkin",
        json=body,
        headers={"X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode("ascii")},
        timeout=REQUEST_TIMEOUT,
    )


# --- 1. admin auth: correct token succeeds -----------------------------------


def test_admin_tokens_and_scenarios_succeed_with_correct_token(engine, tmp_path):
    base_url, admin_token, _db_path, _proc = engine
    scenario_name = "scenario-auth-ok"

    resp = requests.post(
        f"{base_url}/admin/tokens",
        json={"scenario_name": scenario_name, "ttl_s": 3600},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": admin_token},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scenario_name"] == scenario_name
    assert isinstance(body["token"], str) and body["token"]

    engine_record = _build_engine_record(tmp_path, scenario_name)
    resp = requests.post(
        f"{base_url}/admin/scenarios",
        json=engine_record,
        headers={"X-HUITZILOPOCHTLI-Admin-Token": admin_token},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "scenario_name": scenario_name}


# --- 2. admin auth: wrong/missing token is rejected with 403 ----------------


def test_admin_tokens_rejects_wrong_token(engine, tmp_path):
    base_url, _admin_token, _db_path, _proc = engine
    scenario_name = "scenario-auth-bad"

    resp = requests.post(
        f"{base_url}/admin/tokens",
        json={"scenario_name": scenario_name, "ttl_s": 3600},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": "totally-wrong-token"},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 403, resp.text

    resp = requests.post(
        f"{base_url}/admin/tokens",
        json={"scenario_name": scenario_name, "ttl_s": 3600},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 403, resp.text


def test_admin_scenarios_rejects_wrong_token(engine, tmp_path):
    base_url, _admin_token, _db_path, _proc = engine
    scenario_name = "scenario-auth-bad-2"
    engine_record = _build_engine_record(tmp_path, scenario_name)

    resp = requests.post(
        f"{base_url}/admin/scenarios",
        json=engine_record,
        headers={"X-HUITZILOPOCHTLI-Admin-Token": "totally-wrong-token"},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 403, resp.text

    resp = requests.post(
        f"{base_url}/admin/scenarios",
        json=engine_record,
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 403, resp.text


# --- 3. admin endpoints disabled (503) when no admin token configured -------


def test_admin_endpoints_disabled_with_503_when_no_admin_token_set(
    engine_no_admin_token, tmp_path
):
    base_url, _proc = engine_no_admin_token
    scenario_name = "scenario-no-admin"

    resp = requests.post(
        f"{base_url}/admin/tokens",
        json={"scenario_name": scenario_name, "ttl_s": 3600},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": "anything"},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 503, resp.text

    engine_record = _build_engine_record(tmp_path, scenario_name)
    resp = requests.post(
        f"{base_url}/admin/scenarios",
        json=engine_record,
        headers={"X-HUITZILOPOCHTLI-Admin-Token": "anything"},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 503, resp.text


# --- 4. per-scenario rubric resolution: upload -> checkin against that ------
#        exact scenario_name resolves the correct (not a global) rubric ----


def test_checkin_resolves_rubric_per_scenario_not_globally(engine, tmp_path):
    base_url, admin_token, _db_path, _proc = engine

    # Two distinct scenarios with DIFFERENT expected values / point totals,
    # uploaded under different names. If the engine used a single global
    # rubric instead of a true per-scenario lookup, a checkin against
    # scenario B would score using scenario A's expectations (or vice versa).
    scenario_a = "rubric-scenario-a"
    scenario_b = "rubric-scenario-b"

    record_a = _build_engine_record(tmp_path, scenario_a, expected_value="yes", points=10)
    record_b = _build_engine_record(tmp_path, scenario_b, expected_value="no", points=25)

    for record in (record_a, record_b):
        resp = requests.post(
            f"{base_url}/admin/scenarios",
            json=record,
            headers={"X-HUITZILOPOCHTLI-Admin-Token": admin_token},
            timeout=REQUEST_TIMEOUT,
        )
        assert resp.status_code == 200, resp.text

    priv_a, _pub_a = _enroll_box(base_url, admin_token, scenario_a, box_id="box-a")
    priv_b, _pub_b = _enroll_box(base_url, admin_token, scenario_b, box_id="box-b")

    # box-a submits evidence matching scenario A's expectation ("yes") -> 10 pts.
    body_a = _make_checkin_body(box_id="box-a", scenario_name=scenario_a, seq=1,
                                 matched_value="yes")
    resp = _signed_checkin(base_url, priv_a, body_a)
    assert resp.status_code == 200, resp.text
    score_a = resp.json()["score"]
    assert score_a["scenario_name"] == scenario_a
    assert score_a["total"] == 10

    # box-b submits evidence matching scenario B's expectation ("no") -> 25 pts.
    # If the engine wrongly used scenario A's rubric here (expects "yes"),
    # this would score 0 instead of 25.
    body_b = _make_checkin_body(box_id="box-b", scenario_name=scenario_b, seq=1,
                                 matched_value="no")
    resp = _signed_checkin(base_url, priv_b, body_b)
    assert resp.status_code == 200, resp.text
    score_b = resp.json()["score"]
    assert score_b["scenario_name"] == scenario_b
    assert score_b["total"] == 25


# --- 5. checkin against a never-uploaded scenario -> clean 400 --------------


def test_checkin_unknown_scenario_returns_clean_400(engine, tmp_path):
    base_url, admin_token, _db_path, _proc = engine

    # Enroll the box against a scenario name that is registered as an
    # enrollment-token scenario but for which we deliberately never upload
    # an /admin/scenarios rubric, so the store's `scenarios` table has no
    # row for it at checkin time.
    unknown_scenario = "scenario-never-uploaded"
    priv_key, _pub = _enroll_box(base_url, admin_token, unknown_scenario, box_id="box-unknown")

    body = _make_checkin_body(box_id="box-unknown", scenario_name=unknown_scenario,
                               seq=1, matched_value="yes")
    resp = _signed_checkin(base_url, priv_key, body)

    assert resp.status_code == 400, resp.text
    payload = resp.json()
    assert "unknown scenario" in payload["error"].lower()
    assert payload.get("scenario_name") == unknown_scenario
    assert payload.get("last_seq") is None


# --- 6. leaderboard reflects a real checkin's score -------------------------


def test_leaderboard_reflects_score_after_checkin(engine, tmp_path):
    base_url, admin_token, _db_path, _proc = engine
    scenario_name = "scenario-leaderboard"

    record = _build_engine_record(tmp_path, scenario_name, expected_value="yes", points=15)
    resp = requests.post(
        f"{base_url}/admin/scenarios",
        json=record,
        headers={"X-HUITZILOPOCHTLI-Admin-Token": admin_token},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text

    priv_key, _pub = _enroll_box(base_url, admin_token, scenario_name, box_id="board-box-1")

    # Before any checkin, the leaderboard for this scenario should have no
    # entry for this box.
    resp = requests.get(
        f"{base_url}/leaderboard", params={"scenario": scenario_name}, timeout=REQUEST_TIMEOUT
    )
    assert resp.status_code == 200, resp.text
    before_ids = {row["box_id"] for row in resp.json()}
    assert "board-box-1" not in before_ids

    body = _make_checkin_body(box_id="board-box-1", scenario_name=scenario_name, seq=1,
                               matched_value="yes")
    resp = _signed_checkin(base_url, priv_key, body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["score"]["total"] == 15

    resp = requests.get(
        f"{base_url}/leaderboard", params={"scenario": scenario_name}, timeout=REQUEST_TIMEOUT
    )
    assert resp.status_code == 200, resp.text
    rows = {row["box_id"]: row for row in resp.json()}
    assert "board-box-1" in rows
    assert rows["board-box-1"]["total"] == 15
    assert rows["board-box-1"]["scenario_name"] == scenario_name
