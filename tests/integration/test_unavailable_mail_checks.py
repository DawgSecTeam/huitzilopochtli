"""Integration: a host with no mail stack must NOT score 62 or 84.

Live field incident (2026-11-06, engine on 127.0.0.1:18890, Broadneck Post):
an agent bound to a host where `command -v postconf doveconf` found nothing
reported "hardening 84 / services 0" with zero work done, because the mail
checks fail-opened inside their collect scripts. Those checks now declare
`requires`, and this test replays the incident over the real wire: the agent
reports `unavailable` for every mail check that Broadneck Post gates on a
missing binary, and honest negative evidence for everything else. The engine
must score all of it 0 and record the ungraded count for the roster.
"""
import base64
import dataclasses
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import pytest
import requests
import yaml

from common import canon
from common.crypto import signing
from common.schema import Bundle, CollectorStatus, Evidence
from common.scenario_record import build_scenario_parts
from common.version import AGENT_VERSION

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCENARIO_PATH = os.path.join(REPO_ROOT, "boxes", "broadneck-post", "scenario.yaml")

REQUEST_TIMEOUT = 10.0
ADMIN_TOKEN = "test-admin-token-ungraded"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def engine(tmp_path):
    """Real engine.server subprocess on a private port and DB (same shape as
    tests/integration/test_admin_endpoints.py, incl. the no-boxes-dir default
    so the serving cache is only what this test uploads)."""
    db_path = str(tmp_path / "huitzilopochtli.db")
    port = _free_port()
    env = dict(os.environ)
    env["HUITZILOPOCHTLI_DB_PATH"] = db_path
    env["HUITZILOPOCHTLI_PORT"] = str(port)
    env["HUITZILOPOCHTLI_ADMIN_TOKEN"] = ADMIN_TOKEN
    env["HUITZILOPOCHTLI_TLS_CERT"] = ""
    env["HUITZILOPOCHTLI_TLS_KEY"] = ""
    env.setdefault("HUITZILOPOCHTLI_BOXES_DIR",
                   os.path.join(tempfile.gettempdir(),
                                f"huitz-test-noboxes-{os.getpid()}"))
    proc = subprocess.Popen(
        [sys.executable, "-m", "engine.server"],
        cwd=REPO_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if requests.get(f"{base_url}/health", timeout=1).status_code == 200:
                break
        except Exception:  # noqa: BLE001 - keep polling until the port opens
            time.sleep(0.1)
    else:
        proc.terminate()
        raise AssertionError(
            "engine never became healthy: "
            + (proc.stdout.read() if proc.stdout else ""))
    try:
        yield base_url, db_path
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def _broadneck_parts() -> dict:
    """Compile the committed box through the shared pipeline (the engine's
    own box-folder path). The pool block is deployment data (${VAR}
    placeholders); this test serves a competition-less check-in, so it is
    stripped exactly like engine/scenario.py does when expansion fails."""
    with open(SCENARIO_PATH, encoding="utf-8") as f:
        parsed = yaml.safe_load(f.read())
    parsed["ranked"].pop("pool", None)
    return build_scenario_parts(parsed, "ranked", source=SCENARIO_PATH)


def _upload(base_url: str, record: dict) -> None:
    resp = requests.post(
        f"{base_url}/admin/scenarios",
        json=record,
        headers={"X-HUITZILOPOCHTLI-Admin-Token": ADMIN_TOKEN},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text


def _enroll(base_url: str, box_id: str) -> bytes:
    resp = requests.post(
        f"{base_url}/admin/tokens",
        json={"scenario_name": "Broadneck Post", "ttl_s": 3600},
        headers={"X-HUITZILOPOCHTLI-Admin-Token": ADMIN_TOKEN},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text
    priv, pub = signing.keypair()
    body = {
        "enrollment_token": resp.json()["token"],
        "box_id": box_id,
        "public_key": base64.b64encode(pub).decode("ascii"),
        "agent_version": AGENT_VERSION,
        "scenario_name": "Broadneck Post",
        "scenario_version": 1,
    }
    sig = signing.sign(priv, canon.canonicalize(body))
    resp = requests.post(
        f"{base_url}/enroll", json=body,
        headers={"X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode("ascii")},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text
    return priv


def test_unavailable_mail_checks_score_zero(engine):
    """Agent says `unavailable` for every gated mail check on a host with no
    mail stack: hardening must be 0 -- NOT 62 (the old fail-open mail points)
    and NOT 84 (the live incident total) -- and the gate count must be stored
    so the roster and player dashboard can show it."""
    base_url, db_path = engine
    parts = _broadneck_parts()
    record = parts["engine_record"]
    gated = record["requires"]
    assert len(gated) >= 17, "the mail checks must still declare requires"
    _upload(base_url, record)
    priv = _enroll(base_url, "box-nomail-1")

    spec_types = {spec.id: spec.type for spec in parts["check_specs"]}

    evidence = []
    for entry in record["rubric"]["entries"]:
        cid = entry["check_id"]
        check_type = spec_types.get(cid, "command_json")
        if cid in gated:
            ev = Evidence(
                check_id=cid, check_type=check_type, host_id="localhost",
                status=CollectorStatus.UNAVAILABLE, raw={},
                reason=f"{gated[cid][0]} not present",
                collected_monotonic=1.0, collected_wall_claim=time.time())
        elif entry.get("sla") is not None:
            ev = Evidence(
                check_id=cid, check_type=check_type, host_id="localhost",
                status=CollectorStatus.OK, raw={"open": False}, reason="closed",
                collected_monotonic=1.0, collected_wall_claim=time.time())
        else:
            ev = Evidence(
                check_id=cid, check_type=check_type, host_id="localhost",
                status=CollectorStatus.OK,
                raw={"data": False, "text": "false"}, reason="not hardened",
                collected_monotonic=1.0, collected_wall_claim=time.time())
        evidence.append(ev)

    bundle = Bundle(
        box_id="box-nomail-1", seq=1, boot_id="boot-1",
        agent_version=AGENT_VERSION, scenario_name="Broadneck Post",
        scenario_version=1, evidence=evidence,
        created_wall_claim=time.time(),
    )
    body = dataclasses.asdict(bundle)
    sig = signing.sign(priv, canon.canonicalize(body))
    resp = requests.post(
        f"{base_url}/checkin", json=body,
        headers={"X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode("ascii")},
        timeout=REQUEST_TIMEOUT,
    )
    assert resp.status_code == 200, resp.text
    score = resp.json()["score"]

    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT total, hardening_points, service_points, ungraded_count "
            "FROM scores WHERE box_id = 'box-nomail-1'").fetchone()
    finally:
        conn.close()
    assert row is not None, "check-in did not produce a score row"
    total, hardening, services, ungraded = row

    # The incident numbers must be impossible now.
    assert total not in (62, 84)
    assert hardening not in (62, 84)
    assert hardening == 0 and total == 0 and services == 0
    assert int(score["total"]) == 0
    # Every gated mail check reads as ungraded, not solved, not failed.
    assert ungraded == len(gated)
    assert ungraded >= 17
