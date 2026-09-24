"""Ranked resilience tests over the real wire: engine restart persistence,
verify-gate 503 backpressure with concurrent boxes, and the enrollment-token
race. Complements the loopback tier (which restarts the AGENT) by restarting
the ENGINE and hammering it from several boxes at once.
"""
import base64
import json
import sqlite3
import threading
import time

import pytest

import test_ranked_loopback as lb
from common import canon
from common.crypto import signing
from common.version import AGENT_VERSION

# The vendored Ed25519 verify takes ~1.8s and holds the GIL; one gate slot
# means concurrent arrivals past the first must see 503s.
_VERIFY_TIME_S = 1.8


def _enroll(engine, token, scenario_name, scenario_version, box_id):
    priv, pub = signing.keypair()
    body = {
        "enrollment_token": token,
        "box_id": box_id,
        "public_key": base64.b64encode(pub).decode("ascii"),
        "agent_version": AGENT_VERSION,
        "scenario_name": scenario_name,
        "scenario_version": scenario_version,
    }
    status, parsed = lb._http_json(
        f"{engine.base_url}/enroll", body,
        headers={
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(
                signing.sign(priv, canon.canonicalize(body))).decode("ascii"),
        },
        method="POST",
    )
    assert status == 200, parsed
    return priv, pub, body


def _checkin_body(box_id, seq, scenario_name, hardened):
    return {
        "box_id": box_id,
        "seq": seq,
        "boot_id": f"boot-{box_id}",
        "agent_version": AGENT_VERSION,
        "scenario_name": scenario_name,
        "scenario_version": 1,
        "evidence": [
            {
                "check_id": "backdoor-absent",
                "check_type": "file_regex",
                "host_id": "host-1",
                "status": "ok",
                "raw": {"matched": "no" if hardened else "yes"},
                "reason": "collected by test",
                "collected_monotonic": 0.0,
                "collected_wall_claim": 0.0,
            },
        ],
        "created_wall_claim": 0.0,
        "schema_version": 1,
    }


def _signed_checkin(engine, priv, body):
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", engine.port, timeout=30)
    try:
        conn.request(
            "POST", "/checkin", body=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-HUITZILOPOCHTLI-Sig": base64.b64encode(
                    signing.sign(priv, canon.canonicalize(body))).decode("ascii"),
            },
        )
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode("utf-8"))
    finally:
        conn.close()


# --------------------------------------------------------------------------
# 1: engine restart -- boxes, scores, seq, T0 survive; the box resumes
# --------------------------------------------------------------------------

def test_engine_restart_persistence_and_box_resume(tmp_path):
    port = lb._free_port()
    engine = lb._EngineProc(tmp_path, port=port)
    try:
        name = "resilient-restart"
        engine.upload_scenario(lb._base_rubric(name, [
            {"check_id": "backdoor-absent", "category": "vuln",
             "matcher": {"tag": "equals", "field": "matched", "value": "no"},
             "points": 10},
        ]))
        token = engine.mint_token(name)
        priv, _, body = _enroll(engine, token, name, 1, "resilient-box-1")
        status, parsed = _signed_checkin(
            engine, priv, _checkin_body("resilient-box-1", 1, name,
                                        hardened=True))
        assert status == 200, parsed
    finally:
        engine.stop()

    # Restart on the SAME port + db file.
    engine2 = lb._EngineProc(tmp_path, port=port)
    try:
        # Scores survive.
        rows = engine2.leaderboard(name)
        assert len(rows) == 1 and rows[0]["total"] == 10, rows

        # Box row survives intact: seq and T0 are engine state, not rebuilt.
        conn = sqlite3.connect(engine2.db_path)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT last_seq, t0, scenario_name FROM boxes "
                "WHERE box_id = 'resilient-box-1'").fetchone()
        finally:
            conn.close()
        assert row is not None
        assert row["last_seq"] == 1
        assert row["t0"] is not None
        assert row["scenario_name"] == name

        # The box resumes checking in against the restarted engine: seq 2 is
        # accepted (not a phantom re-enroll, not a replay rejection), and the
        # score carries forward on top of the restored state.
        status, parsed = _signed_checkin(
            engine2, priv, _checkin_body("resilient-box-1", 2, name,
                                         hardened=True))
        assert status == 200, parsed
        assert parsed["last_seq"] == 2
        assert parsed["score"]["total"] == 10
    finally:
        engine2.stop()


# --------------------------------------------------------------------------
# 2: verify-gate saturation -- concurrent check-ins see 503, then land on
#    retry; leaderboard orders scores and breaks ties deterministically
# --------------------------------------------------------------------------

def test_verify_gate_503_backpressure_and_multi_box_concurrency(tmp_path):
    engine = lb._EngineProc(
        tmp_path, env_extra={"HUITZILOPOCHTLI_MAX_VERIFY": "1"})
    try:
        name = "resilient-volley"
        engine.upload_scenario(lb._base_rubric(name, [
            {"check_id": "backdoor-absent", "category": "vuln",
             "matcher": {"tag": "equals", "field": "matched", "value": "no"},
             "points": 10},
        ]))

        # Four boxes: three hardened at 10 points, one unhardened at 0 --
        # enough shape to assert ordering + tie-breaking on the leaderboard.
        boxes = {}
        for box_id, hardened in [("box-a", True), ("box-b", True),
                                 ("box-c", True), ("box-d", False)]:
            priv, _, _ = _enroll(engine, engine.mint_token(name), name, 1,
                                 box_id)
            body = _checkin_body(box_id, 1, name, hardened)
            # Pre-sign BEFORE the barrier: signing is pure-Python Ed25519 and
            # holds the GIL, so signing inside the volley would serialize the
            # arrivals ~1 verify apart and never saturate the gate.
            presigned = (
                canon.canonicalize(body),
                signing.sign(priv, canon.canonicalize(body)),
            )
            boxes[box_id] = (priv, hardened, presigned)

        # Fire all four first check-ins as simultaneously as threads allow.
        results = {}
        barrier = threading.Barrier(len(boxes), timeout=30)

        def volley(box_id):
            _, _, (canonical, sig_b64) = boxes[box_id]
            barrier.wait()
            import http.client
            conn = http.client.HTTPConnection("127.0.0.1", engine.port,
                                              timeout=30)
            try:
                conn.request(
                    "POST", "/checkin", body=canonical,
                    headers={
                        "Content-Type": "application/json",
                        "X-HUITZILOPOCHTLI-Sig": base64.b64encode(
                            sig_b64).decode("ascii"),
                    },
                )
                resp = conn.getresponse()
                parsed = json.loads(resp.read().decode("utf-8"))
            finally:
                conn.close()
            results[box_id] = (resp.status, parsed)

        threads = [threading.Thread(target=volley, args=(b,)) for b in boxes]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert len(results) == 4, results

        # With one verify slot and ~1.8s verifies, at least one of the four
        # simultaneous arrivals must have been told to retry.
        statuses = [r[0] for r in results.values()]
        assert 503 in statuses, (
            f"expected the saturated verify gate to 503 at least one "
            f"concurrent check-in, got {statuses}"
        )

        # Every 503'd box retries (the agent's documented behavior on 503)
        # and lands: nothing is lost to backpressure.
        for box_id in list(results):
            status, parsed = results[box_id]
            attempts = 0
            while status == 503:
                attempts += 1
                assert attempts <= 10, f"{box_id} never got past the gate"
                time.sleep(_VERIFY_TIME_S)
                priv, hardened, _ = boxes[box_id]
                body = _checkin_body(box_id, 1 + attempts, name, hardened)
                status, parsed = _signed_checkin(engine, priv, body)
            assert status == 200, (box_id, parsed)
            results[box_id] = (status, parsed)

        rows = engine.leaderboard(name)
        assert len(rows) == 4, rows
        by_box = {r["box_id"]: r for r in rows}

        # Scores are correct per box: hardened boxes hold 10, the unhardened
        # box holds 0.
        assert by_box["box-a"]["total"] == 10
        assert by_box["box-b"]["total"] == 10
        assert by_box["box-c"]["total"] == 10
        assert by_box["box-d"]["total"] == 0

        # Ordering: 10s above the 0; the tie between the three 10s is broken
        # by first-confirmed (updated_at asc, then box_id) -- deterministic,
        # not arbitrary.
        assert [r["box_id"] for r in rows][-1] == "box-d"
        tens = [r["box_id"] for r in rows if r["total"] == 10]
        assert len(tens) == 3
        first_confirmed = min(
            tens, key=lambda b: by_box[b]["updated_at"])
        assert rows[0]["box_id"] == first_confirmed
    finally:
        engine.stop()


# --------------------------------------------------------------------------
# 3: enrollment-token race -- exactly one concurrent enrollment wins
# --------------------------------------------------------------------------

def test_concurrent_enroll_single_token_exactly_one_winner(tmp_path):
    engine = lb._EngineProc(tmp_path)
    try:
        name = "resilient-race"
        engine.upload_scenario(lb._base_rubric(name, [
            {"check_id": "backdoor-absent", "category": "vuln",
             "matcher": {"tag": "equals", "field": "matched", "value": "no"},
             "points": 10},
        ]))
        token = engine.mint_token(name)

        n = 5
        outcomes = {}
        _bodies = {}
        _sigs = {}
        barrier = threading.Barrier(n, timeout=60)

        def racer(i):
            priv, pub = signing.keypair()
            box_id = f"race-box-{i}"
            body = {
                "enrollment_token": token,
                "box_id": box_id,
                "public_key": base64.b64encode(pub).decode("ascii"),
                "agent_version": AGENT_VERSION,
                "scenario_name": name,
                "scenario_version": 1,
            }
            _bodies[box_id] = body
            _sigs[box_id] = base64.b64encode(
                signing.sign(priv, canon.canonicalize(body))).decode("ascii")
            barrier.wait()
            outcomes[box_id] = lb._http_json(
                f"{engine.base_url}/enroll", body,
                headers={
                    "Content-Type": "application/json",
                    "X-HUITZILOPOCHTLI-Sig": _sigs[box_id],
                },
                method="POST", timeout=30,
            )

        threads = [threading.Thread(target=racer, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
        assert len(outcomes) == n

        # The volley can also saturate the verify gate (default 4 slots, n=5
        # racers): a 503 means "retry", so model the agent and retry each
        # backpressured enrollment before judging the outcome.
        for box_id in list(outcomes):
            status, body = outcomes[box_id]
            attempts = 0
            while status == 503:
                attempts += 1
                assert attempts <= 10, f"{box_id} never got past the gate"
                time.sleep(1.8)
                outcomes[box_id] = lb._http_json(
                    f"{engine.base_url}/enroll", _bodies[box_id],
                    headers={
                        "Content-Type": "application/json",
                        "X-HUITZILOPOCHTLI-Sig": _sigs[box_id],
                    },
                    method="POST", timeout=30,
                )
                status, body = outcomes[box_id]

        winners = [b for b, (status, _) in outcomes.items() if status == 200]
        losers = {b: (status, body) for b, (status, body) in outcomes.items()
                  if status != 200}
        assert len(winners) == 1, (
            f"token race produced {len(winners)} winners: {outcomes}"
        )
        # Every loser lost to the same atomic consume: 409, not a 500 and
        # not a silent success.
        for b, (status, body) in losers.items():
            assert status == 409, (b, status, body)
            assert "consumed" in body["error"]

        # Exactly one box row exists for the token's scenario.
        rows = engine.leaderboard(name)
        assert rows == []  # nobody has checked in yet
        conn = sqlite3.connect(engine.db_path)
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM boxes WHERE scenario_name = ?",
                (name,)).fetchone()[0]
        finally:
            conn.close()
        assert count == 1, count
    finally:
        engine.stop()
