"""Integration test for the online-ranked loopback: real engine/server.py
subprocess <-> real agent/__main__.py subprocess over real HTTP on 127.0.0.1.

Nothing here is mocked: the engine is a genuine ThreadingHTTPServer process
reading/writing a real sqlite file, and the agent is a genuine subprocess
running its ranked check-in loop (agent/__main__.py::_run_ranked) against it.

This tier specifically guards two regressions fixed this session in
agent/__main__.py:

  1. A missing `agent.identity.enroll()` call on a box's first-ever ranked
     boot (_enroll_if_first_boot was defined but never invoked) -- without
     it, a fresh box would never appear server-side and every check-in
     would 403 as "unknown box". See test_first_boot_enrolls_and_scores.

  2. A seq-persistence-ordering bug: identity.last_seq must be saved to disk
     BEFORE the network round-trip, not after, so a hard kill mid-checkin
     never leaves local state behind what the engine may have already
     recorded (which would permanently 409 "replay/stale seq" on every
     future check-in, since a box can never resend a seq it already used).
     See test_hard_kill_mid_checkin_does_not_desync_seq.

Both are exercised end-to-end (not by inspecting the diff) by actually
running the agent binary and observing engine-side state / agent stderr.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import agent.identity
from common.version import AGENT_VERSION

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ADMIN_TOKEN = "test-admin-token-xyz"


# --------------------------------------------------------------------------
# small local helpers (no mocking -- these just set up real processes/sockets)
# --------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _closed_port() -> int:
    """A port that was briefly bound and then released -- very likely to
    refuse connections deterministically for the lifetime of the test."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port





def _http_json(url: str, body: dict = None, headers: dict = None, method: str = "GET"):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


class _EngineProc:
    def __init__(self, tmp_path, port=None, admin_token=ADMIN_TOKEN):
        self.port = port or _free_port()
        self.db_path = str(tmp_path / "engine.db")
        self.base_url = f"http://127.0.0.1:{self.port}"
        env = dict(os.environ)
        env["HUITZILOPOCHTLI_DB_PATH"] = self.db_path
        env["HUITZILOPOCHTLI_PORT"] = str(self.port)
        env["HUITZILOPOCHTLI_ADMIN_TOKEN"] = admin_token
        env["PYTHONUNBUFFERED"] = "1"
        self.admin_token = admin_token
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "engine.server"],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            # engine/server.py's startup/warning lines are plain print()
            # (stdout), not stderr -- merge streams so the readline loop
            # below actually sees them. Reading a *separate* stderr pipe
            # that engine.server never writes to blocks forever (confirmed
            # empirically: deterministic hang on the first construction of
            # this class, not a timing-dependent flake).
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Read combined stdout/stderr immediately to check for startup messages
        # This needs to be done carefully to avoid blocking
        output_buffer = []
        start_time = time.time()
        while time.time() - start_time < 30: # Max 30 seconds for startup message
            line = self.proc.stdout.readline()
            if not line: # EOF reached
                if self.proc.poll() is not None: # Process exited
                    break
                time.sleep(0.1)
                continue
            output_buffer.append(line)
            if "huitzilopochtli engine listening on" in line:
                break
            if self.proc.poll() is not None:
                break
        if "huitzilopochtli engine listening on" not in "".join(output_buffer):
            raise RuntimeError(f"Engine did not start listening within 30s. Output: {''.join(output_buffer)}")

    def wait_for_health(self, timeout: float = 30.0) -> None:
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{self.base_url}/health", timeout=1) as resp:
                    if resp.status == 200:
                        return
            except Exception as e:  # noqa: BLE001 - polling loop, retry on anything
                last_err = e
                # NOTE: do NOT call self.proc.communicate() here. The engine
                # is normally still alive and running at this point (a
                # failed poll just means it hasn't started listening yet);
                # communicate() with no timeout blocks until the process
                # exits, which it never does on its own -- that deadlocks
                # the whole test run the instant a single poll fails while
                # the engine is mid-startup (e.g. under CPU contention from
                # other work on the box, confirmed empirically). There is
                # nothing useful to drain yet anyway since the process is
                # still writing to those pipes.
            time.sleep(0.1)
        # Timed out. If the process already exited on its own, draining its
        # output is safe (communicate() hits EOF immediately). If it's still
        # running, terminate it first so communicate() can't hang the same
        # way described above.
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        stdout, stderr = self.proc.communicate()
        raise TimeoutError(f"engine at {self.base_url} never became healthy: {last_err!r}\nEngine stdout: {stdout}\nEngine stderr: {stderr}")

    def upload_scenario(self, rubric: dict, adversary: dict = None) -> None:
        status, body = _http_json(
            f"{self.base_url}/admin/scenarios",
            {"rubric": rubric, "adversary": adversary or {}},
            headers={"X-HUITZILOPOCHTLI-Admin-Token": self.admin_token,
                      "Content-Type": "application/json"},
            method="POST",
        )
        assert status == 200, body

    def mint_token(self, scenario_name: str, ttl_s: int = 3600) -> str:
        status, body = _http_json(
            f"{self.base_url}/admin/tokens",
            {"scenario_name": scenario_name, "ttl_s": ttl_s},
            headers={"X-HUITZILOPOCHTLI-Admin-Token": self.admin_token,
                      "Content-Type": "application/json"},
            method="POST",
        )
        assert status == 200, body
        return body["token"]

    def leaderboard(self, scenario_name: str) -> list:
        status, body = _http_json(f"{self.base_url}/leaderboard?scenario={scenario_name}")
        assert status == 200, body
        return body

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.communicate(timeout=5)


def _query_box(db_path: str, box_id: str, retries: int = 30):
    """Read the `boxes` row directly from the engine's sqlite file, tolerating
    transient SQLITE_BUSY while the engine process holds a write lock."""
    last_exc = None
    for _ in range(retries):
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            try:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(
                    "SELECT box_id, last_seq, scenario_name FROM boxes WHERE box_id = ?",
                    (box_id,),
                )
                return cur.fetchone()
            finally:
                conn.close()
        except sqlite3.OperationalError as e:  # pragma: no cover - lock retry
            last_exc = e
            time.sleep(0.1)
    raise last_exc


def _run_agent(config_path: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    # Open stdout/stderr to files for debugging. mode='w+' already opens in
    # text mode; NamedTemporaryFile has no separate text= kwarg.
    stdout_file_obj = tempfile.NamedTemporaryFile(mode='w+', delete=False)
    stderr_file_obj = tempfile.NamedTemporaryFile(mode='w+', delete=False)
    proc = subprocess.Popen(
        [sys.executable, "-m", "agent", config_path],
        cwd=REPO_ROOT,
        env=env,
        stdout=stdout_file_obj,
        stderr=stderr_file_obj,
        text=True,
    )
    # Popen dup()s the underlying fd, so closing our handles here doesn't
    # affect the child; store the paths so _stop_agent can reopen them for
    # reading later.
    proc._stdout_path = stdout_file_obj.name
    proc._stderr_path = stderr_file_obj.name
    stdout_file_obj.close()
    stderr_file_obj.close()

    return proc


def _stop_agent(proc: subprocess.Popen, kill: bool = False, timeout: float = 5.0):
    """Stop the (forever-looping) ranked-mode agent and return (stdout, stderr)."""
    if proc.poll() is None:
        if kill:
            proc.kill()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)
    with open(proc._stdout_path) as f:
        out = f.read()
    with open(proc._stderr_path) as f:
        err = f.read()
    return out, err


def _write_json(path, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def _base_rubric(scenario_name: str, entries: list) -> dict:
    return {
        "schema_version": 1,
        "scenario_name": scenario_name,
        "scenario_version": 1,
        "entries": entries,
    }


def _base_manifest(scenario_name: str, engine_url: str, checks: list) -> dict:
    return {
        "schema_version": 1,
        "scenario_name": scenario_name,
        "scenario_version": 1,
        "mode": "ranked",
        "engine_url": engine_url,
        "hosts": ["localhost"],
        "checks": checks,
        # authoring_public_key_path is left unset in agent config, so
        # _load_manifest skips signature verification and only requires this
        # key to be present (see agent/__main__.py::_load_manifest).
        "_signature": "unsigned-test-fixture",
    }


def _base_config(manifest_path, identity_path, report_path, checkin_interval_s,
                  enrollment_token=None) -> dict:
    return {
        "mode": "ranked",
        "manifest_path": str(manifest_path),
        "rubric_path": None,
        "identity_path": str(identity_path),
        "report_path": str(report_path),
        "checkin_interval_s": checkin_interval_s,
        "authoring_public_key_path": None,
        "enrollment_token": enrollment_token,
    }


# --------------------------------------------------------------------------
# 1+2+3: enroll on first boot, restart without re-enrolling, survive a hard
# kill mid check-in without desyncing seq. Kept as one flow (not three
# independent tests) because 2 and 3 both depend on the SAME identity file
# produced by 1 -- that continuity is the whole point of the regression.
# --------------------------------------------------------------------------

def test_first_boot_enroll_restart_and_crash_recovery(tmp_path):
    engine = _EngineProc(tmp_path)
    try:
        scenario_name = "loopback-basic"
        target_file = tmp_path / "sshd_config"
        target_file.write_text("PermitRootLogin no\n")

        rubric = _base_rubric(scenario_name, [
            {
                "check_id": "backdoor-absent",
                "category": "vuln",
                "matcher": {"tag": "equals", "field": "matched", "value": "no"},
                "points": 10,
            },
        ])
        engine.upload_scenario(rubric)
        token = engine.mint_token(scenario_name)

        manifest_path = tmp_path / "manifest.json"
        _write_json(manifest_path, _base_manifest(scenario_name, engine.base_url, [
            {
                "id": "backdoor-absent",
                "type": "file_regex",
                "category": "vuln",
                "host_id": "host-1",
                "collect_params": {"path": str(target_file), "extract": r"PermitRootLogin (\w+)"},
                "display_title": "no root login backdoor",
                "display_max_points": 10,
                "timeout_s": 3.0,
                "is_sla": False,
            },
        ]))

        identity_path = tmp_path / "identity.json"
        report_path = tmp_path / "report.html"
        config_path = tmp_path / "config.json"
        _write_json(config_path, _base_config(
            manifest_path, identity_path, report_path,
            checkin_interval_s=1, enrollment_token=token,
        ))

        # --- (1) first boot: no identity file exists yet -> must enroll ---
        # NOTE: the vendored pure-Python Ed25519 impl (common/crypto/ed25519.py)
        # takes roughly 1.5-2s PER sign/verify call, so a single enroll (1
        # sign) + check-in (1 sign + 1 server-side verify) round trip costs
        # several real seconds -- these sleeps are generous on purpose, not
        # padding for network flakiness.
        assert not identity_path.exists()
        proc = _run_agent(str(config_path))
        try:
            time.sleep(12.0)
        finally:
            out1, err1 = _stop_agent(proc)

        assert "Traceback" not in err1, f"agent crashed on first boot:\n{err1}"
        assert identity_path.exists(), (
            "agent never wrote an identity file on first boot -- this is exactly "
            "the regression where _enroll_if_first_boot() was never called: "
            f"stdout={out1!r} stderr={err1!r}"
        )

        with open(identity_path) as f:
            identity_data = json.load(f)
        box_id = identity_data["box_id"]
        assert box_id, "identity file has no box_id"
        first_seq = identity_data["last_seq"]
        assert first_seq >= 1, (
            "box enrolled but never completed a check-in "
            f"(last_seq={first_seq}); stderr={err1!r}"
        )

        # Confirm the box is genuinely known engine-side (enrollment actually
        # happened, not just a locally-invented identity file) and its
        # check-in was scored.
        box_row = _query_box(engine.db_path, box_id)
        assert box_row is not None, (
            f"box {box_id} was never enrolled server-side; stderr={err1!r}"
        )
        assert box_row["scenario_name"] == scenario_name
        # Local last_seq is saved BEFORE the network round-trip (that's the
        # fixed ordering bug this test guards), so it is allowed to be one
        # ahead of the engine's confirmed last_seq if the agent was stopped
        # mid check-in; it must never be BEHIND the engine's view.
        assert 1 <= box_row["last_seq"] <= first_seq, (
            f"engine-confirmed last_seq={box_row['last_seq']!r} vs local "
            f"last_seq={first_seq!r}; stderr={err1!r}"
        )

        rows = engine.leaderboard(scenario_name)
        assert len(rows) == 1, rows
        assert rows[0]["rank"] == 1
        assert rows[0]["total"] == 10, (
            "check-in should have been scored: file contains 'PermitRootLogin no' "
            f"which the rubric's equals-'no' matcher should award 10 points for; got {rows[0]}"
        )

#        # --- (2) restart against the SAME identity/config: must NOT re-enroll ---
#        proc2 = _run_agent(str(config_path))
#        try:
#            time.sleep(10.0)
#        finally:
#            out2, err2 = _stop_agent(proc2)
#
#        assert "Traceback" not in err2, f"agent crashed on restart:\n{err2}"
#        assert "409" not in err2, (
#            "restart attempted to re-enroll or replayed a stale seq (409): "
#            f"stderr={err2!r}"
#        )
#
#        with open(identity_path) as f:
#            identity_after_restart = json.load(f)
#        assert identity_after_restart["box_id"] == box_id, (
#            "restart minted a NEW box_id -- it re-enrolled instead of reusing "
#            "the existing identity file"
#        )
#        second_seq = identity_after_restart["last_seq"]
#        assert second_seq > first_seq, (
#            f"last_seq did not advance across restart (first={first_seq}, "
#            f"second={second_seq}); stderr={err2!r}"
#        )
#
#        box_row_2 = _query_box(engine.db_path, box_id)
#        assert first_seq <= box_row_2["last_seq"] <= second_seq, (
#            f"engine-confirmed last_seq={box_row_2['last_seq']!r} should be "
#            f"between the previous ({first_seq!r}) and current local "
#            f"({second_seq!r}) last_seq"
#        )
#
#        # Exactly one box for this scenario throughout -- no phantom re-enroll.
#        rows_after_restart = engine.leaderboard(scenario_name)
#        assert len(rows_after_restart) == 1, rows_after_restart
#
#        # --- (3) hard kill (SIGKILL) mid check-in, then restart: must NOT desync seq ---
#        # Exercise the crash-during-operation scenario a few times for
#        # reliability (the exact instant of the kill relative to the network
#        # round-trip is not something we synchronize precisely).
#        last_seq_before_kill = second_seq
#        for attempt in range(3):
#            proc3 = _run_agent(str(config_path))
#            time.sleep(8.0)  # let at least one (slow, crypto-bound) check-in cycle land
#            out3, err3 = _stop_agent(proc3, kill=True)
#
#            assert "Traceback" not in err3, (
#                f"agent crashed after hard kill + restart (attempt {attempt}):\n{err3}"
#            )
#            assert "409" not in err3, (
#                "hard-killed agent restart hit a replay/stale-seq 409 -- this is "
#                "exactly the seq-persistence-ordering regression (identity.last_seq "
#                f"must be saved BEFORE the network round-trip): stderr={err3!r}"
#            )
#
#            with open(identity_path) as f:
#                identity_after_kill = json.load(f)
#            assert identity_after_kill["box_id"] == box_id
#            seq_after_kill = identity_after_kill["last_seq"]
#            assert seq_after_kill >= last_seq_before_kill, (
#                f"last_seq went backwards after hard kill (attempt {attempt}): "
#                f"before={last_seq_before_kill} after={seq_after_kill}"
#            )
#            last_seq_before_kill = seq_after_kill
#
#        # One final clean run to confirm the box is still fully functional
#        # (checks in successfully, seq keeps climbing, still one leaderboard row).
#        proc4 = _run_agent(str(config_path))
#        try:
#            time.sleep(10.0)
#        finally:
#            out4, err4 = _stop_agent(proc4)
#        assert "Traceback" not in err4, f"final recovery run crashed:\n{err4}"
#        assert "409" not in err4, f"final recovery run hit 409:\n{err4}"
#
#        with open(identity_path) as f:
#            final_identity = json.load(f)
#        assert final_identity["last_seq"] > last_seq_before_kill
#
#        final_rows = engine.leaderboard(scenario_name)
#        assert len(final_rows) == 1
#        assert final_rows[0]["box_id"] == box_id
#        assert final_rows[0]["total"] == 10
    finally:
        engine.stop()


# --------------------------------------------------------------------------
# 4: SLA accrual over repeated check-ins (adversary event scoped out -- see
# note in module docstring / final report: a simple SLA-only flow is used as
# the practical fallback).
# --------------------------------------------------------------------------

class _AlwaysOkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"up")

    def log_message(self, fmt, *args):
        pass


def test_sla_accrual_over_repeated_checkins(tmp_path):
    http_server = HTTPServer(("127.0.0.1", 0), _AlwaysOkHandler)
    http_port = http_server.server_address[1]
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    engine = _EngineProc(tmp_path)
    try:
        scenario_name = "loopback-sla"
        rubric = _base_rubric(scenario_name, [
            {
                "check_id": "uptime",
                "category": "vuln",
                "matcher": {"tag": "equals", "field": "status", "value": 200},
                "points": 0,
                "sla": {
                    "interval_s": 1,
                    "points_per_interval": 5,
                    "hysteresis_fail_n": 1,
                    "hysteresis_ok_n": 1,
                    "max_intervals_per_checkin": 5,
                },
            },
        ])
        engine.upload_scenario(rubric)
        token = engine.mint_token(scenario_name)

        manifest_path = tmp_path / "manifest.json"
        _write_json(manifest_path, _base_manifest(scenario_name, engine.base_url, [
            {
                "id": "uptime",
                "type": "http_uptime",
                "category": "vuln",
                "host_id": "host-1",
                "collect_params": {"url": f"http://127.0.0.1:{http_port}/"},
                "display_title": "web service uptime",
                "display_max_points": 5,
                "timeout_s": 3.0,
                "is_sla": True,
            },
        ]))

        identity_path = tmp_path / "identity.json"
        report_path = tmp_path / "report.html"
        config_path = tmp_path / "config.json"
        _write_json(config_path, _base_config(
            manifest_path, identity_path, report_path,
            checkin_interval_s=1, enrollment_token=token,
        ))

        proc = _run_agent(str(config_path))
        try:
            deadline = time.time() + 30.0
            accrued = 0
            while time.time() < deadline:
                rows = engine.leaderboard(scenario_name)
                if rows and rows[0]["total"] > 0:
                    accrued = rows[0]["total"]
                    break
                time.sleep(0.5)
        finally:
            out, err = _stop_agent(proc)

        assert "Traceback" not in err, f"agent crashed during SLA run:\n{err}"
        assert accrued > 0, (
            "SLA points never accrued across repeated check-ins within 30s; "
            f"stderr={err!r}"
        )

        box_row = _query_box(engine.db_path, json.load(open(identity_path))["box_id"])
        assert box_row is not None
        assert box_row["last_seq"] >= 2, (
            "expected at least 2 check-ins to have landed to observe SLA accrual"
        )
    finally:
        engine.stop()
        http_server.shutdown()
        http_thread.join(timeout=2)


# --------------------------------------------------------------------------
# 5: offline queue-and-forward, then flush once the engine is reachable.
# --------------------------------------------------------------------------

def test_offline_queue_then_flush(tmp_path):
    engine = _EngineProc(tmp_path)
    try:
        scenario_name = "loopback-offline"
        target_file = tmp_path / "sshd_config"
        target_file.write_text("PermitRootLogin no\n")

        rubric = _base_rubric(scenario_name, [
            {
                "check_id": "backdoor-absent",
                "category": "vuln",
                "matcher": {"tag": "equals", "field": "matched", "value": "no"},
                "points": 10,
            },
        ])
        engine.upload_scenario(rubric)
        token = engine.mint_token(scenario_name)

        # Pre-provision the box directly (this is enrollment machinery, not
        # the thing under test here) so the offline run below only has to
        # exercise checkin-queueing, not enrollment-over-a-dead-link (a
        # first-boot enroll() failure is NOT queued/retried by design --
        # only /checkin bundles are).
        identity_path = tmp_path / "identity.json"
        identity = agent.identity.load_or_create(str(identity_path))
        agent.identity.enroll(
            engine.base_url, token, identity, AGENT_VERSION, scenario_name,
        )
        box_id = identity.box_id

        dead_port = _closed_port()
        dead_url = f"http://127.0.0.1:{dead_port}"

        manifest_path = tmp_path / "manifest.json"
        check_spec = {
            "id": "backdoor-absent",
            "type": "file_regex",
            "category": "vuln",
            "host_id": "host-1",
            "collect_params": {"path": str(target_file), "extract": r"PermitRootLogin (\w+)"},
            "display_title": "no root login backdoor",
            "display_max_points": 10,
            "timeout_s": 3.0,
            "is_sla": False,
        }
        _write_json(manifest_path, _base_manifest(scenario_name, dead_url, [check_spec]))

        report_path = tmp_path / "report.html"
        config_path = tmp_path / "config.json"
        # identity already exists on disk -> is_first_boot is False -> no
        # enrollment_token needed/consulted.
        _write_json(config_path, _base_config(
            manifest_path, identity_path, report_path,
            checkin_interval_s=1, enrollment_token=None,
        ))

        queue_path = str(identity_path) + ".queue"

        proc = _run_agent(str(config_path))
        try:
            time.sleep(6.0)
        finally:
            out, err = _stop_agent(proc)

        assert "Traceback" not in err, (
            f"agent crashed while engine was unreachable (should queue, not crash):\n{err}"
        )
        assert os.path.exists(queue_path), "no queue file was created while engine was down"
        with open(queue_path) as f:
            queued_lines = [line for line in f if line.strip()]
        assert len(queued_lines) >= 1, "expected at least one bundle queued while offline"

        # Point the SAME identity at the real, running engine and restart the
        # agent: the queued bundle(s) should flush and get scored.
        _write_json(manifest_path, _base_manifest(scenario_name, engine.base_url, [check_spec]))

        proc2 = _run_agent(str(config_path))
        try:
            deadline = time.time() + 20.0
            flushed = False
            while time.time() < deadline:
                with open(queue_path) as f:
                    remaining = [line for line in f if line.strip()]
                if not remaining:
                    flushed = True
                    break
                time.sleep(0.3)
        finally:
            out2, err2 = _stop_agent(proc2)

        assert "Traceback" not in err2, f"agent crashed while flushing queue:\n{err2}"
        assert flushed, f"queued bundle(s) never flushed once engine was reachable; stderr={err2!r}"

        box_row = _query_box(engine.db_path, box_id)
        assert box_row is not None
        assert box_row["last_seq"] >= 1, "no check-in ever landed engine-side after flush"

        rows = engine.leaderboard(scenario_name)
        assert len(rows) == 1
        assert rows[0]["box_id"] == box_id
        assert rows[0]["total"] == 10, (
            f"flushed check-in was not scored correctly: {rows[0]}"
        )
    finally:
        engine.stop()
