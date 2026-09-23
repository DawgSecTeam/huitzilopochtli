"""Adversary + SLA end-to-end over the real wire: a real agent subprocess
runs its ranked loop against a real engine with an adversary pool, and we
observe the full §12 chain engine-side (adversary_log) and box-side (the
directive's effect on disk, deduped across resends and restarts), plus the
§11.3 SLA DOWN transition when the monitored service actually dies.

Safety: the only adversary action exercised live is drop_inert_artifact,
sandboxed via HUITZILOPOCHTLI_ARTIFACT_DIR into the test's tmp dir. The
host-mutating actions (flush_firewall, kill_service) are covered by unit
tests only -- they must never run against the dev host.
"""
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import test_ranked_loopback as lb

SLA = {
    "interval_s": 1,
    "points_per_interval": 2,
    "hysteresis_fail_n": 1,
    "hysteresis_ok_n": 1,
    "max_intervals_per_checkin": 5,
}


class _AlwaysOkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"up")

    def log_message(self, fmt, *args):
        pass


def _sla_rubric(scenario_name):
    return lb._base_rubric(scenario_name, [
        {
            "check_id": "uptime",
            "category": "vuln",
            "matcher": {"tag": "equals", "field": "status", "value": 200},
            "points": 0,
            "sla": dict(SLA),
        },
    ])


def _sla_manifest(scenario_name, engine_url, uptime_port):
    return lb._base_manifest(scenario_name, engine_url, [
        {
            "id": "uptime",
            "type": "http_uptime",
            "category": "vuln",
            "host_id": "host-1",
            "collect_params": {"url": f"http://127.0.0.1:{uptime_port}/"},
            "display_title": "web service uptime",
            "display_max_points": 5,
            "timeout_s": 3.0,
            "is_sla": True,
        },
    ])


def _box_id_when_known(identity_path, deadline_s=15.0):
    """The agent subprocess writes identity.json shortly after boot; tolerate
    polling that starts before it exists."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            with open(identity_path) as f:
                return json.load(f)["box_id"]
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            time.sleep(0.3)
    raise AssertionError(f"identity file never appeared at {identity_path}")


def _sla_state(db_path, box_id):
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT state, accrued_points FROM sla_state WHERE box_id = ?",
            (box_id,)).fetchone()
    finally:
        conn.close()


def _adversary_rows(db_path, box_id):
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT event_id, action FROM adversary_log WHERE box_id = ?",
            (box_id,)).fetchall()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# 1: directive delivery -> execution -> dedup across resends and restarts
# --------------------------------------------------------------------------

def test_directive_fires_executes_once_and_survives_restart(tmp_path):
    engine = lb._EngineProc(
        tmp_path, env_extra={"HUITZILOPOCHTLI_CHECKIN_INTERVAL_S": "2"})
    try:
        name = "adv-e2e"
        engine.upload_scenario(
            lb._base_rubric(name, [
                {"check_id": "backdoor-absent", "category": "vuln",
                 "matcher": {"tag": "equals", "field": "matched",
                             "value": "no"},
                 "points": 10},
            ]),
            adversary={
                "events": [
                    {
                        "id": "ev-marker",
                        "action": "drop_inert_artifact",
                        "params": {"path": "marker-e2e.txt"},
                        "window_s": [0.5, 2.0],
                    },
                ],
            },
        )
        token = engine.mint_token(name)

        target_file = tmp_path / "sshd_config"
        target_file.write_text("PermitRootLogin no\n")
        manifest_path = tmp_path / "manifest.json"
        lb._write_json(manifest_path, lb._base_manifest(name, engine.base_url, [
            {
                "id": "backdoor-absent",
                "type": "file_regex",
                "category": "vuln",
                "host_id": "host-1",
                "collect_params": {"path": str(target_file),
                                   "extract": r"PermitRootLogin (\w+)"},
                "display_title": "no root login backdoor",
                "display_max_points": 10,
                "timeout_s": 3.0,
                "is_sla": False,
            },
        ]))

        identity_path = tmp_path / "identity.json"
        config_path = tmp_path / "config.json"
        lb._write_json(config_path, lb._base_config(
            manifest_path, identity_path, tmp_path / "report.html",
            checkin_interval_s=1, enrollment_token=token))

        adv_dir = tmp_path / "adv"
        marker = adv_dir / "marker-e2e.txt"

        # Run the agent until the directive's effect lands on disk: the fire
        # window is [t0+0.5, t0+2.0] and each check-in cycle costs a few
        # seconds of Ed25519, so give the poll generous room.
        proc = lb._run_agent(str(config_path), env_extra={
            "HUITZILOPOCHTLI_ARTIFACT_DIR": str(adv_dir)})
        try:
            deadline = time.time() + 30.0
            while time.time() < deadline and not marker.exists():
                time.sleep(0.5)
        finally:
            out, err = lb._stop_agent(proc)

        assert "Traceback" not in err, f"agent crashed:\n{err}"
        assert marker.exists(), (
            f"directive never executed: no marker at {marker}; "
            f"stderr={err!r}"
        )
        assert marker.read_text().startswith("HUITZILOPOCHTLI adversary marker")

        # Engine side: issued exactly once.
        with open(identity_path) as f:
            box_id = json.load(f)["box_id"]
        rows = _adversary_rows(engine.db_path, box_id)
        assert [r["event_id"] for r in rows] == ["ev-marker"], rows
        assert rows[0]["action"] == "drop_inert_artifact"

        # The agent recorded the execution (identity.json.directives).
        record_path = str(identity_path) + ".directives"
        with open(record_path) as f:
            assert json.load(f) == ["ev-marker"]

        # At-most-once despite issued_directives resending every cycle:
        # keep the agent running two more cycles and the marker must be
        # untouched (same inode + content, not rewritten).
        st_before = marker.stat()

        def marker_untouched():
            st = marker.stat()
            return (st.st_ino, st.st_mtime_ns) == (st_before.st_ino,
                                                   st_before.st_mtime_ns)

        proc = lb._run_agent(str(config_path), env_extra={
            "HUITZILOPOCHTLI_ARTIFACT_DIR": str(adv_dir)})
        try:
            deadline = time.time() + 12.0  # ~2 crypto-bound cycles
            while time.time() < deadline:
                assert marker_untouched(), (
                    "agent re-executed an already-run directive on a resend"
                )
                time.sleep(0.5)
        finally:
            out2, err2 = lb._stop_agent(proc)
        assert "Traceback" not in err2, f"agent crashed on resend run:\n{err2}"

        # And again after a full agent restart: executed-directives state
        # persists adjacent to the identity, so the directive still runs
        # exactly once in the box's lifetime.
        proc = lb._run_agent(str(config_path), env_extra={
            "HUITZILOPOCHTLI_ARTIFACT_DIR": str(adv_dir)})
        try:
            deadline = time.time() + 12.0
            while time.time() < deadline:
                assert marker_untouched(), (
                    "restarted agent re-executed an already-run directive"
                )
                time.sleep(0.5)
        finally:
            out3, err3 = lb._stop_agent(proc)
        assert "Traceback" not in err3, f"agent crashed after restart:\n{err3}"
        with open(record_path) as f:
            assert json.load(f) == ["ev-marker"]
    finally:
        engine.stop()


# --------------------------------------------------------------------------
# 2: the service the SLA watches actually dies -> DOWN, accrual freezes
# --------------------------------------------------------------------------

def test_sla_goes_down_when_monitored_service_dies(tmp_path):
    http_server = HTTPServer(("127.0.0.1", 0), _AlwaysOkHandler)
    uptime_port = http_server.server_address[1]
    http_thread = threading.Thread(target=http_server.serve_forever,
                                   daemon=True)
    http_thread.start()

    engine = lb._EngineProc(
        tmp_path, env_extra={"HUITZILOPOCHTLI_CHECKIN_INTERVAL_S": "2"})
    try:
        name = "adv-sla-down"
        engine.upload_scenario(_sla_rubric(name))
        token = engine.mint_token(name)

        manifest_path = tmp_path / "manifest.json"
        lb._write_json(manifest_path,
                       _sla_manifest(name, engine.base_url, uptime_port))
        identity_path = tmp_path / "identity.json"
        config_path = tmp_path / "config.json"
        lb._write_json(config_path, lb._base_config(
            manifest_path, identity_path, tmp_path / "report.html",
            checkin_interval_s=1, enrollment_token=token))

        # Phase 1: accrue while the service is up.
        proc = lb._run_agent(str(config_path))
        try:
            deadline = time.time() + 30.0
            accrued = 0
            while time.time() < deadline:
                row = _sla_state(engine.db_path,
                                 _box_id_when_known(identity_path))
                if row is not None and row["accrued_points"] >= 4:
                    accrued = row["accrued_points"]
                    break
                time.sleep(0.5)
            assert accrued >= 4, (
                f"SLA never accrued 4 points while up (got {accrued}); "
                f"this phase needs a working accrual before the DOWN phase "
                f"is meaningful"
            )

            # Phase 2: kill the monitored service; the very next observation
            # fails and (hysteresis_fail_n=1) flips the state DOWN.
            http_server.shutdown()

            deadline = time.time() + 30.0
            while time.time() < deadline:
                row = _sla_state(engine.db_path,
                                 _box_id_when_known(identity_path))
                if row is not None and row["state"] == "DOWN":
                    break
                time.sleep(0.5)
            assert row is not None and row["state"] == "DOWN", (
                f"SLA never went DOWN after the service died: {row!r}"
            )
            frozen_at = row["accrued_points"]

            # Phase 3: accrual is frozen while DOWN -- two more crypto-bound
            # cycles pass without the score moving.
            time.sleep(10.0)
            row = _sla_state(engine.db_path,
                             _box_id_when_known(identity_path))
            assert row["state"] == "DOWN"
            assert row["accrued_points"] == frozen_at, (
                f"accrual moved while DOWN: {frozen_at} -> "
                f"{row['accrued_points']}"
            )
        finally:
            out, err = lb._stop_agent(proc)
        assert "Traceback" not in err, f"agent crashed during SLA run:\n{err}"
    finally:
        engine.stop()
        # In case phase 1 failed before the shutdown, stop the server thread.
        http_server.shutdown()
        http_thread.join(timeout=2)
