"""Admin action guards: unknown verbs refuse, seat loss releases the VM.

Found on the range: `POST /admin/api/competitions/<id>/open-join` (and three
more bogus verbs) answered {"ok": true} and wrote audit rows while doing
nothing -- a typo on end/close-join would have read as success. Disqualify
and remove likewise left the player's VM powered until the portal lease
expired on its own. Both run against the real HTTP surface with the shared
fake workshop portal.
"""
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer

from tests.integration.test_competition_http import (
    ADMIN, REPO_ROOT, _Workshop, _free_port, _http, _scenario_yaml)


def _engine(tmp_path):
    port = _free_port()
    workshop_port = _free_port()
    _Workshop.server_port = workshop_port
    _Workshop.requests = []
    _Workshop.counter = 0
    _Workshop.fail_claims = 0
    _Workshop.pools = []
    _Workshop.vms = [{"vmid": 901, "pool": "PROV1",
                      "student_id": "huitz-ranked-guard-comp-1",
                      "claimed": True, "expired": False}]
    db = tmp_path / "engine.db"
    boxes = tmp_path / "boxes" / "guard-box"
    boxes.mkdir(parents=True)
    (boxes / "scenario.yaml").write_text(_scenario_yaml())
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(db),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": ADMIN,
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_WORKSHOP_URL": f"http://127.0.0.1:{workshop_port}",
        "HUITZILOPOCHTLI_WORKSHOP_SECRET": "ws-secret",
        "HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD": "portal-pw",
        "HUITZILOPOCHTLI_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "HUITZILOPOCHTLI_BOXES_DIR": str(tmp_path / "boxes"),
        "PYTHONUNBUFFERED": "1",
    })
    ws = ThreadingHTTPServer(("127.0.0.1", workshop_port), _Workshop)
    threading.Thread(target=ws.serve_forever, daemon=True).start()
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"], cwd=REPO_ROOT,
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if _http("GET", base + "/health")[0] == 200:
                break
        except Exception:
            pass
        time.sleep(0.1)
    return proc, base, db


def _audit_rows(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()


def test_unknown_admin_verbs_are_refused_without_audit(tmp_path):
    proc, base, db = _engine(tmp_path)
    auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
    try:
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "guard-comp", "name": "Guard Comp", "scenario_name": "HTTPComp",
            "scenario_version": 1, "max_players": 4, "duration_s": 3600}, auth)
        comp_id = json.loads(body)["id"]
        _http("POST", base + f"/admin/api/competitions/{comp_id}/start", {}, auth)

        before = _audit_rows(db)
        for verb in ("open-join", "reopen-join", "frobnicate"):
            status, body = _http("POST",
                                 base + f"/admin/api/competitions/{comp_id}/{verb}",
                                 {}, auth)
            assert status == 400, (verb, status, body)
            assert "unknown competition action" in body, (verb, body)
        assert _audit_rows(db) == before  # refused verbs write no audit row

        # Same guard on the player side.
        status, body = _http("POST", base + "/admin/players/nope/teleport", {}, auth)
        assert status == 404, body  # unknown player answers 404 first
        assert _audit_rows(db) == before
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_disqualify_releases_the_claimed_vm(tmp_path):
    import http.client
    import urllib.parse
    proc, base, db = _engine(tmp_path)
    auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
    try:
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "dq-comp", "name": "DQ Comp", "scenario_name": "HTTPComp",
            "scenario_version": 1, "max_players": 4, "duration_s": 3600}, auth)
        comp_id = json.loads(body)["id"]
        _http("POST", base + f"/admin/api/competitions/{comp_id}/start", {}, auth)
        conn = http.client.HTTPConnection("127.0.0.1", int(base.rsplit(":", 1)[1]),
                                          timeout=10)
        conn.request("POST", "/c/dq-comp/join",
                     body=urllib.parse.urlencode({"name": "Cheater"}),
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 303
        conn.close()

        sconn = sqlite3.connect(db)
        sconn.row_factory = sqlite3.Row
        player = sconn.execute(
            "SELECT * FROM players WHERE display_name='Cheater'").fetchone()
        sconn.close()
        assert player is not None and player["claim_uid"]

        releases_before = sum(1 for r in _Workshop.requests
                              if r[0] == "/api/release")
        status, body = _http("POST",
                             base + f"/admin/players/{player['player_id']}/disqualify",
                             {}, auth)
        assert status == 200, body
        releases = [r for r in _Workshop.requests if r[0] == "/api/release"]
        assert len(releases) == releases_before + 1, _Workshop.requests
        # the release carried THIS player's claim uid
        assert releases[-1][2].get("uid") == player["claim_uid"]

        sconn = sqlite3.connect(db)
        sconn.row_factory = sqlite3.Row
        row = sconn.execute("SELECT status FROM players WHERE player_id=?",
                            (player["player_id"],)).fetchone()
        audit = sconn.execute(
            "SELECT details_json FROM audit_log WHERE action='player_disqualify' "
            "ORDER BY ts DESC LIMIT 1").fetchone()
        sconn.close()
        assert row["status"] == "disqualified"
        assert json.loads(audit["details_json"]) == {"released_vm": True}
    finally:
        proc.terminate()
        proc.wait(timeout=10)
