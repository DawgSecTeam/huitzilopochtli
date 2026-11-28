"""Admin action guards: unknown verbs refuse, seat loss releases the VM.

Found on the range: bogus verbs answered {"ok": true} and wrote audit rows
while doing nothing -- a typo on end/close-join would have read as success.
"open-join" was one of those typos back then; it is a real verb now (the
counterpart of close-join), so it is asserted as working below and the
remaining bogus verbs still have to refuse. Disqualify and remove likewise
left the player's VM powered until the portal lease expired on its own. Both
run against the real HTTP surface with the shared fake workshop portal.
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
    ADMIN, REPO_ROOT, _Workshop, _free_port, _http, _scenario_yaml, _wait_db)


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
        for verb in ("reopen-join", "frobnicate"):
            status, body = _http("POST",
                                 base + f"/admin/api/competitions/{comp_id}/{verb}",
                                 {}, auth)
            assert status == 400, (verb, status, body)
            assert "unknown competition action" in body, (verb, body)
        assert _audit_rows(db) == before  # refused verbs write no audit row

        # "open-join" used to be in the bogus list above: close-join had no
        # counterpart, so a competition closed too early could never accept
        # joins again. It is a real verb now (see
        # test_ranked_general_use_gaps.test_open_join_verb_restores_join_open).
        status, body = _http("POST",
                             base + f"/admin/api/competitions/{comp_id}/close-join",
                             {}, auth)
        assert status == 200, body
        status, body = _http("POST",
                             base + f"/admin/api/competitions/{comp_id}/open-join",
                             {}, auth)
        assert status == 200, body
        assert json.loads(body)["competition"]["join_open"] is True
        before = _audit_rows(db)  # the toggles above did write rows

        # Same guard on the player side.
        status, body = _http("POST", base + "/admin/players/nope/teleport", {}, auth)
        assert status == 404, body  # unknown player answers 404 first
        assert _audit_rows(db) == before
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_disqualify_keeps_the_box_and_remove_releases_it(tmp_path):
    """§7.1 (boss directive): disqualification is a board exclusion, not an
    eviction -- no release fires, the audit row records that the player
    keeps playing, and Reinstate walks them back onto the board. Remove is
    the only verb that hands the VM back (exactly once, this player's uid).
    """
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

        # The claim finishes after the join response; wait for the uid.
        player = _wait_db(db, "SELECT * FROM players WHERE display_name=?",
                          ("Cheater",), "claim_uid")
        assert player["claim_uid"]
        pid = player["player_id"]

        # §7.1 speaks to a seat with a box and a clock: stamp the bind (the
        # state `huitz join` writes) before exercising the admin verbs --
        # disqualify is refused for a seat that never bound one, and
        # reinstating such a seat used to fabricate a running status.
        bconn = sqlite3.connect(db)
        bconn.execute(
            "INSERT INTO boxes (box_id, public_key, scenario_name, "
            "scenario_version, enrolled_at, last_seq, competition_id, "
            "player_id) VALUES (?, 'k', 'HTTPComp', 1, ?, 0, ?, ?)",
            (f"box-{pid[:8]}", time.time(), comp_id, pid))
        bconn.execute(
            "UPDATE players SET box_id = ?, status = 'running', "
            "started_at = ?, ends_at = ? WHERE player_id = ?",
            (f"box-{pid[:8]}", time.time(), time.time() + 3600, pid))
        bconn.commit()
        bconn.close()

        releases_before = sum(1 for r in _Workshop.requests
                              if r[0] == "/api/release")

        # Disqualify: status flips, nothing is released, audit says so.
        status, body = _http("POST",
                             base + f"/admin/players/{pid}/disqualify", {}, auth)
        assert status == 200, body
        releases = [r for r in _Workshop.requests if r[0] == "/api/release"]
        assert len(releases) == releases_before, (
            "disqualify must NOT release the VM; the player keeps playing")

        def _row_and_audit(action):
            sconn = sqlite3.connect(db)
            sconn.row_factory = sqlite3.Row
            row = sconn.execute("SELECT status FROM players WHERE player_id=?",
                                (pid,)).fetchone()
            audit = sconn.execute(
                "SELECT details_json FROM audit_log WHERE action=? "
                "AND player_id=? ORDER BY ts DESC LIMIT 1",
                (action, pid)).fetchone()
            sconn.close()
            return row, audit

        row, audit = _row_and_audit("player_disqualify")
        assert row["status"] == "disqualified"
        assert json.loads(audit["details_json"]) == {"released_vm": False,
                                                     "keeps_playing": True}

        # Reinstate: the run was never stopped, so it resumes ranked play.
        status, body = _http("POST", base + f"/admin/players/{pid}/reinstate",
                             {}, auth)
        assert status == 200, body
        row, audit = _row_and_audit("player_reinstate")
        assert row["status"] == "running"
        assert json.loads(audit["details_json"]) == {"released_vm": False,
                                                     "keeps_playing": False}

        # Reinstate is only for the disqualified.
        status, _ = _http("POST", base + f"/admin/players/{pid}/reinstate",
                          {}, auth)
        assert status == 409

        # Disqualify again, then Remove: the box hands back exactly once.
        status, _ = _http("POST", base + f"/admin/players/{pid}/disqualify",
                          {}, auth)
        assert status == 200
        status, body = _http("POST", base + f"/admin/players/{pid}/remove",
                             {}, auth)
        assert status == 200, body
        releases = [r for r in _Workshop.requests if r[0] == "/api/release"]
        assert len(releases) == releases_before + 1, _Workshop.requests
        # the release carried THIS player's claim uid
        assert releases[-1][2].get("uid") == player["claim_uid"]
        row, audit = _row_and_audit("player_remove")
        assert row["status"] == "removed"
        assert json.loads(audit["details_json"]) == {"released_vm": True,
                                                     "keeps_playing": False}
    finally:
        proc.terminate()
        proc.wait(timeout=10)




def test_release_box_destroys_the_run_vm_without_tombstoning(tmp_path):
    """The post-run lifecycle verb: release_box ends a run's access window
    early (the VM is destroyed, the uid's claim goes with it) while the
    player keeps their status, score and entry. A second call refuses."""
    import http.client
    import urllib.parse
    proc, base, db = _engine(tmp_path)
    auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
    try:
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "release-comp", "name": "Release Comp",
            "scenario_name": "HTTPComp", "scenario_version": 1,
            "max_players": 4, "duration_s": 3600}, auth)
        comp_id = json.loads(body)["id"]
        _http("POST", base + f"/admin/api/competitions/{comp_id}/start",
              {}, auth)
        conn = http.client.HTTPConnection("127.0.0.1", int(base.rsplit(":", 1)[1]),
                                          timeout=10)
        conn.request("POST", "/c/release-comp/join",
                     body=urllib.parse.urlencode({"name": "Gone"}),
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 303
        conn.close()

        # The claim finishes after the join response; wait for the uid.
        player = _wait_db(db, "SELECT * FROM players WHERE display_name=?",
                          ("Gone",), "claim_uid")
        assert player["claim_uid"]
        pid = player["player_id"]
        # release_box is for a held, bound box (a bound run); the join flow
        # alone leaves the claim unbound until the agent joins, so bind the
        # box the way the agent would (bind starts the player's run clock).
        now = time.time()
        sconn = sqlite3.connect(db)
        sconn.execute(
            "UPDATE players SET box_id='box-gone', status='running', "
            "started_at=?, ends_at=? WHERE player_id=?",
            (now, now + 3600, pid))
        sconn.commit()
        sconn.close()

        releases_before = sum(1 for r in _Workshop.requests
                              if r[0] == "/api/release")
        status, body = _http("POST", base + f"/admin/players/{pid}/release_box",
                             {}, auth)
        assert status == 200, body
        releases = [r for r in _Workshop.requests if r[0] == "/api/release"]
        assert len(releases) == releases_before + 1
        assert releases[-1][2].get("uid") == player["claim_uid"]

        sconn = sqlite3.connect(db)
        sconn.row_factory = sqlite3.Row
        row = sconn.execute(
            "SELECT status, box_id, claim_uid, claim_url, box_released_at "
            "FROM players WHERE player_id=?", (pid,)).fetchone()
        audit = sconn.execute(
            "SELECT details_json FROM audit_log WHERE action=? AND player_id=? "
            "ORDER BY ts DESC LIMIT 1",
            ("player_release_box", pid)).fetchone()
        sconn.close()
        assert row["status"] == "running"       # not tombstoned
        assert row["box_id"] == "box-gone"      # history survives the release
        assert row["claim_uid"] is None and row["claim_url"] is None
        assert row["box_released_at"] is not None
        assert json.loads(audit["details_json"]) == {"released_vm": True,
                                                     "keeps_playing": False}

        # Nothing left to release: a second call refuses.
        status, body = _http("POST", base + f"/admin/players/{pid}/release_box",
                             {}, auth)
        assert status == 409, body
        assert "no bound box" in body, body
    finally:
        proc.terminate()
        proc.wait(timeout=10)
