"""End-to-end HTTP test for the ranked competition surface.

Real engine subprocess + real sqlite DB + a tiny fake workshop portal. Covers
the public join page, the signed /join endpoint, check-in scoring/leaderboard,
and admin start/end through the token API.
"""
import base64
import dataclasses
import http.client
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common import canon
from common.crypto import signing
from common.schema import Bundle, CollectorStatus, Evidence, SCHEMA_VERSION
from common.version import AGENT_VERSION

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADMIN = "admin-token"


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _http(method, url, body=None, headers=None):
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            headers = {**(headers or {}), "Content-Type": "application/json"}
        else:
            data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _http_req(port, method, path, body=None, headers=None):
    """Raw request that does not follow redirects and returns headers, for
    flows that must observe the 303 + Set-Cookie (e.g. two-step admin login)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=dict(headers or {}))
    r = conn.getresponse()
    data = r.read().decode("utf-8", "replace")
    hdrs = dict(r.getheaders())
    conn.close()
    return r.status, data, hdrs


def _wait_claim_url(base, player_id, want, timeout=15.0):
    """Poll the join-page status endpoint until the claim lands.

    The claim runs outside the join request (the cookie is sent first), so
    tests must wait for provisioning instead of assuming it finished
    synchronously with the 303. The fake portal usually answers in
    milliseconds; the timeout exists for the general case.
    """
    deadline = time.time() + timeout
    body = ""
    while time.time() < deadline:
        status, body = _http(
            "GET", f"{base}/api/public/join/{player_id}/status")
        if status == 200:
            state = json.loads(body)
            if state.get("claim_url") == want:
                return state
        time.sleep(0.2)
    raise AssertionError(f"claim_url never reached {want!r}: {body!r}")


def _wait_db(db, sql, params, column, timeout=15.0):
    """Poll the engine DB until ``column`` of the single matching row is set."""
    deadline = time.time() + timeout
    row = None
    while time.time() < deadline:
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(sql, params).fetchone()
        conn.close()
        if row is not None and row[column]:
            return row
        time.sleep(0.2)
    raise AssertionError(f"{column} never appeared for {sql} {params}")


class _Workshop(BaseHTTPRequestHandler):
    requests = []
    counter = 0
    fail_claims = 0
    claim_delay = 0.0
    pools = []
    vms = []

    def log_message(self, *a):
        pass

    def _reply(self, status, payload):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _admin(self):
        expected = "Basic " + base64.b64encode(b"admin:portal-pw").decode()
        return self.headers.get("Authorization", "") == expected

    def do_GET(self):
        if self.path.startswith("/api/redeem/"):
            self._reply(200, {"status": "ready",
                              "open_url": "http://portal.example/r/u1",
                              "url": "http://guac.example/session/abc",
                              "uid": "u1"})
            return
        if self.path == "/api/admin/pools":
            if not self._admin():
                self._reply(403, {"detail": "admin auth required"})
                return
            self._reply(200, list(type(self).pools))
            return
        if self.path == "/api/admin/pool":
            if not self._admin():
                self._reply(403, {"detail": "admin auth required"})
                return
            self._reply(200, list(type(self).vms))
            return
        self._reply(404, {"detail": "not found"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw or b"{}")
        type(self).requests.append((self.path, dict(self.headers), body))
        if self.path == "/api/admin/destroy":
            if not self._admin():
                self._reply(403, {"detail": "admin auth required"})
                return
            self._reply(200, {"status": "done"})
            return
        if self.path == "/api/admin/provision":
            if not self._admin():
                self._reply(403, {"detail": "admin auth required"})
                return
            code = f"PROV{len(type(self).pools) + 1}"
            # The real portal saves the pool config synchronously (generating
            # the code) and provisions VMs on a background job.
            type(self).pools.append({
                "code": code, "name": body.get("pool_name"), "available": 0,
                "total": 0, "in_use": 0, "last_used": 0, "count": 1,
                "config": {"template_vm_id": body.get("template_vm_id"),
                           "pool_name": body.get("pool_name"),
                           "pool_code": code},
            })
            self._reply(200, {"job_id": "j1"})
            return
        if self.path == "/api/admin/extend":
            if not self._admin():
                self._reply(403, {"detail": "admin auth required"})
                return
            self._reply(200, {"extended": body.get("vmid")})
            return
        if self.path == "/api/release":
            self._reply(200, {"released": True})
            return
        if self.path == "/api/prebind":
            self._reply(200, {"ok": True})
            return
        if self.path == "/api/claim" and type(self).fail_claims:
            type(self).fail_claims -= 1
            self._reply(503, {"detail": "No VMs available right now."})
            return
        type(self).counter += 1
        uid = f"u{type(self).counter}"
        # Simulate a cold portal: a claim can spend seconds (or minutes in
        # real life) before it answers. Tests assert the join POST did NOT
        # wait for this.
        if type(self).claim_delay:
            time.sleep(type(self).claim_delay)
        self._reply(200, {
            "status": "ready",
            "open_url": f"http://portal.example/r/{uid}",
            "url": "http://guac.example/session/abc",
            "uid": uid,
            "expires_at": time.time() + 7200,
        })

    def do_DELETE(self):
        type(self).requests.append((self.path, dict(self.headers), {}))
        if self.path.startswith("/api/admin/pools/"):
            code = self.path.rsplit("/", 1)[1]
            type(self).pools = [p for p in type(self).pools
                                if p["code"] != code]
            self._reply(200, {"removed": True})
            return
        self._reply(404, {"detail": "not found"})


def _rubric():
    return {
        "schema_version": SCHEMA_VERSION, "scenario_name": "HTTPComp",
        "scenario_version": 1,
        "entries": [
            {"check_id": "banner", "category": "vuln",
             "matcher": {"tag": "equals", "value": "ok"}, "points": 10, "sla": None},
            {"check_id": "svc_web", "category": "vuln",
             "matcher": {"tag": "equals", "value": True, "field": "open"},
             "points": 0,
             "sla": {"interval_s": 1, "points_per_interval": 1,
                     "hysteresis_fail_n": 1, "hysteresis_ok_n": 1,
                     "max_intervals_per_checkin": 3}},
        ],
    }


def _services():
    return [{"id": "web", "check_id": "svc_web", "display": "Web",
             "type": "tcp_port", "interval_s": 1, "points_per_interval": 1}]


def _scenario_yaml():
    """Ranked box source equivalent of _rubric() + _services() + pool."""
    import yaml
    return yaml.safe_dump({
        "scenario": {"name": "HTTPComp", "version": 1, "mode": "honor",
                     "hosts": ["localhost"]},
        "checks": [{"id": "banner", "type": "file_regex", "category": "vuln",
                    "display": "Banner", "max_points": 10,
                    "collect": {"path": "/srv/banner", "extract": "B"},
                    "expect": {"equals": "ok", "points": 10}}],
        "ranked": {
            "engine_url": "http://127.0.0.1:8080",
            "services": [{"id": "web", "display": "Web", "type": "tcp_port",
                          "collect": {"host": "127.0.0.1", "port": 80},
                          "expect": {"equals": True, "field": "open"},
                          "interval_s": 1, "points_per_interval": 1,
                          "hysteresis_fail_n": 1, "hysteresis_ok_n": 1,
                          "max_intervals_per_checkin": 3}],
            "adversary": {},
            "pool": {"template_vm_id": 174, "template_vm_access_method": "ssh",
                     "template_vm_username": "sysadmin",
                     "template_vm_password": "asdf", "vm_count": 1},
        },
    })



def test_public_join_signed_join_and_leaderboard(tmp_path):
    port = _free_port()
    workshop_port = _free_port()
    _Workshop.server_port = workshop_port
    _Workshop.requests = []
    _Workshop.counter = 0
    _Workshop.fail_claims = 0
    _Workshop.pools = []
    # One registered clone for the provisioned pool: teardown enumerates it
    # (via /api/admin/pool), destroys it, then deletes the pool config.
    _Workshop.vms = [{"vmid": 901, "pool": "PROV1", "student_id":
                      "huitz-ranked-http-comp-1", "claimed": True,
                      "expired": False}]
    db = tmp_path / "engine.db"
    boxes = tmp_path / "boxes" / "http-comp-box"
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
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    try:
        # wait for listening
        for _ in range(100):
            try:
                if _http("GET", base + "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "http-comp", "name": "HTTP Comp", "scenario_name": "HTTPComp",
            "scenario_version": 1, "max_players": 4, "duration_s": 3600,
        }, auth)
        assert status == 200, body
        comp_id = json.loads(body)["id"]
        status, body = _http("POST", base + f"/admin/api/competitions/{comp_id}/start",
                             {}, auth)
        assert status in (200, 303), body

        # PRG: the join POST redirects (303) to the main page -- which, while
        # the run is active, is the dashboard itself -- and sets the player
        # cookie on the redirect, so a browser refresh never re-submits.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/c/http-comp/join",
                     body=urllib.parse.urlencode({"name": "Ada"}),
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 303, resp.status
        assert resp.getheader("Location") == "/"
        cookie = (resp.getheader("Set-Cookie") or "").split(";", 1)[0]
        assert cookie.startswith("huitz_player=")
        conn.close()

        # The claim runs after the join response now, so the seat row exists
        # (the cookie already names it) while provisioning finishes in the
        # background. Wait for the VM link before asserting what the pages
        # show about it.
        conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
        player = conn.execute(
            "SELECT * FROM players WHERE display_name='Ada'").fetchone()
        conn.close()
        assert player is not None
        _wait_claim_url(base, player["player_id"],
                        "http://portal.example/r/u1")

        # The success URL remains the pending/fallback page while unbound.
        status, page = _http("GET", base + "/c/http-comp/join/success",
                             headers={"Cookie": cookie})
        assert status == 200, page
        assert "Ada" in page and "Open my VM" in page
        assert "http://portal.example/r/u1" in page
        # A working VM link never pairs with a "get a new one" button.
        assert "Get a new VM" not in page
        assert "clock starts when you open" in page

        # One competition at a time: the main page becomes the active run ...
        status, page = _http("GET", base + "/", headers={"Cookie": cookie})
        assert status == 200, page
        assert "You're in HTTP Comp" in page
        assert "this is your main page" in page
        assert 'class="home-grid"' in page
        assert "Leave competition" in page
        assert "/c/http-comp/leave" in page
        assert "Permanent status link" not in page
        # Service names are present before the box joins, with ten tick slots.
        assert "Service uptime" in page and "Web" in page
        assert page.count('class="tick ') == 10
        # ... and the competition page no longer offers Join.
        status, page = _http("GET", base + "/c/http-comp",
                             headers={"Cookie": cookie})
        assert status == 200
        assert "Join this competition" not in page
        assert "You're in this competition" in page

        # ... and a second live competition refuses the same browser.
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "other-comp", "name": "Other Comp", "scenario_name": "HTTPComp",
            "scenario_version": 1, "max_players": 4, "duration_s": 3600,
        }, auth)
        assert status == 200, body
        other = json.loads(body)
        status, body = _http("POST", base + f"/admin/api/competitions/{other['id']}/start",
                             {}, auth)
        assert status in (200, 303), body
        status, page = _http("GET", base + "/c/other-comp/join",
                             headers={"Cookie": cookie})
        assert status == 409 and "already in HTTP Comp" in page
        form = {"Content-Type": "application/x-www-form-urlencoded"}
        status, page = _http("POST", base + "/c/other-comp/join",
                             urllib.parse.urlencode({"name": "Ada"}),
                             {**form, "Cookie": cookie})
        assert status == 409 and "already in HTTP Comp" in page
        # Clearing the cookie does not turn one person into two competitors:
        # the live display name is the second handle the engine has.
        status, page = _http("POST", base + "/c/other-comp/join",
                             urllib.parse.urlencode({"name": "Ada"}), form)
        assert status == 409 and "already competing in HTTP Comp" in page
        conn = sqlite3.connect(db)
        n = conn.execute("SELECT COUNT(*) FROM players WHERE competition_id = ?",
                         (other["id"],)).fetchone()[0]
        conn.close()
        assert n == 0  # no second slot, no second VM

        # Same competition, cookie lost: the held seat is named, and the
        # message tells the seat's owner and the second joiner apart.
        status, page = _http("POST", base + "/c/http-comp/join",
                             urllib.parse.urlencode({"name": "Ada"}), form)
        assert status == 409 and "already reserved in HTTP Comp" in page
        assert "If that is you" in page and "pick a different name" in page
        # Matching is on the trimmed, lower-cased handle, so padding and case
        # collide with the same held seat rather than minting a second Ada.
        status, page = _http("POST", base + "/c/http-comp/join",
                             urllib.parse.urlencode({"name": "  ADA  "}), form)
        assert status == 409 and "is already reserved" in page
        # The form says out loud that spaces and case don't dodge a clash.
        status, page = _http("GET", base + "/c/http-comp/join?key=http-key")
        assert status == 200 and "matched case-insensitively" in page

        conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
        player = conn.execute("SELECT * FROM players WHERE display_name='Ada'").fetchone()
        conn.close()
        assert player is not None and player["join_code_plain"]
        code = player["join_code_plain"]

        # The engine handed the portal the one-time code and the prebind
        # secret, so the VM can join itself when the player opens the link.
        claim_reqs = [r for r in _Workshop.requests if r[0] == "/api/claim"]
        assert claim_reqs, _Workshop.requests
        _path, headers, body = claim_reqs[0]
        assert headers.get("X-Huitz-Secret") == "ws-secret"
        assert body["prebind"]["code"] == code
        assert body["prebind"]["back_url"].endswith("/c/http-comp/join/success")

        # A dedicated pool is provisioned per competition from the scenario's
        # pool block — the engine never picks among the portal's pools.
        prov_reqs = [r for r in _Workshop.requests
                     if r[0] == "/api/admin/provision"]
        assert len(prov_reqs) == 1, _Workshop.requests
        _path, prov_headers, prov_body = prov_reqs[0]
        assert prov_headers.get("Authorization", "").startswith("Basic ")
        assert prov_body["pool_name"] == "huitz-ranked-http-comp"
        assert prov_body["template_vm_id"] == 174
        assert prov_body["vm_count"] == 1
        assert prov_body["dispenser"] is True and prov_body["private"] is True
        # The claim went to the freshly provisioned pool (code captured by
        # re-listing pools by name after the provision POST).
        assert body["code"] == "PROV1"

        # The polling endpoint the join page uses must resolve the player id
        # (it used to read the trailing /status segment as the id).
        status, body = _http(
            "GET", base + f"/api/public/join/{player['player_id']}/status")
        assert status == 200, body
        state = json.loads(body)
        assert state["claim_url"] == "http://portal.example/r/u1"
        assert state["claim_pending"] is False
        assert state["box_bound"] is False
        assert "join_code" not in state

        # "Get a new VM" is no longer linked from a working-VM page, but the
        # reclaim endpoint remains as the recovery path. Build the page CSRF
        # the way web.py does (HMAC of the player id under the server secret).
        conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
        stored = conn.execute(
            "SELECT value FROM engine_meta WHERE key='server_secret'").fetchone()
        conn.close()
        from engine.claims import player_csrf
        csrf = player_csrf(base64.b64decode(stored["value"]),
                           player["player_id"])
        status, body = _http(
            "POST", base + f"/api/public/join/{player['player_id']}/claim",
            {"csrf": csrf},
            {"Cookie": cookie, "Accept": "application/json"})
        assert status == 200, body
        assert json.loads(body)["url"] == "http://portal.example/r/u2"
        assert any(r[0] == "/api/release" for r in _Workshop.requests)
        status, _body = _http(
            "POST", base + f"/api/public/join/{player['player_id']}/claim",
            {"csrf": "forged"}, {"Cookie": cookie,
                                  "Accept": "application/json"})
        assert status == 403

        priv, pub = signing.keypair()
        join_body = {
            "join_code": code, "box_id": "box-http-1",
            "public_key": base64.b64encode(pub).decode(),
            "agent_version": AGENT_VERSION, "scenario_name": "HTTPComp",
            "scenario_version": 1,
        }
        sig = signing.sign(priv, canon.canonicalize(join_body))
        status, body = _http("POST", base + "/join", json.dumps(join_body).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-http-1",
        })
        assert status == 200, body

        # Once the box is joined, the old success URL hands off to the run.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/c/http-comp/join/success", headers={"Cookie": cookie})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 303
        assert resp.getheader("Location") == "/"
        conn.close()

        ev = [
            Evidence(check_id="banner", check_type="file_regex", host_id="localhost",
                     status=CollectorStatus.OK, raw={"matched": "ok", "present": True},
                     reason="ok", collected_monotonic=0.0, collected_wall_claim=0.0),
            Evidence(check_id="svc_web", check_type="tcp_port", host_id="localhost",
                     status=CollectorStatus.OK, raw={"open": True, "error": None},
                     reason="web", collected_monotonic=0.0, collected_wall_claim=0.0),
        ]
        bundle = Bundle(box_id="box-http-1", seq=1, boot_id="b",
                        agent_version=AGENT_VERSION, scenario_name="HTTPComp",
                        scenario_version=1, evidence=ev, created_wall_claim=0.0,
                        schema_version=SCHEMA_VERSION)
        bsig = signing.sign(priv, canon.canonicalize(dataclasses.asdict(bundle)))
        status, body = _http("POST", base + "/checkin", json.dumps(dataclasses.asdict(bundle)).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(bsig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-http-1",
        })
        assert status == 200, body
        checkin = json.loads(body)
        assert checkin["score"]["total"] == 10
        # The ranked report's new top bar + uptime tab read these fields, so
        # they must survive the real HTTP JSON serialization.
        assert checkin["rank"] == 1 and checkin["rank_total"] == 1
        assert checkin["run_ends_at"] is not None
        services = {s["check_id"]: s
                    for s in checkin["score"]["sla_status"]}
        assert services["svc_web"]["state"] == "UP"
        assert services["svc_web"]["history"] == ["UP"]

        status, body = _http("GET", base + "/api/public/competitions/http-comp/leaderboard")
        assert status == 200
        board = json.loads(body)
        assert board["leaderboard"][0]["name"] == "Ada"
        assert board["leaderboard"][0]["total"] == 10
        status, page = _http("GET", base + "/c/http-comp")
        assert status == 200 and "Ada" in page
        assert 'data-poll=' in page and 'data-remaining=' in page

        # Unknown paths: browsers get a styled HTML 404, API callers get JSON.
        status, page = _http("GET", base + "/definitely-not-a-page",
                             headers={"Accept": "text/html,application/xhtml+xml"})
        assert status == 404 and page.startswith("<!doctype html>")
        status, body = _http("GET", base + "/definitely-not-a-page")
        assert status == 404 and json.loads(body)["error"] == "not found"

        # Leaving is a forfeit: the cookie is cleared, the VM is released, the
        # slot is removed, and the board no longer lists the player.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/c/http-comp/leave",
                     body=urllib.parse.urlencode({"csrf": csrf}),
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Cookie": cookie})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 303
        assert resp.getheader("Location") == "/"
        cleared = (resp.getheader("Set-Cookie") or "")
        assert cleared.startswith("huitz_player=;") and "Max-Age=0" in cleared
        conn.close()
        conn = sqlite3.connect(db)
        row = conn.execute("SELECT status FROM players WHERE player_id = ?",
                           (player["player_id"],)).fetchone()
        conn.close()
        assert row is not None and row[0] == "removed"
        status, body = _http("GET", base + "/api/public/competitions/http-comp/leaderboard")
        assert json.loads(body)["leaderboard"] == []
        status, page = _http("GET", base + "/", headers={"Cookie": cookie})
        assert status == 200 and "You're in HTTP Comp" not in page

        status, body = _http("POST", base + f"/admin/api/competitions/{comp_id}/end", {}, auth)
        assert status in (200, 303), body
        status, body = _http("GET", base + "/api/public/competitions/http-comp")
        assert json.loads(body)["status"] == "ended"
        # Ending the competition hands the VMs back and deletes the pool.
        assert any(r[0] == "/api/admin/pools/PROV1" for r in _Workshop.requests)
        assert any(r[0] == "/api/release" for r in _Workshop.requests)
        assert _Workshop.pools == []

        # A live competition cannot be removed; once ended, deletion drops the
        # competition and its player slots (the box/score history stays).
        status, body = _http("POST", base + f"/admin/api/competitions/{other['id']}/delete",
                             {}, auth)
        assert status == 409, body
        status, body = _http("POST", base + f"/admin/api/competitions/{comp_id}/delete",
                             {}, auth)
        assert status == 200, body
        assert json.loads(body)["deleted"] == comp_id
        conn = sqlite3.connect(db)
        assert conn.execute("SELECT COUNT(*) FROM competitions WHERE id = ?",
                            (comp_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM players WHERE competition_id = ?",
                            (comp_id,)).fetchone()[0] == 0
        conn.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        ws.shutdown()


def test_team_link_and_roster_http(tmp_path):
    """v1.2 teams over real HTTP: the seat's shareable link, rotation, roster.

    The seat itself (clock, claim, board row) is the same row the join flow
    creates; this pins only the surfaces teams add. Auto-warm is off so the
    fake portal sees no background traffic.
    """
    port = _free_port()
    workshop_port = _free_port()
    _Workshop.server_port = workshop_port
    _Workshop.requests = []
    _Workshop.counter = 0
    _Workshop.fail_claims = 0
    _Workshop.pools = []
    _Workshop.vms = []
    db = tmp_path / "engine.db"
    boxes = tmp_path / "boxes" / "http-comp-box"
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
        "HUITZILOPOCHTLI_AUTOWARM": "0",
        "PYTHONUNBUFFERED": "1",
    })
    ws = ThreadingHTTPServer(("127.0.0.1", workshop_port), _Workshop)
    threading.Thread(target=ws.serve_forever, daemon=True).start()
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"], cwd=REPO_ROOT,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if _http("GET", base + "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "team-http", "name": "Team HTTP", "scenario_name": "HTTPComp",
            "scenario_version": 1, "max_players": 4, "duration_s": 3600,
        }, auth)
        assert status == 200, body
        comp_id = json.loads(body)["id"]
        status, _body = _http("POST",
                              base + f"/admin/api/competitions/{comp_id}/start",
                              {}, auth)
        assert status in (200, 303)

        # Ada joins (PRG: cookie on the 303). The seat's team link is minted
        # with the reservation itself.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/c/team-http/join",
                     body=urllib.parse.urlencode({"name": "Ada"}),
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 303
        cookie = (resp.getheader("Set-Cookie") or "").split(";", 1)[0]
        assert cookie.startswith("huitz_player=")
        conn.close()
        player = _wait_db(db, "SELECT * FROM players WHERE display_name='Ada'",
                          (), "team_token_plain")

        # A teammate's browser (no cookie) rides the link onto the same seat.
        status, _b, hdrs = _http_req(
            port, "GET", f"/c/team-http/team/{player['team_token_plain']}")
        assert status == 303 and hdrs.get("Location") == "/"
        mate_cookie = f"huitz_player={player['player_id']}"
        status, page = _http("GET", base + "/", headers={"Cookie": mate_cookie})
        assert status == 200 and "Ada" in page and "/c/team-http/team/" in page

        # A forged/unknown token resolves to nobody's seat.
        status, page = _http("GET", base + "/c/team-http/team/nope-nope-nope")
        assert status == 403 and "Team link not valid" in page

        # Roster management needs the seat's CSRF, same discipline as leave.
        conn2 = sqlite3.connect(db); conn2.row_factory = sqlite3.Row
        stored = conn2.execute(
            "SELECT value FROM engine_meta WHERE key='server_secret'").fetchone()
        conn2.close()
        from engine.claims import player_csrf
        csrf = player_csrf(base64.b64decode(stored["value"]), player["player_id"])
        status, _body, _h = _http_req(
            port, "POST", "/c/team-http/team",
            body=urllib.parse.urlencode({"csrf": "forged", "action": "add",
                                         "handle": "Grace"}),
            headers={"Cookie": cookie,
                     "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 403

        status, _body, _h = _http_req(
            port, "POST", "/c/team-http/team",
            body=urllib.parse.urlencode({"csrf": csrf, "action": "add",
                                         "handle": "Grace H."}),
            headers={"Cookie": cookie,
                     "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        status, page = _http("GET", base + "/", headers={"Cookie": mate_cookie})
        assert "Grace H." in page
        # The link a teammate already used keeps working (it is the seat's,
        # not the browser's): re-opening resolves the same player.
        status, _b, hdrs = _http_req(
            port, "GET", f"/c/team-http/team/{player['team_token_plain']}")
        assert status == 303

        # Rotating invalidates every previously shared link at once.
        status, _b, _h = _http_req(
            port, "POST", "/c/team-http/team",
            body=urllib.parse.urlencode({"csrf": csrf, "action": "rotate"}),
            headers={"Cookie": cookie,
                     "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        status, page = _http("GET",
                             base + f"/c/team-http/team/{player['team_token_plain']}")
        assert status == 403, "the old team link must stop resolving"
        fresh = _wait_db(db,
                         "SELECT * FROM players WHERE player_id = ?",
                         (player["player_id"],), "team_token_plain")
        assert fresh["team_token_plain"] != player["team_token_plain"]
        status, _b, _h = _http_req(
            port, "GET", f"/c/team-http/team/{fresh['team_token_plain']}")
        assert status == 303

        # Members drop off the roster and the card.
        status, _b, _h = _http_req(
            port, "POST", "/c/team-http/team",
            body=urllib.parse.urlencode({"csrf": csrf, "action": "remove",
                                         "handle": "Grace H."}),
            headers={"Cookie": cookie,
                     "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        status, page = _http("GET", base + "/", headers={"Cookie": cookie})
        assert "Grace H." not in page

        # The run itself is untouched by all of the above: the seat is still
        # the invited slot the join created (team ops never bind, finish, or
        # re-claim anything).
        now_row = _wait_db(db, "SELECT * FROM players WHERE player_id = ?",
                           (player["player_id"],), "joined_at")
        assert now_row["status"] == "invited"
    finally:
        proc.terminate()
        ws.shutdown()


def test_leaderboard_visibility_toggle(tmp_path):
    """The dashboard can conceal the public leaderboard (and reveal it back).

    Concealment is data-layer: the public page, the JSON API and the admin
    dashboard row read the same flag, and toggling it never touches scores
    or player rows.
    """
    port = _free_port()
    workshop_port = _free_port()
    db = tmp_path / "engine.db"
    boxes = tmp_path / "boxes" / "http-comp-box"
    boxes.mkdir(parents=True)
    (boxes / "scenario.yaml").write_text(_scenario_yaml())
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(db),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": ADMIN,
        "HUITZILOPOCHTLI_ADMIN_PASSWORD": "test-pw",
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
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if _http("GET", base + "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "vis-comp", "name": "Vis Comp", "scenario_name": "HTTPComp",
            "scenario_version": 1, "max_players": 4, "duration_s": 3600,
        }, auth)
        assert status == 200, body
        vis = json.loads(body)
        status, _body = _http("POST",
                              base + f"/admin/api/competitions/{vis['id']}/start",
                              {}, auth)

        status, _body = _http("POST", base + "/c/vis-comp/join",
                              urllib.parse.urlencode({"name": "Ada"}),
                              {"Content-Type": "application/x-www-form-urlencoded"})
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        player = conn.execute(
            "SELECT * FROM players WHERE display_name='Ada'").fetchone()
        conn.close()
        assert player is not None
        code = player["join_code_plain"]
        priv, pub = signing.keypair()
        join_body = {
            "join_code": code, "box_id": "box-vis-1",
            "public_key": base64.b64encode(pub).decode(),
            "agent_version": AGENT_VERSION, "scenario_name": "HTTPComp",
            "scenario_version": 1,
        }
        sig = signing.sign(priv, canon.canonicalize(join_body))
        status, body = _http("POST", base + "/join", json.dumps(join_body).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-vis-1",
        })
        assert status == 200, body
        ev = [Evidence(check_id="banner", check_type="file_regex",
                       host_id="localhost", status=CollectorStatus.OK,
                       raw={"matched": "ok", "present": True}, reason="ok",
                       collected_monotonic=0.0, collected_wall_claim=0.0)]
        bundle = Bundle(box_id="box-vis-1", seq=1, boot_id="b",
                        agent_version=AGENT_VERSION, scenario_name="HTTPComp",
                        scenario_version=1, evidence=ev,
                        created_wall_claim=0.0, schema_version=SCHEMA_VERSION)
        bsig = signing.sign(priv, canon.canonicalize(dataclasses.asdict(bundle)))
        status, _body = _http("POST", base + "/checkin",
                              json.dumps(dataclasses.asdict(bundle)).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(bsig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-vis-1",
        })
        assert status == 200, body

        # The board is live: the player's row is visible.
        status, page = _http("GET", base + "/c/vis-comp")
        assert status == 200 and "Ada" in page
        status, body = _http("GET", base + "/api/public/competitions/vis-comp/leaderboard")
        assert json.loads(body)["leaderboard"][0]["name"] == "Ada"

        # Login session for the dashboard route.
        from tests.helpers import login_session
        dash_cookie = login_session(_http_req, port,
                                    username="admin", password="test-pw")

        # Conceal: every read surface shows the quiet note, no standings.
        status, reason = _http("POST",
                               base + f"/admin/api/competitions/{vis['id']}/leaderboard-visibility",
                               {"hidden": 1}, auth)
        assert status in (200, 303), reason
        status, page = _http("GET", base + "/c/vis-comp")
        assert "Standings are hidden by the organizers." in page
        assert "Ada" not in page
        status, page = _http("GET", base + "/c/vis-comp/display")
        assert "Standings are hidden by the organizers." in page
        status, body = _http("GET", base + "/api/public/competitions/vis-comp/leaderboard")
        assert json.loads(body)["leaderboard"] == []

        # The dashboard row flips to the reveal control, matching the
        # concealed state (the session cookie from the login above).
        status, page = _http("GET", base + "/admin",
                             headers={"Cookie": dash_cookie})
        assert "Show leaderboard" in page

        # Revealing restores the standings without re-scoring anything.
        status, body = _http("POST",
                             base + f"/admin/api/competitions/{vis['id']}/leaderboard-visibility",
                             {"hidden": 0}, auth)
        assert status in (200, 303), body
        status, page = _http("GET", base + "/c/vis-comp")
        assert "Ada" in page
        status, body = _http("GET", base + "/api/public/competitions/vis-comp/leaderboard")
        assert json.loads(body)["leaderboard"][0]["name"] == "Ada"

        # The index page live-reloads: its list is inside a data-poll node.
        status, page = _http("GET", base + "/")
        assert status == 200
        assert 'id="home" data-poll=' in page
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        ws.shutdown()


def test_extend_overtime(tmp_path):
    """Admin overtime: running clocks slide, expiry-finished runs resume.

    Everything is engine metadata: no scoring change, no box restart, and the
    portal's reclaim clock gets bumped only when the new deadline closes on
    the claimed VM's portal expiry.
    """
    port = _free_port()
    workshop_port = _free_port()
    db = tmp_path / "engine.db"
    boxes = tmp_path / "boxes" / "ot-comp-box"
    boxes.mkdir(parents=True)
    (boxes / "scenario.yaml").write_text(_scenario_yaml())
    _Workshop.requests = []
    _Workshop.pools = []
    _Workshop.vms = []
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
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    base = f"http://127.0.0.1:{port}"
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        for _ in range(100):
            try:
                if _http("GET", base + "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
        status, body = _http("POST", base + "/admin/api/competitions", {
            "slug": "ot-comp", "name": "OT Comp", "scenario_name": "HTTPComp",
            "scenario_version": 1, "max_players": 4, "duration_s": 3600,
        }, auth)
        assert status == 200, body
        ot = json.loads(body)
        status, body = _http("POST",
                             base + f"/admin/api/competitions/{ot['id']}/start",
                             {}, auth)
        assert status in (200, 303), body

        # A player joins, claims a VM link, and binds a box: status running
        # with a one-hour receipt clock. The claim finishes after the join
        # response now, so wait for it before reading the bound fields.
        status, _page = _http("POST", base + "/c/ot-comp/join",
                              urllib.parse.urlencode({"name": "Ada"}), form)
        # _http follows the PRG redirect; the created row below is the check.
        assert status in (200, 303)
        player = _wait_db(db, "SELECT * FROM players WHERE display_name=?",
                          ("Ada",), "claim_expires_at")
        priv, pub = signing.keypair()
        join_body = {
            "join_code": player["join_code_plain"], "box_id": "box-ot-1",
            "public_key": base64.b64encode(pub).decode(),
            "agent_version": AGENT_VERSION, "scenario_name": "HTTPComp",
            "scenario_version": 1,
        }
        sig = signing.sign(priv, canon.canonicalize(join_body))
        status, body = _http("POST", base + "/join", json.dumps(join_body).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-ot-1",
        })
        assert status == 200, body
        conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
        player = conn.execute(
            "SELECT * FROM players WHERE display_name='Ada'").fetchone()
        conn.close()
        bound_ends = player["ends_at"]

        # Overtime +15: the stored deadline slides by exactly 900s, the
        # public leaderboard shows the longer window, and the portal is not
        # touched (its reclaim clock already has two hours of headroom).
        status, body = _http(
            "POST", base + f"/admin/api/competitions/{ot['id']}/extend",
            urllib.parse.urlencode({"minutes": "15"}), auth)
        assert status == 200, body
        report = json.loads(body)
        assert report["ok"] is True and len(report["extended"]) == 1
        assert report["extended"][0]["player_id"] == player["player_id"]
        assert report["vm_bump"] == {
            "bumped": False, "reason": "portal reclaim clocks have headroom"}
        conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM players WHERE player_id = ?",
                           (player["player_id"],)).fetchone()
        conn.close()
        assert row["ends_at"] == bound_ends + 900
        status, body = _http(
            "GET", base + "/api/public/competitions/ot-comp/leaderboard")
        lead = json.loads(body)["leaderboard"][0]
        assert 900 < lead["remaining_s"] <= 4500  # > the original hour left

        # A deadline that closes on the portal's reclaim clock wakes the
        # bump: every clone of the competition's pool gets pushed.
        _Workshop.vms = [{"vmid": 352, "student_id": "huitz-ranked-ot-comp-1",
                          "pool": "PROV1", "claimed": True, "expired": False,
                          "os": "Linux", "expires_at": row["ends_at"] - 300}]
        conn = sqlite3.connect(db)
        conn.execute("UPDATE players SET claim_expires_at = ? WHERE player_id = ?",
                     (row["ends_at"] - 300, player["player_id"]))
        conn.commit(); conn.close()
        _n_before = len([r for r in _Workshop.requests
                         if r[0] == "/api/admin/extend"])
        status, body = _http(
            "POST", base + f"/admin/api/competitions/{ot['id']}/extend",
            urllib.parse.urlencode({"minutes": "10"}), auth)
        assert status == 200, body
        report = json.loads(body)
        bumps = {"hours": 1, "vmid": 352}
        assert any(r[0] == "/api/admin/extend" and r[2] == bumps
                   for r in _Workshop.requests[_n_before:]), _Workshop.requests
        assert report["vm_bump"]["bumped"] is True
        assert report["vm_bump"]["outcomes"] == [{"vmid": 352, "ok": True}]

        # A run the clock already froze (finished at receipt > ends) resumes
        # on the next extension and scores again.
        conn = sqlite3.connect(db)
        conn.execute("UPDATE players SET ends_at = ? WHERE player_id = ?",
                     (time.time() - 60, player["player_id"]))
        conn.commit(); conn.close()
        ev = [Evidence(check_id="banner", check_type="file_regex",
                       host_id="localhost", status=CollectorStatus.OK,
                       raw={"matched": "ok", "present": True}, reason="ok",
                       collected_monotonic=0.0, collected_wall_claim=0.0)]
        bundle = Bundle(box_id="box-ot-1", seq=2, boot_id="b",
                        agent_version=AGENT_VERSION, scenario_name="HTTPComp",
                        scenario_version=1, evidence=ev,
                        created_wall_claim=0.0, schema_version=SCHEMA_VERSION)
        bsig = signing.sign(priv, canon.canonicalize(dataclasses.asdict(bundle)))
        status, _body = _http("POST", base + "/checkin",
                              json.dumps(dataclasses.asdict(bundle)).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(bsig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-ot-1",
        })
        assert status == 200
        conn = sqlite3.connect(db); conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM players WHERE player_id = ?",
                           (player["player_id"],)).fetchone()
        conn.close()
        assert row["status"] == "finished"
        status, body = _http(
            "POST", base + f"/admin/api/competitions/{ot['id']}/extend",
            urllib.parse.urlencode({"minutes": "10"}), auth)
        assert status == 200, body
        report = json.loads(body)
        assert [r["name"] for r in report["resumed"]] == ["Ada"]
        seq3 = dataclasses.replace(bundle, seq=3)
        bsig = signing.sign(priv, canon.canonicalize(dataclasses.asdict(seq3)))
        status, _body = _http("POST", base + "/checkin",
                              json.dumps(dataclasses.asdict(seq3)).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(bsig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-ot-1",
        })
        assert status == 200
        conn = sqlite3.connect(db)
        st = conn.execute("SELECT status FROM players WHERE player_id = ?",
                          (player["player_id"],)).fetchone()[0]
        conn.close()
        assert st == "running"

        # Refusals: out-of-bounds request, then a non-live competition.
        status, body = _http(
            "POST", base + f"/admin/api/competitions/{ot['id']}/extend",
            urllib.parse.urlencode({"minutes": "0"}), auth)
        assert status == 400 and "between 1 minute" in body
        status, _body = _http("POST",
                              base + f"/admin/api/competitions/{ot['id']}/end",
                              {}, auth)
        assert status in (200, 303)
        status, body = _http(
            "POST", base + f"/admin/api/competitions/{ot['id']}/extend",
            urllib.parse.urlencode({"minutes": "15"}), auth)
        assert status == 409 and "not live" in body
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        ws.shutdown()


def test_admin_api_build_reports_deployment_identity(tmp_path):
    """The admin build endpoint reports the deployment's build_info.json.

    An unauthenticated call is refused; the token call returns the deployed
    commit stamp (None here: the integration server runs from a checkout
    without build_info.json) plus the process start time.
    """
    port = _free_port()
    workshop_port = _free_port()
    db = tmp_path / "engine.db"
    boxes = tmp_path / "boxes" / "ot-comp-box"
    boxes.mkdir(parents=True)
    (boxes / "scenario.yaml").write_text(_scenario_yaml())
    _Workshop.requests = []
    _Workshop.pools = []
    _Workshop.vms = []
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
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    base = f"http://127.0.0.1:{port}"
    started = time.time()
    try:
        for _ in range(100):
            try:
                if _http("GET", base + "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        status, body = _http("GET", base + "/admin/api/build")
        assert status == 403, body
        status, body = _http("GET", base + "/admin/api/build",
                             headers={"X-HUITZILOPOCHTLI-Admin-Token": ADMIN})
        assert status == 200, body
        info = json.loads(body)
        assert info["commit"] is None  # honest unknown for a bare checkout
        assert info["built_at"] is None
        assert started - 5 <= info["started_at"] <= time.time()
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        ws.shutdown()
