"""Two competitions live at once, over real HTTP + a fake workshop portal.

The point of this test is isolation, not scoring: each competition provisions
its own portal pool, and ending one must destroy only its own clones. The
``demo`` / ``demo-2`` slug pair is deliberate -- End followed by Rerun creates
exactly that, and the portal names clones ``<pool name>-<n>``, so a slug-prefix
match used to destroy the sibling's running boxes.
"""
import base64
import http.client
import json
import os
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

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADMIN = "multi-admin-token"
PORTAL_PW = "portal-pw"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http(method, url, body=None, headers=None):
    data = None
    headers = dict(headers or {})
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        else:
            data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _post_form(port, path, fields):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", path, body=urllib.parse.urlencode(fields),
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


class _Portal(BaseHTTPRequestHandler):
    pools = []
    vms = []
    destroyed = []
    counter = 0

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
        return self.headers.get("Authorization", "") == (
            "Basic " + base64.b64encode(f"admin:{PORTAL_PW}".encode()).decode())

    def do_GET(self):
        if self.path == "/api/admin/pools":
            if not self._admin():
                return self._reply(403, {"detail": "admin auth required"})
            return self._reply(200, list(type(self).pools))
        if self.path == "/api/admin/pool":
            if not self._admin():
                return self._reply(403, {"detail": "admin auth required"})
            return self._reply(200, list(type(self).vms))
        if self.path.startswith("/api/redeem/"):
            return self._reply(200, {"status": "ready",
                                     "open_url": "http://portal.example/r/u1",
                                     "uid": "u1"})
        self._reply(404, {"detail": "not found"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw or b"{}")
        if self.path == "/api/admin/provision":
            if not self._admin():
                return self._reply(403, {"detail": "admin auth required"})
            type(self).counter += 1
            code = f"P{type(self).counter}"
            type(self).pools.append({
                "code": code, "name": body.get("pool_name"), "available": 0,
                "total": 0, "in_use": 0, "count": 1,
                "config": {"template_vm_id": body.get("template_vm_id"),
                           "pool_name": body.get("pool_name"),
                           "pool_code": code},
            })
            return self._reply(200, {"job_id": "j1"})
        if self.path == "/api/admin/destroy":
            if not self._admin():
                return self._reply(403, {"detail": "admin auth required"})
            ids = [int(v) for v in body.get("vmids") or []]
            type(self).destroyed.append(ids)
            type(self).vms = [v for v in type(self).vms
                              if int(v["vmid"]) not in ids]
            return self._reply(200, {"status": "done"})
        if self.path == "/api/claim":
            type(self).counter += 1
            uid = f"u{type(self).counter}"
            return self._reply(200, {
                "status": "ready", "open_url": f"http://portal.example/r/{uid}",
                "url": "http://guac.example/session/abc", "uid": uid,
                "expires_at": time.time() + 7200})
        if self.path in ("/api/prebind", "/api/release"):
            return self._reply(200, {"ok": True})
        self._reply(404, {"detail": "not found"})

    def do_DELETE(self):
        if self.path.startswith("/api/admin/pools/"):
            code = self.path.rsplit("/", 1)[1]
            type(self).pools = [p for p in type(self).pools
                                if p["code"] != code]
            return self._reply(200, {"removed": True})
        self._reply(404, {"detail": "not found"})


def _scenario_yaml():
    return yaml.safe_dump({
        "scenario": {"name": "MultiComp", "version": 1, "mode": "honor",
                     "hosts": ["localhost"]},
        "checks": [{"id": "banner", "type": "file_regex", "category": "vuln",
                    "display": "Banner", "max_points": 10,
                    "collect": {"path": "/srv/banner", "extract": "B"},
                    "expect": {"equals": "ok", "points": 10}}],
        "ranked": {
            "engine_url": "http://127.0.0.1:8080",
            "services": [],
            "adversary": {},
            "pool": {"template_vm_id": 174, "template_vm_access_method": "ssh",
                     "template_vm_username": "sysadmin",
                     "template_vm_password": "asdf", "vm_count": 1},
        },
    })


def test_two_live_competitions_tear_down_independently(tmp_path):
    port = _free_port()
    portal_port = _free_port()
    _Portal.pools = []
    _Portal.vms = []
    _Portal.destroyed = []
    _Portal.counter = 0
    db = tmp_path / "engine.db"
    box = tmp_path / "boxes" / "multi-comp"
    box.mkdir(parents=True)
    (box / "scenario.yaml").write_text(_scenario_yaml())
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(db),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": ADMIN,
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_WORKSHOP_URL": f"http://127.0.0.1:{portal_port}",
        "HUITZILOPOCHTLI_WORKSHOP_SECRET": "ws-secret",
        "HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD": PORTAL_PW,
        "HUITZILOPOCHTLI_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "HUITZILOPOCHTLI_BOXES_DIR": str(tmp_path / "boxes"),
        "PYTHONUNBUFFERED": "1",
    })
    portal = ThreadingHTTPServer(("127.0.0.1", portal_port), _Portal)
    threading.Thread(target=portal.serve_forever, daemon=True).start()
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"],
                            cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    auth = {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}
    try:
        for _ in range(100):
            try:
                if _http("GET", base + "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)

        def create(slug, name):
            status, body = _http("POST", base + "/admin/api/competitions", {
                "slug": slug, "name": name, "scenario_name": "MultiComp",
                "scenario_version": 1, "max_players": 8, "duration_s": 3600,
            }, auth)
            assert status == 200, body
            comp = json.loads(body)
            status, body = _http(
                "POST", base + f"/admin/api/competitions/{comp['id']}/start",
                {}, auth)
            assert status in (200, 303), body
            return comp

        first = create("demo", "Demo")
        second = create("demo-2", "Demo Two")

        assert _post_form(port, "/c/demo/join", {"name": "Ada"}) == 303
        assert _post_form(port, "/c/demo-2/join", {"name": "Bob"}) == 303

        # Each first claim provisions that competition's own pool — outside
        # the join request now, so wait for both pins before teardown asserts.
        deadline = time.time() + 15
        rows = {}
        while time.time() < deadline:
            conn = sqlite3.connect(db)
            conn.row_factory = sqlite3.Row
            rows = {r["slug"]: r for r in conn.execute(
                "SELECT slug, workshop_pool_code, workshop_pool_name "
                "FROM competitions")}
            conn.close()
            if (rows["demo"]["workshop_pool_code"]
                    and rows["demo-2"]["workshop_pool_code"]):
                break
            time.sleep(0.2)
        code_a = rows["demo"]["workshop_pool_code"]
        code_b = rows["demo-2"]["workshop_pool_code"]
        assert code_a and code_b and code_a != code_b
        assert rows["demo"]["workshop_pool_name"] == "huitz-ranked-demo"
        assert rows["demo-2"]["workshop_pool_name"] == "huitz-ranked-demo-2"

        # Clones as the portal names them. 201/202 belong to demo-2 and must
        # survive demo's teardown even though "huitz-ranked-demo" is a string
        # prefix of their ids.
        _Portal.vms = [
            {"vmid": 101, "pool": code_a, "claimed": True,
             "student_id": "huitz-ranked-demo-1"},
            {"vmid": 201, "pool": code_b, "claimed": True,
             "student_id": "huitz-ranked-demo-2-1"},
            {"vmid": 202, "pool": code_b, "claimed": True,
             "student_id": "huitz-ranked-demo-2-2"},
        ]

        status, body = _http(
            "POST", base + f"/admin/api/competitions/{first['id']}/end",
            {}, auth)
        assert status in (200, 303), body
        assert _Portal.destroyed == [[101]], _Portal.destroyed
        assert {p["code"] for p in _Portal.pools} == {code_b}

        # demo-2 is untouched and still live.
        status, body = _http("GET", base + "/api/public/competitions/demo-2")
        assert status == 200 and json.loads(body)["status"] == "live"

        # A scenario-wide board is ambiguous now; the explicit one is not.
        status, body = _http("GET", base + "/leaderboard?scenario=MultiComp")
        assert status == 400, body
        assert {c["slug"] for c in json.loads(body)["competitions"]} == {
            "demo", "demo-2"}
        status, body = _http("GET",
                             base + "/leaderboard?scenario=MultiComp"
                                  "&competition=demo-2")
        assert status == 200, body
        assert isinstance(json.loads(body), list)

        # Ending the second one destroys exactly its two clones.
        status, body = _http(
            "POST", base + f"/admin/api/competitions/{second['id']}/end",
            {}, auth)
        assert status in (200, 303), body
        assert _Portal.destroyed[-1] == [201, 202], _Portal.destroyed
        assert _Portal.pools == []
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        portal.shutdown()
