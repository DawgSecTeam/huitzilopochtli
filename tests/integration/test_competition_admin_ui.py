"""Admin console authentication/CSRF smoke test over real HTTP."""
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = dict(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body)
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=headers)
    r = conn.getresponse()
    data = r.read().decode("utf-8", "replace")
    hdrs = dict(r.getheaders())
    conn.close()
    return r.status, data, hdrs


def _rubric():
    return {"schema_version": 1, "scenario_name": "UIComp", "scenario_version": 1,
            "entries": [{"check_id": "banner", "category": "vuln",
                         "matcher": {"tag": "equals", "value": "ok"},
                         "points": 10, "sla": None}]}


_SCENARIO_YAML = """scenario:
  name: UIComp
  version: 1
  mode: honor
  hosts: ["localhost"]
checks:
  - id: banner
    type: file_regex
    category: vuln
    display: Banner
    max_points: 10
    collect:
      path: /srv/banner
      extract: B
    expect:
      equals: ok
      points: 10
ranked:
  engine_url: http://127.0.0.1:8080
  services: []
  adversary: {}
"""


def _write_box_scenario(boxes_root):
    boxes_root.mkdir(parents=True, exist_ok=True)
    (boxes_root / "ui-comp-box").mkdir(exist_ok=True)
    (boxes_root / "ui-comp-box" / "scenario.yaml").write_text(_SCENARIO_YAML)



def test_admin_login_page_start_and_csrf(tmp_path):
    port = _free_port()
    _write_box_scenario(tmp_path / "boxes")
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(tmp_path / "engine.db"),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": "token",
        "HUITZILOPOCHTLI_ADMIN_PASSWORD": "pass",
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_BOXES_DIR": str(tmp_path / "boxes"),
        "PYTHONUNBUFFERED": "1",
    })
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"], cwd=REPO_ROOT,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(100):
            try:
                if _req(port, "GET", "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}
        status, body, _ = _req(port, "POST", "/admin/api/competitions", {
            "slug": "ui-comp", "name": "UI Comp", "scenario_name": "UIComp",
            "scenario_version": 1, "max_players": 8, "duration_s": 600,
        }, auth)
        assert status == 200, body
        comp_id = json.loads(body)["id"]

        status, body, _ = _req(port, "GET", "/admin")
        assert status == 401 and "Admin login" in body

        # The hidden component reference is admin-gated like the rest.
        status, body, _ = _req(port, "GET", "/admin/styleguide")
        assert status == 401 and "Admin login" in body

        status, _body, headers = _req(
            port, "POST", "/admin/login",
            "username=admin&password=pass",
            {"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, dashboard, _ = _req(port, "GET", "/admin", headers={"Cookie": cookie})
        assert status == 200 and "Admin console" in dashboard
        assert 'id="theme-toggle"' in dashboard and 'data-poll="30000"' in dashboard
        status, styleguide, _ = _req(port, "GET", "/admin/styleguide",
                                     headers={"Cookie": cookie})
        assert status == 200 and ">Styleguide<" in styleguide
        assert 'action="/admin/logout"' in styleguide and 'class="sdot ok"' in styleguide
        status, comp_page, _ = _req(
            port, "GET", f"/admin/competitions/{comp_id}", headers={"Cookie": cookie})
        assert status == 200
        assert 'data-poll="15000"' in comp_page
        csrf = re.search(r'name="csrf" value="([^"]+)"', comp_page).group(1)

        # Missing CSRF is rejected.
        status, body, _ = _req(
            port, "POST", f"/admin/api/competitions/{comp_id}/start",
            "", {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 403, body

        status, _body, _ = _req(
            port, "POST", f"/admin/api/competitions/{comp_id}/start",
            urllib.parse.urlencode({"csrf": csrf}),
            {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        status, page, _ = _req(port, "GET", "/c/ui-comp")
        assert status == 200 and 'data-tip="Live"' in page and "Join this competition" in page
        # The public board polls in place and has a <noscript> meta fallback.
        assert 'data-poll="' in page and "<noscript><meta http-equiv=" in page

        # Rerun: end the competition, then rerun it into a fresh draft.
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}
        assert _req(port, "POST", f"/admin/api/competitions/{comp_id}/end", {}, auth)[0] in (200, 303)
        status, _body, headers = _req(
            port, "POST", f"/admin/api/competitions/{comp_id}/rerun",
            urllib.parse.urlencode({"csrf": csrf}),
            {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303, _body
        new_location = headers.get("Location", "")
        assert new_location.startswith("/admin/competitions/") \
            and new_location != f"/admin/competitions/{comp_id}"
        status, new_page, _ = _req(port, "GET", new_location, headers={"Cookie": cookie})
        assert status == 200 and 'data-tip="Draft"' in new_page and "Start competition" in new_page

        # Public index hides the ended competition; the admin view shows it.
        status, idx, _ = _req(port, "GET", "/")
        assert status == 200 and "UI Comp" not in idx
        status, idx_admin, _ = _req(port, "GET", "/", headers={"Cookie": cookie})
        assert "UI Comp" in idx_admin
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_reissue_shows_the_fresh_code_once_and_roster_never(tmp_path):
    """The roster renders no join codes; a session reissue surfaces the fresh
    code exactly once via the one-time flash, never in the URL."""
    import sqlite3
    port = _free_port()
    _write_box_scenario(tmp_path / "boxes")
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(tmp_path / "engine.db"),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": "token",
        "HUITZILOPOCHTLI_ADMIN_PASSWORD": "pass",
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_BOXES_DIR": str(tmp_path / "boxes"),
        "PYTHONUNBUFFERED": "1",
    })
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"], cwd=REPO_ROOT,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(100):
            try:
                if _req(port, "GET", "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}
        status, body, _ = _req(port, "POST", "/admin/api/competitions", {
            "slug": "ui-comp", "name": "UI Comp", "scenario_name": "UIComp",
            "scenario_version": 1, "max_players": 8, "duration_s": 600,
        }, auth)
        assert status == 200, body
        comp_id = json.loads(body)["id"]
        assert _req(port, "POST", f"/admin/api/competitions/{comp_id}/start",
                    {}, auth)[0] in (200, 303)

        # A player joins through the public form. No portal is configured, so
        # the claim errors and the player stays invited with a live code —
        # exactly the state that used to print the code in the roster.
        status, _body, headers = _req(
            port, "POST", "/c/ui-comp/join",
            urllib.parse.urlencode({"name": "Ada"}),
            {"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303, _body

        status, _body, headers = _req(
            port, "POST", "/admin/login",
            "username=admin&password=pass",
            {"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, comp_page, _ = _req(
            port, "GET", f"/admin/competitions/{comp_id}", headers={"Cookie": cookie})
        assert status == 200
        csrf = re.search(r'name="csrf" value="([^"]+)"', comp_page).group(1)
        db = sqlite3.connect(str(tmp_path / "engine.db"))
        original_code, player_id = db.execute(
            "SELECT join_code_plain, player_id FROM players"
            " WHERE display_name='Ada'").fetchone()
        db.close()
        assert original_code and player_id
        # The plaintext code never reaches the roster.
        assert original_code not in comp_page

        status, _body, headers = _req(
            port, "POST", f"/admin/players/{player_id}/reissue",
            urllib.parse.urlencode({"csrf": csrf}),
            {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303, _body
        # The fresh code must not ride in the redirect URL.
        assert headers.get("Location") == f"/admin/competitions/{comp_id}"

        status, page, _ = _req(
            port, "GET", f"/admin/competitions/{comp_id}", headers={"Cookie": cookie})
        assert status == 200
        assert "Reissued code for Ada:" in page
        fresh = page.split("Reissued code for Ada:")[1].split("<")[0].strip()
        assert fresh and fresh != original_code
        assert original_code not in page

        # One-time: the banner (and the code) are gone on the next load.
        status, page2, _ = _req(
            port, "GET", f"/admin/competitions/{comp_id}", headers={"Cookie": cookie})
        assert "Reissued code for" not in page2
        assert fresh not in page2
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_picker_ignores_uploaded_records_without_a_box_folder(tmp_path):
    """The deployed engine has no repo `boxes/` dir: uploaded scenarios must
    still be selectable and creatable from the admin form."""
    port = _free_port()
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(tmp_path / "engine.db"),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": "token",
        "HUITZILOPOCHTLI_ADMIN_PASSWORD": "pass",
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        # Deliberately absent: mirrors /opt/huitzilopochtli/engine on the VM.
        "HUITZILOPOCHTLI_BOXES_DIR": str(tmp_path / "no-such-boxes"),
        "PYTHONUNBUFFERED": "1",
    })
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"], cwd=REPO_ROOT,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(100):
            try:
                if _req(port, "GET", "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        auth = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}
        status, body, _ = _req(port, "POST", "/admin/scenarios", {
            "rubric": _rubric(), "adversary": {}, "services": [], "mode": "ranked",
        }, auth)
        assert status == 200, body

        status, _body, headers = _req(
            port, "POST", "/admin/login",
            "username=admin&password=pass",
            {"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303
        cookie = headers["Set-Cookie"].split(";", 1)[0]

        # The picker is the box folder, full stop: an uploaded record with no
        # box folder behind it is never offered (the upload only seeds the
        # serving cache for tooling; with no folder to contradict it, an API
        # create by exact name still works, but the form has nothing to pick).
        status, page, _ = _req(port, "GET", "/admin/competitions/new",
                               headers={"Cookie": cookie})
        assert status == 200
        assert 'value="UIComp|1"' not in page, page
        assert "No ranked scenarios found" in page
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)

        auth = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}
        status, body, _ = _req(port, "POST", "/admin/api/competitions", {
            "slug": "ui-upload-comp", "name": "UI Upload Comp",
            "scenario_name": "UIComp", "scenario_version": 1,
            "max_players": 4, "duration_s": 600,
        }, auth)
        assert status == 200, body
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
