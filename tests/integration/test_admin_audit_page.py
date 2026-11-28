"""Integration test for GET /admin/audit -- the audit page
RANKED_COMPETITION.md section 5 promises. Before it existed,
store.list_audit() had no production caller, so "who did what" meant
reading engine.db on the engine host.

Real engine subprocess over real HTTP, like the other admin-console tests:
the point is that a request passes the same admin gate the sibling /admin/*
pages use and renders rows the store actually wrote.
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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


def _spawn_engine(tmp_path, port):
    (tmp_path / "boxes" / "ui-comp-box").mkdir(parents=True)
    (tmp_path / "boxes" / "ui-comp-box" / "scenario.yaml").write_text(
        _SCENARIO_YAML, encoding="utf-8")
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(tmp_path / "engine.db"),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_ADMIN_TOKEN": "audit-test-token",
        "HUITZILOPOCHTLI_ADMIN_USER": "admin",
        "HUITZILOPOCHTLI_ADMIN_PASSWORD": "pass",
        "HUITZILOPOCHTLI_BOXES_DIR": str(tmp_path / "boxes"),
        "PYTHONUNBUFFERED": "1",
    })
    env.pop("HUITZILOPOCHTLI_TLS_CERT", None)
    env.pop("HUITZILOPOCHTLI_TLS_KEY", None)
    return subprocess.Popen([sys.executable, "-m", "engine.server"],
                            cwd=REPO_ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)


def _tbody_rows(page):
    """The rendered body rows -- the filter dropdown lists every competition,
    so assertions about what a filter matched must not read the <head> of the
    document."""
    return page.split("<tbody>")[1].split("</tbody>")[0].split("<tr>")[1:]


def test_admin_audit_page_gates_filters_and_shows_logged_actions(tmp_path):
    port = _free_port()
    proc = _spawn_engine(tmp_path, port)
    auth = {"X-HUITZILOPOCHTLI-Admin-Token": "audit-test-token"}
    try:
        for _ in range(100):
            try:
                if _req(port, "GET", "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        else:
            raise AssertionError("engine did not come up")

        # No admin auth: the same 401 login page the sibling pages give.
        status, body, _ = _req(port, "GET", "/admin/audit")
        assert status == 401 and "Admin login" in body

        # Two actions that write audit rows (one per competition).
        for slug, name in (("audit-a", "Audit Alpha"), ("audit-b", "Audit Beta")):
            status, body, _ = _req(
                port, "POST", "/admin/api/competitions",
                {"slug": slug, "name": name, "scenario_name": "UIComp",
                 "scenario_version": 1, "max_players": 8, "duration_s": 600},
                auth)
            assert status == 200, body

        # With the admin token: the create of each competition, newest first.
        status, page, _ = _req(port, "GET", "/admin/audit", headers=auth)
        assert status == 200, page[:300]
        rows = _tbody_rows(page)
        assert len(rows) == 2, rows
        assert all("competition_create" in r for r in rows)
        assert "Audit Beta" in rows[0] and "Audit Alpha" in rows[1]
        assert "audit-test-token" not in rows[0]  # actor is "token", not the secret
        assert ">token<" in rows[0]

        # The session path, like every other admin page, reached from the
        # dashboard link.
        from tests.helpers import login_session
        cookie = login_session(_req, port)
        status, dash, _ = _req(port, "GET", "/admin", headers={"Cookie": cookie})
        assert status == 200 and 'href="/admin/audit"' in dash
        status, page, _ = _req(port, "GET", "/admin/audit",
                               headers={"Cookie": cookie})
        # The session's own login is audited now (a failed operator login
        # is exactly what the audit log exists for): 2 creates + 1 login.
        rows = _tbody_rows(page)
        assert status == 200 and len(rows) == 3
        assert "admin_login" in rows[0]

        # Competition filter (slug and id both address one competition).
        comps = json.loads(_req(port, "GET", "/admin/api/competitions",
                                headers=auth)[1])
        comp_id = next(c["id"] for c in comps if c["slug"] == "audit-a")
        for needle in ("audit-a", comp_id):
            status, page, _ = _req(port, "GET",
                                   f"/admin/audit?competition={needle}",
                                   headers=auth)
            assert status == 200, page[:300]
            rows = _tbody_rows(page)
            assert len(rows) == 1, rows
            assert "Audit Alpha" in rows[0] and "Audit Beta" not in rows[0]

        # An unknown filter says so instead of quietly showing everything.
        status, page, _ = _req(port, "GET", "/admin/audit?competition=no-such",
                               headers=auth)
        assert status == 200
        assert "No matching audit entries." in page and "no-such" in page
        assert "Audit Alpha" not in page.split("<tbody>")[1]

        # limit: the newest row only -- the session's own login (audited
        # above), not the competition creates.
        status, page, _ = _req(port, "GET", "/admin/audit?limit=1", headers=auth)
        assert status == 200
        rows = _tbody_rows(page)
        assert len(rows) == 1 and "admin_login" in rows[0]
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
