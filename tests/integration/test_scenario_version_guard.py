"""Run attempts validate against the box folder's single current version.

The picker only ever offers current versions, so the guard fires on stale
form posts, hand-rolled API calls, reruns of comps pinned to an older
version, and drafts started after their scenario moved on. Check-in refusal
for stale versions is covered in test_ranked_protocol_errors.py.
"""
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADMIN = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def _req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = dict(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body)
        hdrs["Content-Type"] = "application/json"
    elif isinstance(body, str):
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    conn.request(method, path, body=body, headers=hdrs)
    r = conn.getresponse()
    data = r.read().decode("utf-8", "replace")
    hdrs_out = dict(r.getheaders())
    conn.close()
    return r.status, data, hdrs_out


def _ranked_yaml(name, version):
    return yaml.safe_dump({
        "scenario": {"name": name, "version": version, "mode": "honor",
                     "hosts": ["localhost"]},
        "checks": [{"id": "c1", "type": "file_regex", "category": "vuln",
                    "display": "C1", "max_points": 5,
                    "collect": {"path": "/srv/x", "extract": "X"},
                    "expect": {"equals": "X", "points": 5}}],
        "ranked": {"engine_url": "http://127.0.0.1:8080",
                   "services": [], "adversary": {}},
    })


def _write_scenario(boxes_root, name, version):
    boxes_root.mkdir(parents=True, exist_ok=True)
    (boxes_root / "guard-box").mkdir(exist_ok=True)
    (boxes_root / "guard-box" / "scenario.yaml").write_text(
        _ranked_yaml(name, version))


def _spawn(tmp_path, boxes_root, port):
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(tmp_path / "engine.db"),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": "token",
        "HUITZILOPOCHTLI_ADMIN_PASSWORD": "pass",
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_BOXES_DIR": str(boxes_root),
        "PYTHONUNBUFFERED": "1",
    })
    return subprocess.Popen(
        [sys.executable, "-m", "engine.server"], cwd=REPO_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _wait_health(port, proc):
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError("engine exited during startup")
        try:
            if _req(port, "GET", "/health")[0] == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError("engine never became healthy")


def _login(port):
    status, _b, headers = _req(port, "POST", "/admin/login",
                               "username=admin&password=pass")
    assert status == 303
    return headers["Set-Cookie"].split(";", 1)[0]


def _create_comp(port, slug, version=None, name="Guard Comp"):
    body = {"slug": slug, "name": name, "scenario_name": "Guarded",
            "max_players": 4, "duration_s": 600}
    if version is not None:
        body["scenario_version"] = version
    return _req(port, "POST", "/admin/api/competitions", body, ADMIN)


def test_api_create_defaults_to_current_version(tmp_path):
    """Omitting scenario_version means "the box folder's current one"."""
    port = _free_port()
    boxes = tmp_path / "boxes"
    _write_scenario(boxes, "Guarded", 3)
    proc = _spawn(tmp_path, boxes, port)
    try:
        _wait_health(port, proc)
        status, body, _ = _create_comp(port, "guard-current")
        assert status == 200, body
        assert json.loads(body)["scenario_version"] == 3
    finally:
        proc.terminate(); proc.wait(timeout=5)


def test_api_create_stale_version_is_refused(tmp_path):
    port = _free_port()
    boxes = tmp_path / "boxes"
    _write_scenario(boxes, "Guarded", 2)
    proc = _spawn(tmp_path, boxes, port)
    try:
        _wait_health(port, proc)
        status, body, _ = _create_comp(port, "guard-stale", version=1)
        assert status == 400, body
        assert "not current" in json.loads(body)["error"]
        assert "v2" in json.loads(body)["error"]
    finally:
        proc.terminate(); proc.wait(timeout=5)


def test_form_create_stale_version_is_refused(tmp_path):
    """A stale picker value (hand-rolled POST / old tab) is refused."""
    port = _free_port()
    boxes = tmp_path / "boxes"
    _write_scenario(boxes, "Guarded", 2)
    proc = _spawn(tmp_path, boxes, port)
    try:
        _wait_health(port, proc)
        cookie = _login(port)
        status, page, _ = _req(port, "GET", "/admin/competitions/new",
                               headers={"Cookie": cookie})
        assert 'value="Guarded|2"' in page and ">Guarded</option>" in page
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        status, page, _ = _req(
            port, "POST", "/admin/competitions/new",
            urllib.parse.urlencode({
                "csrf": csrf, "name": "Stale Form", "scenario": "Guarded|1",
                "max_players": "4", "duration_min": "10", "accent": "#5f4a38",
            }),
            {"Cookie": cookie})
        assert status == 400, page
        assert "not current" in page and "v2" in page
    finally:
        proc.terminate(); proc.wait(timeout=5)


def _comp_pinned_to_v1(tmp_path, port, slug):
    """Engine with Guarded@v1, a comp that ran live on it and ended, then the
    box folder bumped to v2 underneath it."""
    boxes = tmp_path / "boxes"
    _write_scenario(boxes, "Guarded", 1)
    proc = _spawn(tmp_path, boxes, port)
    _wait_health(port, proc)
    status, body, _ = _create_comp(port, slug, version=1)
    assert status == 200, body
    comp_id = json.loads(body)["id"]
    # Go live and end while the scenario is still current at v1.
    status, page, _ = _req(port, "POST",
                           f"/admin/api/competitions/{comp_id}/start", {}, ADMIN)
    assert status == 200, page
    status, page, _ = _req(port, "POST",
                           f"/admin/api/competitions/{comp_id}/end", {}, ADMIN)
    assert status == 200 and '"status": "ended"' in page, page
    _write_scenario(boxes, "Guarded", 2)  # the author bumps the version
    return proc, comp_id, None


def test_rerun_refused_after_scenario_bump(tmp_path):
    port = _free_port()
    proc, comp_id, _cookie = _comp_pinned_to_v1(tmp_path, port, "guard-rerun")
    try:
        status, _b, _h = _req(port, "POST",
                              f"/admin/api/competitions/{comp_id}/end", {}, ADMIN)
        assert status in (200, 303)
        # Token-auth path: 409 JSON naming the migration.
        status, page, _ = _req(port, "POST",
                               f"/admin/api/competitions/{comp_id}/rerun",
                               {}, ADMIN)
        assert status == 409, page
        assert "not current" in page and "migrate" in page
    finally:
        proc.terminate(); proc.wait(timeout=5)


def test_start_refused_after_scenario_bump(tmp_path):
    port = _free_port()
    proc, comp_id, _cookie = _comp_pinned_to_v1(tmp_path, port, "guard-start")
    try:
        status, page, _ = _req(port, "POST",
                               f"/admin/api/competitions/{comp_id}/start",
                               {}, ADMIN)
        assert status == 409, page
        assert "not current" in page and "migrate" in page
    finally:
        proc.terminate(); proc.wait(timeout=5)
