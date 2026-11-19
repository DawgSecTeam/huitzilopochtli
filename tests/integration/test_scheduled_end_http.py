"""Scheduled competition end over real HTTP: admin schedules it, competitors
see the countdown, the sweeper ends the competition at the moment without an
operator. Complements tests/unit/test_scheduled_end.py (domain logic) and
test_checkin_run_state.py (check-ins between the moment and the sweep).
"""
import http.client
import json
import os
import datetime
import socket
import subprocess
import sys
import time
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

AUTH = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _req(port, method, path, body=None, headers=None, form=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = dict(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body)
        headers["Content-Type"] = "application/json"
    if isinstance(form, dict):
        body = urllib.parse.urlencode(form)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    r = conn.getresponse()
    data = r.read().decode("utf-8", "replace")
    hdrs = dict(r.getheaders())
    conn.close()
    return r.status, data, hdrs


_SCENARIO_YAML = """scenario:
  name: SchedComp
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
    box = boxes_root / "sched-comp-box"
    box.mkdir(exist_ok=True)
    (box / "scenario.yaml").write_text(_SCENARIO_YAML)


def _start_server(tmp_path):
    port = _free_port()
    _write_box_scenario(tmp_path / "boxes")
    env = dict(os.environ)
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(tmp_path / "engine.db"),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": "token",
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_BOXES_DIR": str(tmp_path / "boxes"),
        # Minimum interval: the scheduled-end sweep rides this loop.
        "HUITZILOPOCHTLI_SWEEP_INTERVAL_S": "5",
        "PYTHONUNBUFFERED": "1",
    })
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"],
                            cwd=REPO_ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    try:
        for _ in range(100):
            try:
                if _req(port, "GET", "/health")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            raise AssertionError("engine did not come up")
        return port, proc
    except BaseException:
        proc.kill()
        raise


def _create_competition(port, slug):
    status, data, _ = _req(port, "POST", "/admin/api/competitions", body={
        "name": "Scheduled End Test", "slug": slug,
        "scenario_name": "SchedComp", "scenario_version": 1,
        "max_players": 8, "duration_s": 3600,
    }, headers=AUTH)
    assert status == 200, data
    return json.loads(data)


def _schedule(port, comp_id, when=None):
    """POST schedule-end; ``when`` is an epoch or None (cancel)."""
    value = "" if when is None else datetime.datetime.fromtimestamp(
        when).strftime("%Y-%m-%dT%H:%M:%S")
    return _req(port, "POST", f"/admin/api/competitions/{comp_id}/schedule-end",
                form={"ends_at": value}, headers=AUTH)


def test_schedule_end_shows_countdown_and_fires(tmp_path):
    port, proc = _start_server(tmp_path)
    try:
        comp = _create_competition(port, "sched-e2e")
        comp_id = comp["id"]
        status, data, _ = _req(port, "POST",
                               f"/admin/api/competitions/{comp_id}/start",
                               form={}, headers=AUTH)
        assert status == 200, data

        # Garbage and past times are refused with a usable message.
        status, data, _ = _schedule(port, comp_id, when=None)
        assert status == 200  # cancelling a not-yet-scheduled end is a no-op ok
        status, data, _ = _req(port, "POST",
                               f"/admin/api/competitions/{comp_id}/schedule-end",
                               form={"ends_at": "not-a-time"}, headers=AUTH)
        assert status == 400 and "could not read" in json.loads(data)["error"]
        status, data, _ = _req(port, "POST",
                               f"/admin/api/competitions/{comp_id}/schedule-end",
                               form={"ends_at": "2020-01-01T00:00:00"},
                               headers=AUTH)
        assert status == 400 and "past" in json.loads(data)["error"]

        # Schedule the end ~12 s out (whole seconds: the datetime-local
        # wire format carries no sub-second precision) and make it visible
        # everywhere.
        when = int(time.time()) + 12
        status, data, _ = _schedule(port, comp_id, when)
        assert status == 200, data
        assert json.loads(data)["scheduled_end_at"] == when

        status, data, _ = _req(port, "GET", f"/admin/api/competitions/{comp_id}",
                               headers=AUTH)
        assert json.loads(data)["competition"]["scheduled_end_at"] == when
        status, data, _ = _req(port, "GET",
                               "/api/public/competitions/sched-e2e")
        assert json.loads(data)["scheduled_end_at"] == when

        # The competitor-facing board counts down to it...
        status, page, _ = _req(port, "GET", "/c/sched-e2e")
        assert status == 200
        assert "ends in" in page and "data-remaining" in page
        # ...and the admin page carries the control + the live countdown.
        status, page, _ = _req(port, "GET", f"/admin/competitions/{comp_id}",
                               headers=AUTH)
        assert status == 200
        assert "Scheduled end" in page and "datetime-local" in page

        # Cancel clears it again.
        status, data, _ = _schedule(port, comp_id, when=None)
        assert status == 200
        status, data, _ = _req(port, "GET",
                               "/api/public/competitions/sched-e2e")
        assert json.loads(data)["scheduled_end_at"] is None

        # Now schedule for real and wait out the sweeper: no operator, the
        # competition ends itself at the wall time.
        when = int(time.time()) + 12
        status, data, _ = _schedule(port, comp_id, when)
        assert status == 200, data
        deadline = time.time() + 45
        payload = None
        while time.time() < deadline:
            _, data, _ = _req(port, "GET",
                              "/api/public/competitions/sched-e2e")
            payload = json.loads(data)
            if payload["status"] == "ended":
                break
            time.sleep(1)
        assert payload["status"] == "ended", payload
        assert payload["ended_at"] is not None
        assert payload["can_join"] is False
        # The fired schedule is kept for the record.
        assert payload["scheduled_end_at"] == when
    finally:
        proc.kill()
        proc.wait()
