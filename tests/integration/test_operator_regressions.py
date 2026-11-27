"""Regression tests for four operator-facing defects found in the live UI.

1. Seat math for disqualified players. First fix (2026-11-06) freed the
   seat because disqualify released the VM; the boss directive of
   2026-11-08 (§7.1) supersedes it: disqualified players keep playing
   their full clock, so they keep their box AND seat, and only Remove
   frees both. The test below pins the directive.
2. Reissuing a join code cleared ``claim_error``, so the roster stopped
   explaining why the claim kept failing while it still was failing.
3. A disqualified roster row rendered no actions at all; the row now
   offers Reinstate (the run is still alive) and Remove, the one verb
   that releases the box and frees the name.
4. "migrate the competition" named a verb that does not exist; the stale-
   version refusals must name the real exit (discard and recreate from the
   current scenario via the admin console's New competition page).

Run: /usr/bin/python3 -m pytest tests/integration/test_operator_regressions.py -q
"""
import http.client
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.parse

import pytest

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


_SCENARIO_YAML = """scenario:
  name: OpReg
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


def _launch(tmp_path):
    """Start an engine with a v1 box scenario; returns (port, env-style auth)."""
    port = _free_port()
    boxes = tmp_path / "boxes"
    (boxes / "opreg-box").mkdir(parents=True)
    (boxes / "opreg-box" / "scenario.yaml").write_text(_SCENARIO_YAML)
    env = dict(os.environ)
    for key in ("HUITZILOPOCHTLI_WORKSHOP_URL", "HUITZILOPOCHTLI_WORKSHOP_SECRET",
                "HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD"):
        env.pop(key, None)  # no portal: joins leave the player invited + claim_error
    env.update({
        "HUITZILOPOCHTLI_DB_PATH": str(tmp_path / "engine.db"),
        "HUITZILOPOCHTLI_PORT": str(port),
        "HUITZILOPOCHTLI_ADMIN_TOKEN": "token",
        "HUITZILOPOCHTLI_ADMIN_PASSWORD": "pass",
        "HUITZILOPOCHTLI_BIND": "127.0.0.1",
        "HUITZILOPOCHTLI_BOXES_DIR": str(boxes),
        "HUITZILOPOCHTLI_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "PYTHONUNBUFFERED": "1",
    })
    proc = subprocess.Popen([sys.executable, "-m", "engine.server"], cwd=REPO_ROOT,
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    for _ in range(150):
        try:
            if _req(port, "GET", "/health")[0] == 200:
                return proc, port
        except Exception:
            pass
        time.sleep(0.1)
    proc.terminate()
    raise AssertionError("engine never became healthy:\n" + proc.stdout.read())


def _admin_login(port):
    from tests.helpers import login_session
    return login_session(_req, port)


def _live_comp(port, max_players):
    auth = {"X-HUITZILOPOCHTLI-Admin-Token": "token"}
    status, body, _ = _req(port, "POST", "/admin/api/competitions", {
        "slug": "opreg", "name": "Op Reg", "scenario_name": "OpReg",
        "scenario_version": 1, "max_players": max_players, "duration_s": 600,
    }, auth)
    assert status == 200, body
    comp_id = json.loads(body)["id"]
    assert _req(port, "POST", f"/admin/api/competitions/{comp_id}/start",
                {}, auth)[0] in (200, 303)
    return auth, comp_id


def _join(port, name):
    return _req(port, "POST", "/c/opreg/join",
                urllib.parse.urlencode({"name": name}),
                {"Content-Type": "application/x-www-form-urlencoded"})


def _api_players(port, auth, comp_id):
    status, body, _ = _req(port, "GET", f"/admin/api/competitions/{comp_id}",
                           headers=auth)
    assert status == 200, body
    return json.loads(body)


# --- defect 1 (§7.1 directive): DQ keeps seat+box; Remove frees them ------


def test_disqualified_player_keeps_the_seat_until_removed(tmp_path):
    """§7.1 (boss directive): the disqualified keep playing the normal time,
    so their seat -- a box handed out -- stays theirs. The count frees only
    on Remove. Their score is excluded from the board (separate assertion)
    and the roster row offers Reinstate plus Remove."""
    proc, port = _launch(tmp_path)
    try:
        auth, comp_id = _live_comp(port, max_players=2)

        assert _join(port, "Ada")[0] == 303
        assert _join(port, "Bob")[0] == 303

        # Full: a third join is refused while both slots are occupied.
        status, body, _ = _join(port, "Eve")
        assert status == 400 and "full" in body.lower(), (status, body[:300])

        data = _api_players(port, auth, comp_id)
        assert data["competition"]["player_count"] == 2
        ada = next(p for p in data["players"] if p["name"] == "Ada")

        status, body, _ = _req(port, "POST",
                               f"/admin/players/{ada['player_id']}/disqualify",
                               {}, auth)
        assert status == 200, body

        # The run keeps its seat: Ada still holds her box and clock.
        data = _api_players(port, auth, comp_id)
        assert data["competition"]["player_count"] == 2, (
            "a disqualified run that keeps playing keeps its seat")
        status, body, _ = _join(port, "Eve")
        assert status == 400 and "full" in body.lower(), (
            "the seat Ada keeps playing on must not be double-booked")

        # Roster: the row wears the Disqualified badge, offers Reinstate
        # and Remove, and never a second Disqualify.
        cookie = _admin_login(port)
        status, roster, _ = _req(port, "GET", f"/admin/competitions/{comp_id}",
                                 headers={"Cookie": cookie})
        assert status == 200
        assert "Ada" in roster
        assert 'data-tip="Disqualified"' in roster
        assert f'action="/admin/players/{ada["player_id"]}/reinstate"' in roster
        assert f'action="/admin/players/{ada["player_id"]}/remove"' in roster
        assert f'/admin/players/{ada["player_id"]}/disqualify' not in roster
        # A live row still gets its normal action set (Bob never claimed a
        # box -- no portal -- so he is invited and offers Reissue/Remove).
        bob = next(p for p in _api_players(port, auth, comp_id)["players"]
                   if p["name"] == "Bob")
        assert f'/admin/players/{bob["player_id"]}/reissue' in roster

        # Reinstate puts Ada back on the board with the same box.
        status, body, _ = _req(port, "POST",
                               f"/admin/players/{ada['player_id']}/reinstate",
                               {}, auth)
        assert status == 200, body
        ada = next(p for p in _api_players(port, auth, comp_id)["players"]
                   if p["name"] == "Ada")
        assert ada["status"] == "running"

        # Remove is the exit that frees the seat (and the box).
        status, body, _ = _req(port, "POST",
                               f"/admin/players/{ada['player_id']}/remove",
                               {}, auth)
        assert status == 200, body
        data = _api_players(port, auth, comp_id)
        assert data["competition"]["player_count"] == 1
        status, body, _ = _join(port, "Eve")
        assert status == 303, (
            f"Remove must free the seat for a new join; got {status}: "
            f"{body[:300]}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# --- defect 2: reissue must keep the claim_error visible ----------------------


def _claim_error(db_path, player_id):
    conn = sqlite3.connect(str(db_path), timeout=10)
    try:
        row = conn.execute(
            "SELECT claim_error FROM players WHERE player_id = ?",
            (player_id,)).fetchone()
        return None if row is None else row[0]
    finally:
        conn.close()


def test_reissue_keeps_the_claim_error_visible(tmp_path):
    proc, port = _launch(tmp_path)
    try:
        auth, comp_id = _live_comp(port, max_players=8)

        # No portal is configured, so the claim fails and records why.
        assert _join(port, "Ada")[0] == 303
        data = _api_players(port, auth, comp_id)
        ada = next(p for p in data["players"] if p["name"] == "Ada")
        first_error = _claim_error(tmp_path / "engine.db", ada["player_id"])
        assert first_error, (
            "a failed claim must record a claim_error before this test means "
            f"anything; player row: {json.dumps(ada)}")

        status, body, _ = _req(port, "POST",
                               f"/admin/players/{ada['player_id']}/reissue",
                               {}, auth)
        assert status == 200, body
        assert json.loads(body)["ok"] is True

        # The claim failure is still on the record next to the new code.
        kept = _claim_error(tmp_path / "engine.db", ada["player_id"])
        assert kept == first_error, (
            "reissue must keep the claim_error that explains the still-live "
            f"failure; was {first_error!r}, now {kept!r}")

        # And the roster row still explains the failure.
        cookie = _admin_login(port)
        status, roster, _ = _req(port, "GET", f"/admin/competitions/{comp_id}",
                                 headers={"Cookie": cookie})
        assert status == 200
        assert "Ada" in roster
        assert first_error in roster, (
            "the roster row must still show why the claim keeps failing")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# --- defect 3: disqualified row -> Remove works over HTTP ---------------------


def test_remove_a_disqualified_player_from_the_roster(tmp_path):
    proc, port = _launch(tmp_path)
    try:
        auth, comp_id = _live_comp(port, max_players=8)
        assert _join(port, "Ada")[0] == 303
        data = _api_players(port, auth, comp_id)
        ada = next(p for p in data["players"] if p["name"] == "Ada")
        assert _req(port, "POST",
                    f"/admin/players/{ada['player_id']}/disqualify",
                    {}, auth)[0] == 200

        # Remove is now offered on the disqualified row and it works: the
        # tombstone frees the name and the row leaves the rendered roster.
        assert _req(port, "POST",
                    f"/admin/players/{ada['player_id']}/remove",
                    {}, auth)[0] == 200
        cookie = _admin_login(port)
        status, roster, _ = _req(port, "GET", f"/admin/competitions/{comp_id}",
                                 headers={"Cookie": cookie})
        assert status == 200 and "Ada" not in roster
        assert _join(port, "Ada")[0] == 303, (
            "removing a disqualified player must free the name for a new join")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# --- defect 4: stale-version refusals name the real exit ----------------------

_GONE = ("migrate the competition", "migrate this competition")


def test_stale_form_submission_names_discard_and_recreate(tmp_path):
    """The admin 'new competition' form POSTed with a version the box folder
    has moved past must name the real exit (discard/recreate via the console)
    and never invent a 'migrate' verb."""
    proc, port = _launch(tmp_path)
    try:
        cookie = _admin_login(port)
        status, page, _ = _req(port, "GET", "/admin/competitions/new",
                               headers={"Cookie": cookie})
        assert status == 200
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        # Bump the box to v2 so the form's pinned v1 option goes stale.
        box = tmp_path / "boxes" / "opreg-box" / "scenario.yaml"
        box.write_text(_SCENARIO_YAML.replace("version: 1", "version: 2"))
        status, page, _ = _req(
            port, "POST", "/admin/competitions/new",
            urllib.parse.urlencode({"csrf": csrf, "name": "Stale Draft",
                                    "scenario": "OpReg|1", "max_players": "2",
                                    "duration_min": "60"}),
            {"Cookie": cookie,
             "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 400, page[:300]  # error re-render of the form
        assert "not current" in page, page[:400]
        assert "v2" in page
        for verb in _GONE:
            assert verb not in page, (
                f"the refusal still says {verb!r}; there is no migrate verb")
        assert "discard this submission" in page and \
            "recreate the competition" in page, (
            "the refusal must name the real exit: discard and recreate from "
            "the current scenario on the admin console")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_new_competition_form_persists_the_member_cap(tmp_path):
    """The form's max-members-per-team field lands on the competition row:
    it is the cap the self-serve team join reads back on every registration."""
    proc, port = _launch(tmp_path)
    try:
        cookie = _admin_login(port)
        status, page, _ = _req(port, "GET", "/admin/competitions/new",
                               headers={"Cookie": cookie})
        assert status == 200
        assert 'name="max_team_members"' in page
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        status, page, _ = _req(
            port, "POST", "/admin/competitions/new",
            urllib.parse.urlencode({"csrf": csrf, "name": "Capped Draft",
                                    "scenario": "OpReg|1", "max_players": "2",
                                    "max_team_members": "4",
                                    "duration_min": "60"}),
            {"Cookie": cookie,
             "Content-Type": "application/x-www-form-urlencoded"})
        assert status == 303, page[:300]
        conn = sqlite3.connect(tmp_path / "engine.db")
        try:
            row = conn.execute(
                "SELECT max_players, max_team_members FROM competitions "
                "WHERE name = 'Capped Draft'").fetchone()
        finally:
            conn.close()
        assert row == (2, 4), row
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_create_competition_message_names_the_real_exit(tmp_path, monkeypatch):
    """engine.competition.create_competition (the shared guard) refuses a
    non-current version with the discard/recreate exit, not a fake verb."""
    from engine import competition, scenario as scenario_mod
    from engine.store import Store

    boxes = tmp_path / "boxes"
    (boxes / "opreg-box").mkdir(parents=True)
    (boxes / "opreg-box" / "scenario.yaml").write_text(_SCENARIO_YAML)
    monkeypatch.setenv("HUITZILOPOCHTLI_BOXES_DIR", str(boxes))
    monkeypatch.setattr(scenario_mod, "boxes_dir", lambda: str(boxes),
                        raising=False)
    store = Store(str(tmp_path / "t.db"))
    scenario_mod.sync_box_scenarios(store)
    with pytest.raises(ValueError) as exc:
        competition.create_competition(
            store, slug="stale", name="Stale", scenario_name="OpReg",
            scenario_version=2, max_players=2, duration_s=600)
    msg = str(exc.value)
    assert "not current" in msg and "v1" in msg
    for verb in _GONE:
        assert verb not in msg
    assert "discard" in msg.lower()
    assert "new competition" in msg.lower() and "/admin" in msg
