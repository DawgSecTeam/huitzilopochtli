"""Coverage-gap tests for ranked mode, pinning the CORRECT behaviour.

Each test names the defect it pins and the fix it expects. Tests marked
"current behaviour" deliberately pass on today's code; the rest must fail
until the product code is fixed. Nothing here changes product code or any
existing test.

Run:
    /usr/bin/python3 -m pytest tests/integration/test_ranked_general_use_gaps.py -q
"""
import csv
import datetime as dt
import http.client
import io
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADMIN = "gap-admin-token"
ENV_HEADER = "X-HUITZILOPOCHTLI-Admin-Token"

#: A pool map is deliberately NOT supplied for these: the committed
#: ${...} placeholders below must be the only source for the broken box.
GAP_POOL_VARS = (
    "HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_VM_ID",
    "HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_USER",
    "HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_PASSWORD",
)

STATIC_POOL = {
    "template_vm_id": 174,
    "template_vm_access_method": "ssh",
    "template_vm_username": "sysadmin",
    "template_vm_password": "asdf",
    "vm_count": 1,
}


# --- HTTP / process helpers ---------------------------------------------------


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _request(port: int, method: str, path: str, body=None, headers=None):
    """One HTTP request; returns (status, text, lowercase-header-dict)."""
    headers = dict(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body)
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", "replace")
        hdrs = {key.lower(): value for key, value in resp.getheaders()}
        return resp.status, text, hdrs
    finally:
        conn.close()


def _as_json(text: str):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def _auth() -> dict:
    return {ENV_HEADER: ADMIN}


class Engine:
    def __init__(self, port: int, db: Path):
        self.port = port
        self.db = db

    def request(self, method, path, body=None, headers=None):
        return _request(self.port, method, path, body, headers)

    def admin(self, method, path, body=None):
        return self.request(method, path, body, _auth())


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


@pytest.fixture
def launch_engine(tmp_path):
    """Factory that starts isolated engine.server subprocesses for one test.

    Every inherited HUITZILOPOCHTLI_* deployment knob that could point at a
    real portal, pool map, TLS certificate, or admin password is removed; the
    test passes its own boxes folder and explicitly removes placeholder vars.
    """
    procs = []

    def _launch(*, boxes: Path = None, remove_env=(), extra_env=None) -> Engine:
        port = _free_port()
        db = tmp_path / f"engine-{len(procs)}.db"
        boxes_root = Path(boxes) if boxes is not None else (tmp_path / "boxes")
        boxes_root.mkdir(parents=True, exist_ok=True)

        env = dict(os.environ)
        for key in (
            "HUITZILOPOCHTLI_DB_PATH",
            "HUITZILOPOCHTLI_PORT",
            "HUITZILOPOCHTLI_ADMIN_TOKEN",
            "HUITZILOPOCHTLI_ADMIN_PASSWORD",
            "HUITZILOPOCHTLI_BIND",
            "HUITZILOPOCHTLI_BOXES_DIR",
            "HUITZILOPOCHTLI_POOLS_FILE",
            "HUITZILOPOCHTLI_WORKSHOP_URL",
            "HUITZILOPOCHTLI_WORKSHOP_SECRET",
            "HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD",
            "HUITZILOPOCHTLI_TLS_CERT",
            "HUITZILOPOCHTLI_TLS_KEY",
            "HUITZILOPOCHTLI_SERVER_SECRET",
            "HUITZILOPOCHTLI_ENGINE_RECORD_PATH",
            "HUITZILOPOCHTLI_PUBLIC_URL",
            *GAP_POOL_VARS,
        ):
            env.pop(key, None)
        for key in remove_env:
            env.pop(key, None)
        env.update({
            "HUITZILOPOCHTLI_DB_PATH": str(db),
            "HUITZILOPOCHTLI_PORT": str(port),
            "HUITZILOPOCHTLI_ADMIN_TOKEN": ADMIN,
            "HUITZILOPOCHTLI_BIND": "127.0.0.1",
            "HUITZILOPOCHTLI_BOXES_DIR": str(boxes_root),
            "HUITZILOPOCHTLI_PUBLIC_URL": f"http://127.0.0.1:{port}",
            "PYTHONUNBUFFERED": "1",
        })
        env.update(extra_env or {})

        proc = subprocess.Popen(
            [sys.executable, "-m", "engine.server"],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        procs.append(proc)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                if _request(port, "GET", "/health")[0] == 200:
                    return Engine(port, db)
            except OSError:
                pass
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        _stop(proc)
        output = proc.stdout.read() if proc.stdout else ""
        raise AssertionError(f"engine never became healthy:\n{output}")

    yield _launch
    for proc in procs:
        _stop(proc)


# --- box-folder / competition helpers ----------------------------------------


def _make_box(boxes_root: Path, dirname: str, scenario_name: str,
              pool: dict) -> Path:
    """Write one ranked scenario.yaml exactly the way the engine reads it."""
    directory = Path(boxes_root) / dirname
    directory.mkdir(parents=True, exist_ok=True)
    data = {
        "scenario": {
            "name": scenario_name,
            "version": 1,
            "mode": "honor",
            "hosts": ["localhost"],
        },
        "checks": [{
            "id": "banner",
            "type": "file_regex",
            "category": "vuln",
            "display": "Banner",
            "max_points": 10,
            "collect": {"path": "/srv/banner", "extract": "B"},
            "expect": {"equals": "ok", "points": 10},
        }],
        "ranked": {
            "engine_url": "http://127.0.0.1:8080",
            "services": [],
            "adversary": {},
            "pool": dict(pool),
        },
    }
    (directory / "scenario.yaml").write_text(
        yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return directory


def _standard_engine(launch_engine, tmp_path, scenario_name="Gap Scenario"):
    boxes = tmp_path / "boxes"
    _make_box(boxes, "standard-box", scenario_name, STATIC_POOL)
    return launch_engine(boxes=boxes)


def _create_competition(eng: Engine, scenario_name="Gap Scenario",
                        name="Gap Competition", *, max_players=8,
                        duration_s=3600) -> dict:
    status, text, _ = eng.admin("POST", "/admin/api/competitions", {
        "slug": name.lower().replace(" ", "-"),
        "name": name,
        "scenario_name": scenario_name,
        "scenario_version": 1,
        "max_players": max_players,
        "duration_s": duration_s,
    })
    assert status == 200, text
    return json.loads(text)


def _start(eng: Engine, comp_id: str):
    return eng.admin("POST", f"/admin/api/competitions/{comp_id}/start", {})


def _join(eng: Engine, slug: str, name: str):
    status, text, headers = eng.request(
        "POST", f"/c/{slug}/join",
        urllib.parse.urlencode({"name": name}),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    cookie = (headers.get("set-cookie") or "").split(";", 1)[0]
    return status, text, cookie


def _live_competition(launch_engine, tmp_path, *, player_name=None):
    eng = _standard_engine(launch_engine, tmp_path)
    comp = _create_competition(eng)
    status, text, _ = _start(eng, comp["id"])
    assert status == 200, text
    cookie = player_id = None
    if player_name is not None:
        status, text, cookie = _join(eng, comp["slug"], player_name)
        assert status == 303, (status, text)
        player_id = cookie.partition("=")[2]
        assert player_id
    return eng, comp, cookie, player_id


def _audit_rows(eng: Engine, comp_id: str) -> list:
    conn = sqlite3.connect(eng.db)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(
            "SELECT id, action, details_json FROM audit_log "
            "WHERE competition_id = ? ORDER BY id", (comp_id,))]
    finally:
        conn.close()


def _pool_reason_in_page(body: str) -> bool:
    """The page states why the pool block cannot be used (not a raw traceback)."""
    text = body.lower()
    return ("unset environment variable" in text
            or ("pool" in text and any(
                word in text for word in
                ("expand", "unresolv", "unusable", "cannot be used", "failed"))))


def _scenario_option(body: str, name: str, version: int = 1):
    return re.search(
        r'<option[^>]*value="' + re.escape(f"{name}|{version}") + r'"[^>]*>',
        body)


# --- defect 1: one broken pool must not 400 the whole picker -----------------


def test_unset_pool_placeholders_do_not_make_the_new_competition_page_400(
        launch_engine, tmp_path):
    """Pins defect 1: a box with unresolvable ${...} ranked.pool placeholders
    made GET (and POST) /admin/competitions/new answer 400 with the raw scan
    error, even though the healthy boxes loaded fine.

    Fix: scan errors stay per-box. The page is 200; healthy scenarios are
    selectable; the broken scenario is still surfaced with its reason and is
    marked unusable (a disabled option, or equivalent non-selectable text).
    """
    boxes = tmp_path / "boxes"
    _make_box(boxes, "healthy-box", "Healthy Gap Box", STATIC_POOL)
    _make_box(boxes, "broken-pool-box", "Broken Pool Box", {
        "template_vm_id": "${HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_VM_ID}",
        "template_vm_access_method": "ssh",
        "template_vm_username": "${HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_USER}",
        "template_vm_password": "${HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_PASSWORD}",
        "vm_count": 1,
    })
    eng = launch_engine(boxes=boxes, remove_env=GAP_POOL_VARS)

    status, body, _ = eng.admin("GET", "/admin/competitions/new")
    assert status == 200, (
        "one unresolvable pool must not turn the whole picker into a 400; "
        f"got {status}: {body[:600]}")

    select = re.search(r'<select name="scenario".*?</select>', body, re.S)
    assert select is not None, body
    healthy = _scenario_option(select.group(0), "Healthy Gap Box")
    assert healthy is not None, "the healthy scenario must remain selectable"
    assert "disabled" not in healthy.group(0), healthy.group(0)

    assert "Broken Pool Box" in body, (
        "the broken scenario must be surfaced, not silently dropped")
    broken = _scenario_option(body, "Broken Pool Box")
    if broken is not None:
        assert "disabled" in broken.group(0), (
            "an unresolvable scenario may be listed, but only as disabled: "
            + broken.group(0))
    assert _pool_reason_in_page(body), (
        "the page must state why the pool block cannot be used, got: "
        + body[:800])


# --- defect 2: vanished scenario / wrong path diagnosis ----------------------


def test_unexpandable_pool_scenario_is_not_reported_as_missing_from_the_box_folder(
        launch_engine, tmp_path):
    """Pins defect 2: a scenario whose ranked.pool placeholders cannot expand
    disappeared from the picker, and POST /admin/api/competitions called it
    "not in the engine's box folder" although boxes/<dir>/scenario.yaml exists.

    Fix: list it with a stated reason it cannot be used, or answer 400 naming
    the pool block that failed to expand -- never a path-is-wrong message.
    """
    boxes = tmp_path / "boxes"
    _make_box(boxes, "broken-pool-box", "Broken Pool Box", {
        "template_vm_id": "${HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_VM_ID}",
        "template_vm_access_method": "ssh",
        "template_vm_username": "${HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_USER}",
        "template_vm_password": "${HUITZILOPOCHTLI_GAP_POOL_TEMPLATE_PASSWORD}",
        "vm_count": 1,
    })
    eng = launch_engine(boxes=boxes, remove_env=GAP_POOL_VARS)

    # The picker half of this defect (the scenario vanishing entirely, or
    # taking the page down with it) is pinned by the test above. Here the
    # API's diagnosis is the subject: it must name the pool failure, never
    # claim that boxes/<dir>/scenario.yaml does not exist.
    status, text, _ = eng.admin("POST", "/admin/api/competitions", {
        "slug": "broken-pool-comp",
        "name": "Broken Pool Comp",
        "scenario_name": "Broken Pool Box",
        "max_players": 4,
        "duration_s": 600,
    })
    assert status == 400, (status, text)
    error = (_as_json(text) or {}).get("error", "")
    lowered = error.lower()
    for wrong_path_message in (
            "not in the engine's box folder",
            "box folder has no such",
            "no such scenario",
            "is not on the engine",
    ):
        assert wrong_path_message not in lowered, (
            "boxes/broken-pool-box/scenario.yaml exists; the error must not "
            f"claim the path is wrong: {error!r}")
    assert any(word in lowered for word in ("expand", "unset", "unresolv")) \
        or ("pool" in lowered and "failed" in lowered), (
        "the refusal must name the pool expansion problem, got: " + repr(error))


# --- defect 3: starting an ended competition wrote a success audit -----------


def test_start_on_ended_competition_is_refused_and_not_audited_as_a_start(
        launch_engine, tmp_path):
    """Pins defect 3: POST .../<id>/start on an ENDED competition answered
    200 {"ok": true, "action": "start"} and wrote a competition_start audit
    row while the status stayed "ended".

    Fix: 409 with an explanation, and either no audit row or one whose
    action/details record the refusal.
    """
    eng, comp, _cookie, _pid = _live_competition(launch_engine, tmp_path)
    comp_id = comp["id"]
    status, text, _ = eng.admin("POST", f"/admin/api/competitions/{comp_id}/end")
    assert status in (200, 303), text

    before = _audit_rows(eng, comp_id)
    status, text, _ = eng.admin(
        "POST", f"/admin/api/competitions/{comp_id}/start", {})
    assert status == 409, (
        "starting an ended competition must be refused with 409, got "
        f"{status}: {text[:400]}")
    error = (_as_json(text) or {}).get("error", "")
    assert error, text
    assert re.search(r"(ended|draft|cannot|only|already)", error, re.I), (
        "the 409 must explain why the start was refused: " + repr(error))

    status, text, _ = eng.admin("GET", f"/admin/api/competitions/{comp_id}")
    assert status == 200, text
    assert json.loads(text)["competition"]["status"] == "ended", (
        "a refused start must not move the competition out of ended")

    after = _audit_rows(eng, comp_id)
    last_before = max((row["id"] for row in before), default=0)
    new_rows = [row for row in after if row["id"] > last_before]
    for row in new_rows:
        text = (row["action"] + " " + (row["details_json"] or "")).lower()
        assert any(word in text for word in
                   ("refus", "reject", "blocked", "not allowed", "ended",
                    "draft", "409")), (
            "a refused start may write an audit row only if it records the "
            f"refusal; got {row!r}")


# --- defect 4: /api/public/me ------------------------------------------------


def test_public_me_without_a_cookie_is_404(launch_engine, tmp_path):
    """Pins defect 4 coverage gap: /api/public/me had no test at all.

    Fix: no player cookie means no player session, so 404 JSON.
    """
    eng = launch_engine()
    status, text, _ = eng.request("GET", "/api/public/me")
    assert status == 404, text
    assert (_as_json(text) or {}).get("error") == "no player session", text


def test_public_me_with_a_removed_players_cookie_is_404(launch_engine, tmp_path):
    """Pins defect 4: /api/public/me still answered 200 for a player whose
    slot was removed, exposing a dead player's identity and competition.

    Fix: a removed (or otherwise no-longer-active) player cookie is treated
    as no session: 404.
    """
    eng, _comp, cookie, player_id = _live_competition(
        launch_engine, tmp_path, player_name="Removed Player")
    status, text, _ = eng.admin(
        "POST", f"/admin/players/{player_id}/remove", {})
    assert status == 200, text

    status, text, _ = eng.request(
        "GET", "/api/public/me", headers={"Cookie": cookie})
    assert status == 404, (
        "a removed player's cookie must not resolve to a live session; got "
        f"{status}: {text[:400]}")


def test_public_me_returns_the_players_own_identity_and_competition(
        launch_engine, tmp_path):
    """Pins defect 4 coverage gap: a valid cookie must return that player's
    own player_id/name/status plus the competition payload.

    This is the positive contract the two 404 tests above guard.
    """
    eng, comp, cookie, player_id = _live_competition(
        launch_engine, tmp_path, player_name="Valid Player")
    status, text, _ = eng.request(
        "GET", "/api/public/me", headers={"Cookie": cookie})
    assert status == 200, text
    payload = json.loads(text)

    player = payload["player"]
    assert player["player_id"] == player_id
    assert player["name"] == "Valid Player"
    assert player["status"] in ("invited", "running")

    competition = payload["competition"]
    assert competition["id"] == comp["id"]
    assert competition["slug"] == comp["slug"]
    assert competition["name"] == comp["name"]
    assert competition["status"] == "live"
    assert competition["scenario_name"] == "Gap Scenario"
    assert competition["join_open"] is True
    assert competition["player_count"] >= 1


# --- defect 5: the CSV export's actual bytes --------------------------------


def _csv_export(eng: Engine, comp: dict):
    status, text, headers = eng.admin(
        "GET", f"/admin/api/competitions/{comp['id']}/export.csv")
    assert status == 200, text
    assert headers.get("content-type", "").startswith("text/csv"), headers
    return list(csv.reader(io.StringIO(text)))


CSV_NAMES = ("=1+1", "-2+3", "@SUM(A1:A2)", "+SUM(A1:A2)")
CSV_TOTALS = (10, 10, 5, 0)


def _seed_csv_players(eng: Engine, comp: dict):
    """Join four players over HTTP, then give them deterministic ranked rows.

    The export reads player rows and scores; using sqlite here avoids four
    expensive Ed25519 joins and lets the test control ties and timestamps.
    The join endpoint is still exercised so the display names are the real
    names the engine stored.
    """
    started_base = 1_800_000_000.0  # deterministic, not "now"
    real_joins = []
    # Join over HTTP first: holding a sqlite write transaction open across
    # these requests would lock the engine's own DB writes.
    for name in CSV_NAMES:
        status, text, cookie = _join(eng, comp["slug"], name)
        assert status == 303, (name, status, text)
        real_joins.append((name, cookie.partition("=")[2]))

    expected = {}
    conn = sqlite3.connect(eng.db)
    try:
        for index, ((name, player_id), total) in enumerate(
                zip(real_joins, CSV_TOTALS)):
            started_at = started_base + index * 60
            ends_at = started_at + 7200
            last_checkin = started_at + 30
            box_id = f"csv-box-{index}"
            conn.execute(
                "UPDATE players SET status = 'running', box_id = ?, "
                "started_at = ?, ends_at = ? WHERE player_id = ?",
                (box_id, started_at, ends_at, player_id))
            conn.execute(
                "INSERT INTO scores (box_id, scenario_name, total, updated_at, "
                "first_scored_at, hardening_points, service_points, score_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (box_id, comp["scenario_name"], total, last_checkin,
                 last_checkin, total, 0, "{}"))
            expected[name] = (started_at, ends_at, last_checkin)
        conn.commit()
    finally:
        conn.close()
    return expected


def _csv_row_for(rows: list, name: str):
    """Find a data row by name, accepting a spreadsheet-neutralised spelling."""
    for row in rows[1:]:
        if row[1] == name or row[1].lstrip("' \t") == name:
            return row
    raise AssertionError(f"no CSV row for {name!r} in {rows!r}")


def test_csv_export_header_has_one_row_per_ranked_player_and_shared_ranks(
        launch_engine, tmp_path):
    """Pins defect 5 coverage gap: the CSV export was only asserted to be a
    link on the page, never parsed.

    Fix/contract: a real header row, exactly one data row per ranked player,
    and tied totals sharing a rank.
    """
    eng, comp, _cookie, _pid = _live_competition(launch_engine, tmp_path)
    _seed_csv_players(eng, comp)
    rows = _csv_export(eng, comp)

    # The export reports forensics separately from hardening/services (the
    # scores row carries its own forensics_points column).
    assert rows[0] == [
        "rank", "player", "status", "total", "hardening", "forensics",
        "services", "started_at", "ends_at", "last_checkin",
    ], rows[0]
    assert len(rows) - 1 == len(CSV_NAMES), (
        f"expected one row per ranked player, got {len(rows) - 1}: {rows!r}")

    first = _csv_row_for(rows, "=1+1")
    second = _csv_row_for(rows, "-2+3")
    third = _csv_row_for(rows, "@SUM(A1:A2)")
    assert first[0] == second[0], (
        f"tied totals must share a rank: {first[0]} vs {second[0]}")
    assert int(third[0]) > int(first[0]), (
        f"a lower total must rank after the tie: {third[0]} vs {first[0]}")
    assert first[3] == second[3] == "10"
    # The seeded rows harden everything and touch nothing else: the split
    # columns each carry their own value (forensics defaults to 0).
    assert first[4] == second[4] == "10"
    assert first[5] == second[5] == "0"


def test_csv_export_timestamps_are_iso_8601_local_not_epoch_floats(
        launch_engine, tmp_path):
    """Pins defect 5: started_at/ends_at/last_checkin were exported as raw
    epoch floats, unreadable in a spreadsheet.

    Fix: ISO-8601 local timestamps (naive local time, or an explicit offset).
    Epoch would only be acceptable if documented as intended; nothing does.
    """
    eng, comp, _cookie, _pid = _live_competition(launch_engine, tmp_path)
    expected = _seed_csv_players(eng, comp)
    rows = _csv_export(eng, comp)
    header = rows[0]
    indexes = {name: header.index(name)
               for name in ("started_at", "ends_at", "last_checkin")}

    for name, (started_at, ends_at, last_checkin) in expected.items():
        row = _csv_row_for(rows, name)
        for column, epoch in (
                ("started_at", started_at),
                ("ends_at", ends_at),
                ("last_checkin", last_checkin)):
            raw = row[indexes[column]]
            assert not re.fullmatch(r"-?\d+(?:\.\d+)?", raw), (
                f"{column} is still a raw epoch float ({raw!r}); export "
                "ISO-8601 local time instead")
            parsed = dt.datetime.fromisoformat(raw)
            # A naive ISO string is local time; an offset-aware one converts.
            actual = parsed.timestamp()
            assert abs(actual - epoch) < 1.0, (
                f"{column} {raw!r} does not represent the stored epoch "
                f"{epoch}: parsed back as {actual}")


def test_csv_export_neutralises_spreadsheet_formula_names(
        launch_engine, tmp_path):
    """Pins defect 5: a display name beginning with = + - or @ was exported
    verbatim, so a spreadsheet could execute it as a formula.

    Fix: neutralise the cell (a leading apostrophe is the conventional fix;
    a leading space/tab is also acceptable) without losing the visible name.
    """
    eng, comp, _cookie, _pid = _live_competition(launch_engine, tmp_path)
    _seed_csv_players(eng, comp)
    rows = _csv_export(eng, comp)

    for name in CSV_NAMES:
        row = _csv_row_for(rows, name)
        value = row[1]
        assert value != name, (
            f"formula-leading display name {name!r} was exported verbatim")
        assert value[:1] not in ("=", "+", "-", "@"), (
            f"the neutralised cell must not begin with a formula character: "
            f"{value!r}")
        assert value.lstrip("' \t") == name, (
            f"neutralising {name!r} must preserve the visible name; got "
            f"{value!r}")
    for row in rows[1:]:
        assert row[1][:1] not in ("=", "+", "-", "@"), (
            f"no exported player cell may start with a formula character: "
            f"{row[1]!r}")


# --- defect 6: close-join has no counterpart verb ---------------------------


def test_close_join_refuses_a_late_join_with_400(launch_engine, tmp_path):
    """Pins defect 6 CURRENT behaviour (this test passes today): close-join
    works, and once joins are closed POST /c/<slug>/join answers 400
    "This competition is not accepting joins." with no new player row.

    The fix this guards is the missing open-join counterpart; the sibling
    test below fails until that verb exists and restores this behaviour.
    """
    eng, comp, _cookie, _pid = _live_competition(launch_engine, tmp_path)
    before = _count_players(eng, comp["id"])

    status, text, _ = eng.admin(
        "POST", f"/admin/api/competitions/{comp['id']}/close-join", {})
    assert status == 200, text
    status, text, _ = eng.admin(
        "GET", f"/admin/api/competitions/{comp['id']}")
    assert status == 200, text
    assert json.loads(text)["competition"]["join_open"] is False

    status, text, _cookie = _join(eng, comp["slug"], "Late Player")
    assert status == 400, (status, text)
    assert "This competition is not accepting joins." in text, text
    assert _count_players(eng, comp["id"]) == before, (
        "a refused join must not create a player slot")


def test_open_join_verb_restores_join_open(launch_engine, tmp_path):
    """Pins defect 6: close-join has no counterpart verb, so a prematurely
    closed competition can never accept joins again.

    Fix: an open-join admin verb sets join_open back to true on a live
    competition; a subsequent join then succeeds. This test must FAIL until
    that verb exists.
    """
    eng, comp, _cookie, _pid = _live_competition(launch_engine, tmp_path)
    status, text, _ = eng.admin(
        "POST", f"/admin/api/competitions/{comp['id']}/close-join", {})
    assert status == 200, text

    status, text, _ = eng.admin(
        "POST", f"/admin/api/competitions/{comp['id']}/open-join", {})
    assert status == 200, (
        "open-join must exist as the counterpart to close-join; got "
        f"{status}: {text[:400]}")

    status, text, _ = eng.admin(
        "GET", f"/admin/api/competitions/{comp['id']}")
    assert status == 200, text
    assert json.loads(text)["competition"]["join_open"] is True, (
        "open-join must restore join_open")

    status, text, _cookie = _join(eng, comp["slug"], "Reopened Player")
    assert status == 303, (
        f"joins must work again after open-join; got {status}: {text[:400]}")


def _count_players(eng: Engine, comp_id: str) -> int:
    conn = sqlite3.connect(eng.db)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM players WHERE competition_id = ?",
            (comp_id,)).fetchone()[0]
    finally:
        conn.close()
