"""Seat recovery + cookie-before-provisioning on the public join flow.

Found on the range 2026-11-18 (gavelport field round): the join POST ran the
whole VM provisioning inline and the identity cookie rode on its response, so
a cold pool outlasted the browser -- the seat stayed reserved (invisible: the
board lists only bound boxes), every re-join under the same name 409'd with
"go back to the browser you joined from", and only an admin could unlock it.
Pinned here: the join response seats the cookie BEFORE provisioning starts; a
reserved seat that never got a box can re-link its browser by name; a seat
with a live run cannot be taken over by name; and the public competition page
names waiting seats instead of letting them look like they vanished.
"""
import base64
import http.client
import json
import sqlite3
import time
import urllib.parse

from common import canon
from common.crypto import signing
from common.version import AGENT_VERSION
from tests.integration.test_admin_action_guards import _engine
from tests.integration.test_competition_http import (
    ADMIN, _Workshop, _http, _wait_claim_url, _wait_db)

SLUG = "rec-comp"


def _setup(tmp_path):
    proc, base, db = _engine(tmp_path)
    return proc, base, db, {"X-HUITZILOPOCHTLI-Admin-Token": ADMIN}


def _create_and_start(base, auth):
    status, body = _http("POST", base + "/admin/api/competitions", {
        "slug": SLUG, "name": "Rec Comp", "scenario_name": "HTTPComp",
        "scenario_version": 1, "max_players": 4, "duration_s": 3600,
    }, auth)
    assert status == 200, body
    comp = json.loads(body)
    status, body = _http(
        "POST", base + f"/admin/api/competitions/{comp['id']}/start", {}, auth)
    assert status in (200, 303), body
    return comp


def _port(base):
    return int(base.rsplit(":", 1)[1])


def _join(port, name):
    """Join without using the resulting cookie (a browser that drops it)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", f"/c/{SLUG}/join",
                 body=urllib.parse.urlencode({"name": name}),
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    resp.read()
    cookie = (resp.getheader("Set-Cookie") or "").split(";", 1)[0]
    conn.close()
    return resp, cookie


def _post_form(port, path, fields, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    conn.request("POST", path, body=urllib.parse.urlencode(fields),
                 headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    headers_out = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, body, headers_out


def _player_row(db, name):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM players WHERE display_name=?", (name,)).fetchone()
    conn.close()
    return row


def test_join_seats_the_cookie_before_provisioning(tmp_path):
    """A slow pool must not hold the join response (and its cookie) hostage.

    The regression: provisioning ran inside the POST, so a cold portal
    outlasted the browser and the seat was born unreachable. The response now
    returns immediately with the cookie; the claim finishes afterwards.
    """
    try:
        proc, base, db, auth = _setup(tmp_path)
        _create_and_start(base, auth)
        port = _port(base)

        _Workshop.claim_delay = 3.0
        t0 = time.time()
        resp, cookie = _join(port, "Slow")
        took = time.time() - t0
        assert resp.status == 303, resp.status
        assert resp.getheader("Location") == "/"
        assert cookie.startswith("huitz_player="), cookie
        # The fake portal's claim sleeps 3 s; the join POST must be well
        # ahead of it (pool provision answers fast; only the claim waits).
        assert took < 2.0, f"join POST waited for provisioning ({took:.2f}s)"

        # The public competition page names the waiting seat while the VM is
        # still being prepared, instead of looking like it never joined.
        status, page = _http("GET", f"{base}/c/{SLUG}")
        assert status == 200 and "1 waiting for a VM" in page, page[:400]
        status, body = _http(
            "GET", f"{base}/api/public/competitions/{SLUG}")
        assert json.loads(body)["waiting_count"] == 1

        # The run dashboard (the join's redirect target) knows the seat by
        # cookie only, and says provisioning retries in the background.
        status, page = _http("GET", base + "/", headers={"Cookie": cookie})
        assert status == 200 and "will appear here automatically" in page

        _Workshop.claim_delay = 0.0
        row = _player_row(db, "Slow")
        state = _wait_claim_url(base, row["player_id"],
                                "http://portal.example/r/u1")
        assert state["box_bound"] is False
        # Same dashboard now surfaces the ready link.
        status, page = _http("GET", base + "/", headers={"Cookie": cookie})
        assert status == 200 and "Open my VM" in page
    finally:
        _Workshop.claim_delay = 0.0
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def test_seat_recovery_relinks_a_lost_browser(tmp_path):
    """The 409 offers recovery, and the recover form re-binds the browser."""
    proc, base, db, auth = _setup(tmp_path)
    try:
        _create_and_start(base, auth)
        port = _port(base)
        resp, _lost = _join(port, "Ada")  # the cookie never lands in reality
        assert resp.status == 303
        row = _player_row(db, "Ada")
        assert row is not None
        _wait_claim_url(base, row["player_id"],
                        "http://portal.example/r/u1")

        # Re-joining from the cookie-less browser names the held seat and
        # offers the recovery form (name prefilled, distinct action).
        status, page, _ = _post_form(port, f"/c/{SLUG}/join", {"name": "Ada"})
        assert status == 409, page[:300]
        assert "already reserved in Rec Comp" in page
        assert "recover your seat below" in page
        assert f'action="/c/{SLUG}/recover"' in page
        assert 'value="Ada"' in page

        # Recovery re-binds the cookie to the SAME seat (no second slot) and
        # the dashboard comes back with the VM link.
        status, _body, headers = _post_form(
            port, f"/c/{SLUG}/recover", {"name": "Ada", "recover": "1"})
        assert status == 303, _body[:300]
        assert headers.get("location") == "/"
        cookie = (headers.get("set-cookie") or "").split(";", 1)[0]
        assert cookie == f"huitz_player={row['player_id']}", cookie
        status, page = _http("GET", base + "/", headers={"Cookie": cookie})
        assert status == 200 and "You're in Rec Comp" in page
        assert "Open my VM" in page

        conn = sqlite3.connect(db)
        n = conn.execute("SELECT COUNT(*) FROM players").fetchone()[0]
        audit = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='seat_recover'"
        ).fetchone()[0]
        conn.close()
        assert n == 1 and audit == 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def test_seat_recovery_never_takes_over_a_live_run(tmp_path):
    """"Only an invited (never-bound) seat is recoverable by name.

    A name alone must never reattach a running box: that seat sits out the
    recovery path (the organizer frees it), and the 409 page stops offering
    the affordance.
    """
    proc, base, db, auth = _setup(tmp_path)
    try:
        _create_and_start(base, auth)
        port = _port(base)
        resp, _lost = _join(port, "Bob")
        assert resp.status == 303
        row = _wait_db(db, "SELECT * FROM players WHERE display_name=?",
                       ("Bob",), "claim_uid")
        code = row["join_code_plain"]

        priv, pub = signing.keypair()
        join_body = {
            "join_code": code, "box_id": "box-rec-1",
            "public_key": base64.b64encode(pub).decode(),
            "agent_version": AGENT_VERSION, "scenario_name": "HTTPComp",
            "scenario_version": 1,
        }
        sig = signing.sign(priv, canon.canonicalize(join_body))
        status, body = _http("POST", base + "/join", json.dumps(join_body).encode(), {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode(),
            "X-HUITZILOPOCHTLI-Box": "box-rec-1",
        })
        assert status == 200, body

        # The live seat: the join form names it but offers no recovery.
        status, page, _ = _post_form(port, f"/c/{SLUG}/join", {"name": "Bob"})
        assert status == 409 and "already reserved in Rec Comp" in page
        assert "/recover" not in page, page[:400]

        # ... and the endpoint itself refuses, history-proof.
        status, _body, headers = _post_form(
            port, f"/c/{SLUG}/recover", {"name": "Bob", "recover": "1"})
        assert status == 403
        assert headers.get("set-cookie") is None

        # Unknown names are indistinguishable from held ones (no leak).
        status, _body, headers = _post_form(
            port, f"/c/{SLUG}/recover", {"name": "Nobody", "recover": "1"})
        assert status == 403
        assert headers.get("set-cookie") is None
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
