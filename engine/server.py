"""HTTP endpoints. See architecture.md §11.1.

Wires engine.enrollment.handle_enroll / engine.checkin.handle_checkin /
engine.leaderboard.get_leaderboard behind stdlib http.server with a thread
pool. Keep handlers themselves small; all logic lives in the modules above.

Endpoints:
  GET  /health
  POST /enroll
  POST /checkin
  GET  /leaderboard?scenario=...
  POST /admin/tokens      (gated by X-HUITZILOPOCHTLI-Admin-Token)
"""
import base64
import dataclasses
import hmac
import json
import math
import os
import secrets
import ssl
import sys
import threading
import time
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlsplit, parse_qs

from common.schema import Bundle, CollectorStatus, Evidence, SCHEMA_VERSION
from engine import auth, claims, competition, enrollment, leaderboard, web, workshop
from engine import scenario as scenario_mod
from engine.checkin import CheckinError, handle_checkin
from engine.enrollment import EnrollError
from engine.store import Store


def _load_engine_record(path: str) -> dict:
    """Load engine_record.json for seeding the store via save_scenario."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _require_str(d: dict, key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise ValueError(f"{key} must be a non-empty string")
    return v


#: SQLite INTEGER is signed 64-bit: a larger seq OverflowError'd at bind
#: time (a 500) instead of being rejected as malformed.
_MAX_WIRE_INT = 2 ** 63 - 1


def _require_int(d: dict, key: str) -> int:
    v = d.get(key)
    # bool is an int subclass; a True/False seq would corrupt the seq guard.
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{key} must be an integer")
    if not 0 <= v <= _MAX_WIRE_INT:
        raise ValueError(f"{key} out of range")
    return v


def _require_finite(d: dict, key: str, default) -> float:
    v = d.get(key, default)
    # json.loads accepts NaN/Infinity; storing one would poison the audit
    # bundle_json and the signed-canonical round trip.
    if isinstance(v, bool) or not isinstance(v, (int, float)) \
            or not math.isfinite(v):
        raise ValueError(f"{key} must be a finite number")
    return v


#: Deepest JSON nesting accepted in evidence.raw. Real collectors emit a
#: handful of levels; canonicalization recurses, so a hostile ~1000-deep blob
#: would otherwise RecursionError into a 500 before the signature is checked.
_MAX_RAW_DEPTH = 64


def _nesting_exceeds(value, limit: int) -> bool:
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > limit:
                return True
            children = node.values() if isinstance(node, dict) else node
            stack.extend((c, depth + 1) for c in children)
    return False


def _bundle_from_dict(d: dict) -> Bundle:
    # Wire-layer type validation: a wrong JSON type must map to a clean
    # 400 "malformed bundle", not fall out of the handler as a 500 -- or
    # worse, be accepted (a float seq used to advance last_seq to 2.5).
    _require_str(d, "box_id")
    _require_int(d, "seq")
    _require_str(d, "boot_id")
    _require_str(d, "agent_version")
    _require_str(d, "scenario_name")
    _require_int(d, "scenario_version")
    _require_finite(d, "created_wall_claim", 0.0)
    if not isinstance(d.get("evidence"), list):
        raise ValueError("evidence must be a list")
    evidence = []
    for ev in d.get("evidence", []):
        if not isinstance(ev, dict):
            raise ValueError("each evidence item must be an object")
        _require_str(ev, "check_id")
        _require_str(ev, "check_type")
        _require_str(ev, "host_id")
        if not isinstance(ev.get("raw", {}), dict):
            raise ValueError("evidence.raw must be an object")
        if _nesting_exceeds(ev.get("raw", {}), _MAX_RAW_DEPTH):
            raise ValueError(
                f"evidence.raw nests deeper than {_MAX_RAW_DEPTH} levels")
        if not isinstance(ev.get("reason", ""), str):
            raise ValueError("evidence.reason must be a string")
        _require_finite(ev, "collected_monotonic", 0.0)
        _require_finite(ev, "collected_wall_claim", 0.0)
        evidence.append(
            Evidence(
                check_id=ev["check_id"],
                check_type=ev["check_type"],
                host_id=ev["host_id"],
                status=CollectorStatus(ev["status"]),
                raw=ev.get("raw", {}),
                reason=ev.get("reason", ""),
                collected_monotonic=ev.get("collected_monotonic", 0.0),
                collected_wall_claim=ev.get("collected_wall_claim", 0.0),
            )
        )
    return Bundle(
        box_id=d["box_id"],
        seq=d["seq"],
        boot_id=d["boot_id"],
        agent_version=d["agent_version"],
        scenario_name=d["scenario_name"],
        scenario_version=d["scenario_version"],
        evidence=evidence,
        created_wall_claim=d.get("created_wall_claim", 0.0),
        schema_version=d.get("schema_version", SCHEMA_VERSION),
    )


def _jsonable(obj):
    """Recursively convert dataclasses/Enums for json.dumps."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return obj


class _RateLimiter:
    """Small per-source token bucket for the two unauthenticated endpoints.

    Signature verification is intentionally expensive; without a cheap
    admission control, a flood of well-formed bogus signatures can starve the
    verify gate and every real box's check-in. This is deliberately simple
    (in-process, per source IP) and configurable/disable-able via env.
    """

    def __init__(self, per_minute: int, burst: int):
        self.per_minute = per_minute
        self.burst = burst
        self._lock = threading.Lock()
        self._state = {}  # ip -> (tokens, last_monotonic)

    def allow(self, ip: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(ip, (float(self.burst), now))
            tokens = min(float(self.burst),
                         tokens + (now - last) * (self.per_minute / 60.0))
            if tokens < 1.0:
                self._state[ip] = (tokens, now)
                return False
            self._state[ip] = (tokens - 1.0, now)
            return True


class _Flash:
    """One-time in-memory messages keyed to an admin session and competition.

    Post-redirect-get without putting the payload in the URL: a reissued join
    code must never land in browser history or access logs, so it travels in
    server memory and is popped on first read. Entries expire unread.
    """

    TTL_S = 60

    def __init__(self):
        self._lock = threading.Lock()
        self._msgs = {}  # "session_hash:comp_id" -> (text, expires_monotonic)

    def put(self, session_hash: str, comp_id: str, text: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._msgs = {k: v for k, v in self._msgs.items() if v[1] > now}
            self._msgs[f"{session_hash}:{comp_id}"] = (text, now + self.TTL_S)

    def pop(self, session_hash: str, comp_id: str) -> str:
        with self._lock:
            entry = self._msgs.pop(f"{session_hash}:{comp_id}", None)
        if entry and entry[1] > time.monotonic():
            return entry[0]
        return ""


class Handler(BaseHTTPRequestHandler):
    # Populated by main() before the server starts serving.
    store: Store = None
    server_secret: bytes = b""
    admin_token: str = ""
    next_checkin_s: int = 60
    rate_limiter: "_RateLimiter" = None
    flash_store: "_Flash" = None

    timeout = 30

    def log_message(self, fmt, *args):  # quiet down default stderr access log
        pass

    # --- response helpers ------------------------------------------------

    def _send_html(self, status: int, body: str, extra_headers=None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        pending = getattr(self, "_pending_cookie", None)
        if pending:
            self.send_header("Set-Cookie", pending)
            self._pending_cookie = None
        self.end_headers()
        self.wfile.write(payload)

    def _send_csv(self, filename: str, rows: list) -> None:
        import csv
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        for row in rows:
            writer.writerow(row)
        payload = buf.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _public_base(self) -> str:
        """Public origin for links the player's browser follows."""
        base = os.environ.get("HUITZILOPOCHTLI_PUBLIC_URL", "").rstrip("/")
        if base:
            return base
        host = self.headers.get("Host") or f"localhost:{self.server.server_port}"
        scheme = "https" if (self.headers.get("X-Forwarded-Proto") or "") == "https" else "http"
        return f"{scheme}://{host}"

    def _redirect(self, location: str, extra_headers=None) -> None:
        payload = b""
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _cookie(self, name: str):
        for part in (self.headers.get("Cookie") or "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name and value:
                return value
        return None

    def _current_player(self):
        """(player, competition) from the browser's player cookie, or (None, None).

        One player slot per browser is the engine's player identity: it is what
        keeps a person in one competition at a time and what the main page uses
        to say "this is your run".
        """
        pid = self._cookie("huitz_player")
        if not pid:
            return None, None
        player = self.store.get_player(pid)
        if player is None:
            return None, None
        return player, self.store.get_competition(player.competition_id)

    @staticmethod
    def _clear_player_cookie() -> str:
        return "huitz_player=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > self._MAX_BODY_BYTES:
            raise ValueError("bad Content-Length")
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype == "application/json" and raw:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        from urllib.parse import parse_qs
        parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}

    def _admin_actor(self):
        """Return (ok, actor, session, via_header)."""
        token = self.headers.get("X-HUITZILOPOCHTLI-Admin-Token")
        if self.admin_token and token is not None:
            if hmac.compare_digest(self.admin_token.encode("utf-8"),
                                   token.encode("latin-1", "replace")):
                return True, "token", None, True
        session = auth.session_from_cookie(self.store, self.headers.get("Cookie", ""))
        if session is not None:
            return True, session.username, session, False
        basic = auth.parse_basic(self.headers.get("Authorization", ""))
        if basic and auth.check_credentials(*basic):
            return True, basic[0], None, True
        return False, None, None, False

    def _require_admin(self, *, html: bool = False):
        ok, actor, session, via_header = self._admin_actor()
        if not ok:
            if html:
                self._send_html(401, web.login_page("Sign in to continue."))
            else:
                self._send_json(403, {"error": "admin authentication required"})
            return None, None, None, None
        return True, actor, session, via_header

    def _admin_page_session(self):
        ok, actor, session, _via = self._admin_actor()
        if not ok:
            return None
        if session is None:
            token, csrf = auth.new_session(self.store, actor)
            session = self.store.get_admin_session(auth.hash_session(token))
            secure = (os.environ.get("HUITZILOPOCHTLI_PUBLIC_URL", "").startswith("https"))
            self._pending_cookie = auth.cookie_value(token, secure=secure)
        return session

    def _check_csrf(self, session, form: dict) -> bool:
        if session is None:
            return True  # header-authenticated API caller
        provided = form.get("csrf") or self.headers.get("X-CSRF-Token", "")
        if not provided:
            return False
        return hmac.compare_digest(provided, session.csrf_token)

    def _send_json(self, status: int, body) -> None:
        payload = json.dumps(_jsonable(body)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    _MAX_BODY_BYTES = 1 << 20  # 1 MiB hard cap (§11.1)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0:
            raise ValueError(f"negative Content-Length ({length})")
        if length > self._MAX_BODY_BYTES:
            raise ValueError(f"body too large ({length} > {self._MAX_BODY_BYTES})")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}

        def _reject_constant(value):
            # Python's json accepts NaN/Infinity by default; neither is JSON,
            # and canonicalization (used for signatures and audit storage)
            # must be strict. Reject them at the wire boundary.
            raise ValueError(f"non-finite JSON constant {value}")

        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)

    def _sig_header(self) -> bytes:
        sig_b64 = self.headers.get("X-HUITZILOPOCHTLI-Sig", "")
        try:
            return base64.b64decode(sig_b64) if sig_b64 else b""
        except Exception:
            return b""

    def _box_header_mismatches(self, box_id: str) -> bool:
        """The X-HUITZILOPOCHTLI-Box header is advisory routing metadata the
        agents send alongside every enroll/check-in; the signature covers the
        body, so the body is authoritative. But a header that names a
        DIFFERENT box is never legitimate -- reject it before doing any
        expensive verification work."""
        provided = self.headers.get("X-HUITZILOPOCHTLI-Box")
        return provided is not None and provided != box_id

    def _admin_authorized(self) -> "tuple[bool, int, str]":
        """Returns (ok, status_code_if_not_ok, message_if_not_ok)."""
        ok, _actor, _session, _via = self._admin_actor()
        if ok:
            return True, 0, ""
        if not self.admin_token and not auth.admin_enabled():
            return False, 503, "admin endpoints disabled (set HUITZILOPOCHTLI_ADMIN_TOKEN or HUITZILOPOCHTLI_ADMIN_PASSWORD)"
        return False, 403, "bad admin token or credentials"

    # --- routing -------------------------------------------------------

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/health":
            comps = self.store.list_competitions()
            self._send_json(200, {
                "ok": True, "engine": "huitzilopochtli",
                "competitions": len(comps),
                "live": sum(1 for c in comps if c.status == "live"),
            })
            return
        if path == "/leaderboard":
            qs = parse_qs(parts.query)
            scenario = qs.get("scenario", [None])[0]
            if not scenario:
                self._send_json(400, {"error": "missing scenario query param"})
                return
            self._send_json(200, leaderboard.get_leaderboard(self.store, scenario))
            return
        if path == "/":
            # A player who is in a live competition sees their run here, not
            # a list of competitions they cannot currently join. Everyone else
            # gets the public list (admins also see non-live competitions).
            player, current = self._current_player()
            if competition.is_active_player(player, current):
                data = competition.leaderboard_payload(self.store, current)
                row = next((r for r in data["leaderboard"]
                            if r["player_id"] == player.player_id), None)
                services = (row.get("services") if row else None) or \
                    competition.service_rows(self.store, current, player.box_id)
                player_csrf = claims.player_csrf(self.server_secret,
                                                 player.player_id)
                self._send_html(200, web.home_competition_page(
                    current, player, row, data["leaderboard"], player.claim_url,
                    csrf=player_csrf, leave_csrf=player_csrf,
                    player_count=data["competition"]["player_count"],
                    services=services, admin=self._admin_actor()[0]))
                return
            admin_view = self._admin_actor()[0]
            comps = self.store.list_competitions()
            counts = {c.id: self.store.count_players(c.id) for c in comps}
            self._send_html(200, web.index_page(comps, admin_view=admin_view,
                                                players_by_comp=counts))
            return
        if path.startswith("/c/"):
            self._handle_public_competition(path, parts)
            return
        if path == "/admin/login":
            self._send_html(200, web.login_page())
            return
        if path == "/admin":
            session = self._admin_page_session()
            if session is None:
                self._send_html(401, web.login_page("Sign in to continue."))
                return
            self._render_admin_dashboard(session)
            return
        if path == "/admin/styleguide":
            # Component reference for design rounds; not linked from the nav.
            session = self._admin_page_session()
            if session is None:
                self._send_html(401, web.login_page("Sign in to continue."))
                return
            self._send_html(200, web.styleguide_page())
            return
        if path == "/admin/api/competitions":
            ok, _actor, _session, _via = self._admin_actor()
            if not ok:
                self._send_json(403, {"error": "admin authentication required"})
                return
            comps = self.store.list_competitions()
            self._send_json(200, [competition.public_competition_payload(
                self.store, c) for c in comps])
            return
        if path.startswith("/admin/api/competitions/") and path.endswith("/export.csv"):
            ok, _actor, _session, _via = self._admin_actor()
            if not ok:
                self._send_json(403, {"error": "admin authentication required"})
                return
            comp_id = path[len("/admin/api/competitions/"):-len("/export.csv")].strip("/")
            comp = self.store.get_competition(comp_id)
            if comp is None:
                self._send_json(404, {"error": "competition not found"})
                return
            board = competition.leaderboard_payload(self.store, comp)
            rows = [["rank", "player", "status", "total", "hardening", "services",
                     "started_at", "ends_at", "last_checkin"]]
            for r in board["leaderboard"]:
                rows.append([r["rank"], r["name"], r["status"], r["total"],
                             r["hardening_points"], r["service_points"],
                             r["started_at"], r["ends_at"], r["last_checkin"]])
            self._send_csv(f"{comp.slug}-results.csv", rows)
            return
        if path.startswith("/admin/api/competitions/"):
            ok, _actor, _session, _via = self._admin_actor()
            if not ok:
                self._send_json(403, {"error": "admin authentication required"})
                return
            comp_id = path[len("/admin/api/competitions/"):].strip("/").split("/")[0]
            comp = self.store.get_competition(comp_id)
            if comp is None:
                self._send_json(404, {"error": "competition not found"})
                return
            if path.endswith("/warm"):
                self._send_json(200, claims.warm_status(comp.id))
                return
            payload = competition.leaderboard_payload(self.store, comp)
            payload["players"] = [
                {"player_id": p.player_id, "name": p.display_name,
                 "status": p.status, "box_id": p.box_id,
                 "joined_at": p.joined_at, "started_at": p.started_at,
                 "ends_at": p.ends_at, "claim_url": p.claim_url}
                for p in self.store.list_players(comp.id)
            ]
            self._send_json(200, payload)
            return
        if path == "/admin/competitions/new":
            session = self._admin_page_session()
            if session is None:
                self._send_html(401, web.login_page("Sign in to continue."))
                return
            self._render_admin_new_competition(session)
            return
        if path.startswith("/admin/competitions/"):
            session = self._admin_page_session()
            if session is None:
                self._send_html(401, web.login_page("Sign in to continue."))
                return
            qs = parse_qs(parts.query)
            msg = (qs.get("msg") or [""])[0][:200]
            if self.flash_store is not None:
                # One-time flash (e.g. a freshly reissued join code) beats a
                # query-string message; it is consumed by this render.
                flashed = self.flash_store.pop(
                    session.session_hash, path.rsplit("/", 1)[-1])
                msg = flashed or msg
            self._render_admin_competition(session, path.rsplit("/", 1)[-1],
                                           msg=msg)
            return
        if path == "/api/public/competitions":
            comps = self.store.list_competitions()
            self._send_json(200, [competition.public_competition_payload(
                self.store, c) for c in comps])
            return
        if path.startswith("/api/public/competitions/"):
            rest = path[len("/api/public/competitions/"):].strip("/").split("/")
            comp = self.store.get_competition_by_slug(rest[0]) if rest else None
            if comp is None:
                self._send_json(404, {"error": "competition not found"})
                return
            if len(rest) >= 2 and rest[1] == "leaderboard":
                self._send_json(200, competition.leaderboard_payload(self.store, comp))
            else:
                self._send_json(200, competition.public_competition_payload(self.store, comp))
            return
        if path.startswith("/api/public/join/"):
            rest = path[len("/api/public/join/"):].strip("/").split("/")
            if len(rest) == 2 and rest[1] == "status":
                self._handle_claim_status(rest[0])
                return
            self._send_json(404, {"error": "not found"})
            return
        if path == "/api/public/me":
            self._handle_public_me()
            return
        if "text/html" in (self.headers.get("Accept") or ""):
            # A browser typing a bad URL gets a styled page; API clients keep JSON.
            self._send_html(404, web.error_page(404, "Not found",
                                                "The page you requested does not exist.", "/"))
        else:
            self._send_json(404, {"error": "not found"})

    # --- public pages ---------------------------------------------------

    def _handle_public_competition(self, path: str, parts) -> None:
        rest = path[len("/c/"):].strip("/").split("/")
        comp = self.store.get_competition_by_slug(rest[0]) if rest else None
        if comp is None:
            self._send_html(404, web.error_page(
                404, "Competition not found",
                "No competition lives at this address.", "/"))
            return
        # Read-only admin detection (never mints a session): a signed-in admin
        # gets the Log out control on every public page too.
        is_admin = self._admin_actor()[0]
        if len(rest) == 1:
            data = competition.leaderboard_payload(self.store, comp)
            viewer, viewer_comp = self._current_player()
            if not competition.is_active_player(viewer, viewer_comp):
                viewer_comp = None
            self._send_html(200, web.competition_page(data,
                                                      viewer_comp=viewer_comp,
                                                      admin=is_admin))
            return
        if rest[1] == "join" and len(rest) >= 3 and rest[2] == "success":
            pid = self._cookie("huitz_player")
            player = self.store.get_player(pid) if pid else None
            if player is None or player.competition_id != comp.id:
                self._send_html(404, web.error_page(
                    404, "No player session",
                    "Join again to get a new slot.", f"/c/{comp.slug}/join"))
                return
            if player.box_id:
                # The run is live; the main page is the run now.
                self._redirect("/")
                return
            self._send_html(200, web.join_success_page(
                comp, player, join_code=player.join_code_plain or "",
                csrf=claims.player_csrf(self.server_secret, player.player_id),
                admin=is_admin))
            return
        if rest[1] == "join":
            player, current = self._current_player()
            if competition.is_active_player(player, current):
                if current.id == comp.id:
                    # Already holds a slot here -- the main page is the run.
                    self._redirect("/")
                    return
                self._send_html(409, web.join_form_page(
                    comp, blocked_comp=current, admin=is_admin))
                return
            payload = competition.public_competition_payload(self.store, comp)
            notice = ""
            if not payload["can_join"]:
                notice = {"draft": "This competition hasn't started yet.",
                          "ended": "This competition has ended."}.get(comp.status)
                if not notice:
                    if comp.join_open and 0 < comp.max_players <= payload["player_count"]:
                        notice = "This competition is full."
                    else:
                        notice = "Joins are closed."
            self._send_html(200, web.join_form_page(comp, closed_notice=notice,
                                                    admin=is_admin))
            return
        if rest[1] == "display":
            data = competition.leaderboard_payload(self.store, comp)
            self._send_html(200, web.display_page(data))
            return
        if rest[1] == "me":
            pid = self._cookie("huitz_player")
            player = self.store.get_player(pid) if pid else None
            if player is None or player.competition_id != comp.id:
                self._send_html(404, web.error_page(
                    404, "No player session",
                    "Open the join page to enter this competition.",
                    f"/c/{comp.slug}/join"))
                return
            data = competition.leaderboard_payload(self.store, comp)
            row = next((r for r in data["leaderboard"]
                        if r["player_id"] == player.player_id), None)
            self._send_html(200, web.player_page(
                comp, player, row, player.claim_url,
                csrf=claims.player_csrf(self.server_secret, player.player_id),
                admin=is_admin))
            return
        self._send_html(404, web.error_page(404, "Not found",
                                            "The page you requested does not exist.",
                                            f"/c/{comp.slug}"))

    def _handle_public_me(self) -> None:
        pid = self._cookie("huitz_player")
        player = self.store.get_player(pid) if pid else None
        if player is None:
            self._send_json(404, {"error": "no player session"})
            return
        comp = self.store.get_competition(player.competition_id)
        self._send_json(200, {
            "player": {
                "player_id": player.player_id, "name": player.display_name,
                "status": player.status, "box_id": player.box_id,
                "started_at": player.started_at, "ends_at": player.ends_at,
                "claim_url": player.claim_url,
            },
            "competition": competition.public_competition_payload(self.store, comp)
            if comp else None,
        })

    def _handle_claim_status(self, player_id: str) -> None:
        player = self.store.get_player(player_id)
        if player is None:
            self._send_json(404, {"error": "unknown player"})
            return
        comp = self.store.get_competition(player.competition_id)
        back = (f"{self._public_base()}/c/{comp.slug}/join/success" if comp else "")
        player = claims.poll(self.store, player)
        claims.rotate_code_if_needed(self.store, player, self.server_secret,
                                     back_url=back)
        player = self.store.get_player(player_id)
        payload = {
            "player_id": player.player_id,
            "name": player.display_name,
            "status": player.status,
            "competition_slug": comp.slug if comp else None,
        }
        payload.update(claims.describe(player))
        self._send_json(200, payload)

    def _handle_public_reclaim(self, player_id: str) -> None:
        """Player asks for a fresh VM (dead link, failed provision, retry)."""
        player = self.store.get_player(player_id)
        if player is None:
            self._send_json(404, {"error": "unknown player"})
            return
        try:
            form = self._read_form()
        except Exception:
            self._send_json(400, {"error": "malformed form"})
            return
        if not claims.check_csrf(self.server_secret, player_id, form.get("csrf")):
            self._send_json(403, {"error": "invalid csrf token"})
            return
        comp = self.store.get_competition(player.competition_id)
        back = f"{self._public_base()}/c/{comp.slug}/join/success" if comp else ""
        result = claims.reclaim(self.store, comp, player, back_url=back)
        self.store.add_audit(
            "player", "claim_reclaim", comp.id if comp else None, player_id,
            details_json=json.dumps({"ok": bool(result.get("ok")),
                                     "error": result.get("error")}),
            remote_addr=self.client_address[0] if self.client_address else None)
        if "application/json" in (self.headers.get("Accept") or ""):
            self._send_json(200 if result.get("ok") else 502, result)
            return
        if comp is None:
            self._redirect("/")
            return
        self._redirect(back)

    # --- admin renderers ------------------------------------------------

    def _render_admin_dashboard(self, session) -> None:
        comps = self.store.list_competitions()
        counts = {c.id: self.store.count_players(c.id) for c in comps}
        self._send_html(200, web.admin_dashboard_page(
            comps, counts, session.csrf_token))

    def _render_admin_new_competition(self, session, error: str = "") -> None:
        sync_errors = scenario_mod.sync_box_scenarios(self.store)
        if sync_errors:
            error = error or "; ".join(sync_errors[:3])
        self._send_html(200 if not error else 400, web.admin_new_competition_page(
            scenario_mod.list_admin_scenarios(), session.csrf_token,
            error))

    def _render_admin_competition(self, session, comp_id: str,
                                  msg: str = "", error: str = "") -> None:
        comp = self.store.get_competition(comp_id)
        if comp is None:
            self._send_html(404, web.error_page(
                404, "Competition not found",
                "It may have been removed.", "/admin", admin=True))
            return
        board = competition.leaderboard_payload(self.store, comp)
        players = self.store.list_players(comp.id)
        self._send_html(200, web.admin_competition_page(
            comp, board, players, session.csrf_token, msg, error,
            warm=claims.warm_status(comp.id),
            pool=claims.live_pool_status(comp),
            public_base=self._public_base()))

    # --- POST handlers --------------------------------------------------

    def _handle_admin_login(self) -> None:
        try:
            form = self._read_form()
        except Exception:
            self._send_html(400, web.login_page("Malformed login request."))
            return
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        if not auth.check_credentials(username, password):
            self._send_html(401, web.login_page("Invalid username or password."))
            return
        token, _csrf = auth.new_session(self.store, username)
        secure = os.environ.get("HUITZILOPOCHTLI_PUBLIC_URL", "").startswith("https")
        self._send_html(303, "", extra_headers={
            "Location": "/admin",
            "Set-Cookie": auth.cookie_value(token, secure=secure),
        })

    def _handle_admin_logout(self) -> None:
        token = self._cookie(auth.COOKIE_NAME)
        if token:
            self.store.delete_admin_session(auth.hash_session(token))
        self._send_html(303, "", extra_headers={
            "Location": "/admin/login",
            "Set-Cookie": auth.clear_cookie(),
        })

    def _handle_public_join(self, slug: str) -> None:
        comp = self.store.get_competition_by_slug(slug)
        if comp is None:
            self._send_html(404, web.error_page(
                404, "Competition not found",
                "No competition lives at this address.", "/"))
            return
        try:
            form = self._read_form()
        except Exception:
            self._send_html(400, web.join_form_page(comp, "Malformed form."))
            return
        player, current = self._current_player()
        if competition.is_active_player(player, current):
            if current.id == comp.id:
                self._redirect("/")
                return
            self._send_html(409, web.join_form_page(comp, blocked_comp=current))
            return
        name = str(form.get("name", ""))
        # The cookie is the primary identity, but a cleared cookie must not
        # turn one person into two competitors. Names are the only other handle
        # the engine has; while a name is live it cannot be reused elsewhere.
        name_error = competition.validate_display_name(name)
        if not name_error:
            other = self.store.find_active_player_by_name(
                competition.normalize_name(name))
            if other is not None and other.competition_id != comp.id:
                other_comp = self.store.get_competition(other.competition_id)
                if competition.is_active_player(other, other_comp):
                    self._send_html(409, web.join_form_page(
                        comp,
                        error=(f"'{other.display_name}' is already competing "
                               f"in {other_comp.name}. A player can be in only "
                               "one competition at a time — choose a different "
                               "name or wait for that run to end.")))
                    return
        player, code, error = competition.create_player_with_code(
            self.store, comp, name, self.server_secret)
        if error:
            self._send_html(400, web.join_form_page(comp, error))
            return
        claims.start(self.store, comp, player,
                     back_url=f"{self._public_base()}/c/{comp.slug}/join/success")
        self.store.add_audit("player", "join_reserved", comp.id, player.player_id,
                             details_json=json.dumps({"name": player.display_name}),
                             remote_addr=self.client_address[0] if self.client_address else None)
        # PRG: a redirect (not a 200 page) so refreshing never re-submits the
        # form. The main page is now the run dashboard; the success page is
        # kept for the pending/fallback states and redirects here once bound.
        self._redirect("/", extra_headers={"Set-Cookie": (
            f"huitz_player={player.player_id}; Path=/; HttpOnly; "
            f"SameSite=Lax; Max-Age=86400")})

    def _handle_public_leave(self, slug: str) -> None:
        """Player withdraws: release the VM, drop the slot, clear the cookie.

        Leaving a run is a forfeit: the current score disappears from the
        competition board (the box/score rows remain historical), the portal
        VM is destroyed, and the player is free to join another competition.
        """
        comp = self.store.get_competition_by_slug(slug)
        if comp is None:
            self._send_html(404, web.error_page(
                404, "Competition not found",
                "No competition lives at this address.", "/"))
            return
        player, current = self._current_player()
        if player is None or current is None or current.id != comp.id:
            self._redirect("/")
            return
        try:
            form = self._read_form()
        except Exception:
            form = {}
        if not claims.check_csrf(self.server_secret, player.player_id,
                                 form.get("csrf")):
            self._send_html(403, web.error_page(
                403, "Invalid CSRF token",
                "Go back, reload the page, and try again.", "/"))
            return
        if not competition.is_active_player(player, comp):
            # Already finished/removed: there is nothing to forfeit, just drop
            # the browser's stale player session.
            self._redirect("/", extra_headers={
                "Set-Cookie": self._clear_player_cookie()})
            return
        released = False
        base, _secret = claims.config()
        if base and player.claim_uid:
            try:
                workshop.release_vm(base, player.claim_uid)
                released = True
            except workshop.WorkshopError:
                pass  # the portal reaper will collect it; leaving still works
        had_box = bool(player.box_id)
        self.store.remove_player(player.player_id)
        self.store.update_player(
            player.player_id, claim_url=None, claim_uid=None, claim_ticket=None,
            claim_error=None)
        self.store.add_audit(
            "player", "player_leave", comp.id, player.player_id,
            details_json=json.dumps({"released_vm": released,
                                     "had_box": had_box}),
            remote_addr=self.client_address[0] if self.client_address else None)
        self._redirect("/", extra_headers={
            "Set-Cookie": self._clear_player_cookie()})

    def _handle_admin_new_competition(self, session) -> None:
        try:
            form = self._read_form()
        except Exception:
            self._render_admin_new_competition(session, "Malformed form.")
            return
        if not self._check_csrf(session, form):
            self._send_html(403, web.error_page(
                403, "Invalid CSRF token",
                "Go back, reload the page, and try again.", "", admin=True))
            return
        name = str(form.get("name", "")).strip()
        try:
            max_players = int(form.get("max_players", "32"))
            duration_min = int(form.get("duration_min", "120"))
        except ValueError:
            self._render_admin_new_competition(session, "Players and duration must be numbers.")
            return
        scenario = str(form.get("scenario", ""))
        scenario_name, _, version = scenario.rpartition("|")
        try:
            scenario_version = int(version)
        except ValueError:
            self._render_admin_new_competition(session, "Pick a scenario from the list.")
            return
        # The picker only ever offers the box folder's current versions, so a
        # mismatch here is a stale form (or a hand-rolled POST): refuse it --
        # competitions are migrated to new versions, never run back-compatible.
        sync_errors = scenario_mod.sync_box_scenarios(self.store)
        if sync_errors:
            self._render_admin_new_competition(
                session, "Scenario folder: " + "; ".join(sync_errors[:3]))
            return
        current = scenario_mod.current_box_scenario(scenario_name)
        if current is not None and scenario_version != current[0]:
            self._render_admin_new_competition(
                session,
                f"Scenario {scenario_name} v{scenario_version} is not current "
                f"(engine has v{current[0]}); migrate the competition to the "
                f"current version.")
            return
        if self.store.get_scenario(scenario_name, scenario_version) is None:
            err = (f"Scenario {scenario_name} v{scenario_version} is not on the "
                   f"engine; the engine's box folder has no such scenario.")
            self._render_admin_new_competition(session, err)
            return
        # Derive the slug from the name. No pool is chosen here: a dedicated
        # pool is provisioned per competition at first claim (claims.ensure_pool).
        slug = competition.derive_slug(
            name, {c.slug for c in self.store.list_competitions()})
        try:
            theme = json.dumps({"accent": web.sanitize_accent(form.get("accent") or "#5f4a38")})
            comp = competition.create_competition(
                self.store, slug=slug, name=name,
                scenario_name=scenario_name, scenario_version=scenario_version,
                max_players=max_players, duration_s=max(60, duration_min * 60),
                theme_json=theme, join_instructions=None)
        except (ValueError, TypeError) as exc:
            self._render_admin_new_competition(session, str(exc))
            return
        self.store.add_audit(session.username, "competition_create", comp.id,
                             details_json=json.dumps({"slug": comp.slug}),
                             remote_addr=self.client_address[0] if self.client_address else None)
        self._redirect(f"/admin/competitions/{comp.id}")

    def _handle_admin_competition_action(self, comp_id: str, action: str) -> None:
        ok, actor, session, _via = self._admin_actor()
        if not ok:
            self._send_json(403, {"error": "admin authentication required"})
            return
        try:
            form = self._read_form()
        except Exception:
            form = {}
        if not self._check_csrf(session, form):
            self._send_json(403, {"error": "invalid CSRF token"})
            return
        comp = self.store.get_competition(comp_id)
        if comp is None:
            self._send_html(404, web.error_page(
                404, "Competition not found",
                "It may have been removed.", "/admin", admin=True))
            return
        if action == "rerun":
            if comp.status != "ended":
                if session is None:
                    self._send_json(409, {"error": "only ended competitions can be rerun"})
                else:
                    self._send_html(409, web.error_page(
                        409, "Not rerunnable",
                        "Only ended competitions can be rerun.",
                        f"/admin/competitions/{comp.id}", admin=True))
                return
            # A rerun pins the old scenario version; if the box folder has
            # moved on, refuse rather than silently run a stale rubric.
            current = scenario_mod.current_box_scenario(comp.scenario_name)
            if current is not None and comp.scenario_version != current[0]:
                message = (f"Scenario {comp.scenario_name} v{comp.scenario_version} "
                           f"is not current (engine has v{current[0]}); migrate "
                           f"this competition by creating a new one on the "
                           f"current version.")
                if session is None:
                    self._send_json(409, {"error": message})
                else:
                    self._send_html(409, web.error_page(
                        409, "Scenario version moved on", message,
                        f"/admin/competitions/{comp.id}", admin=True))
                return
            taken = {c.slug for c in self.store.list_competitions()}
            try:
                new = competition.create_competition(
                    self.store, slug=competition.derive_slug(comp.name, taken),
                    name=comp.name, scenario_name=comp.scenario_name,
                    scenario_version=comp.scenario_version,
                    max_players=comp.max_players, duration_s=comp.duration_s,
                    workshop_pool_code=comp.workshop_pool_code,
                    theme_json=comp.theme_json,
                    join_instructions=comp.join_instructions)
            except (ValueError, TypeError) as exc:
                if session is None:
                    self._send_json(400, {"error": str(exc)})
                else:
                    self._send_html(400, web.error_page(
                        400, "Could not rerun", str(exc),
                        f"/admin/competitions/{comp.id}", admin=True))
                return
            self.store.add_audit(actor, "competition_rerun", comp.id,
                                 details_json=json.dumps(
                                     {"new_competition": new.id, "slug": new.slug}),
                                 remote_addr=self.client_address[0] if self.client_address else None)
            if session is None:
                self._send_json(200, {"ok": True, "rerun_of": comp.id,
                                      "competition": competition.public_competition_payload(
                                          self.store, new)})
                return
            self._redirect(f"/admin/competitions/{new.id}")
            return
        if action == "warm":
            if comp.status == "ended":
                message = "Only a draft or live competition can pre-deploy boxes."
                if session is None:
                    self._send_json(409, {"error": message})
                else:
                    self._render_admin_competition(session, comp.id, error=message)
                return
            try:
                count = int(form.get("count", "0"))
            except (TypeError, ValueError):
                count = 0
            result = claims.start_warm(self.store, comp, count)
            if result.get("status") == "error":
                message = result.get("error") or "Could not start pre-deploy."
                if session is None:
                    self._send_json(400, {"error": message})
                else:
                    self._render_admin_competition(session, comp.id, error=message)
                return
            self.store.add_audit(actor, "competition_warm", comp.id,
                                 details_json=json.dumps(
                                     {"requested": count,
                                      "status": result.get("status")}),
                                 remote_addr=self.client_address[0] if self.client_address else None)
            if session is None:
                self._send_json(200, result)
                return
            # No flash: the pre-deploy card's polled note is the one message
            # about warm state, so progress never needs a reload to show up.
            self._redirect(f"/admin/competitions/{comp.id}")
            return
        if action == "pool":
            pool = str(form.get("pool_code", "")).strip().upper()
            if pool:
                message = ("Pools are provisioned per competition; only "
                           "clearing a pinned pool is supported.")
                if session is None:
                    self._send_json(400, {"error": message})
                else:
                    self._render_admin_competition(session, comp.id, error=message)
                return
            self.store.update_competition(comp.id, workshop_pool_code=None)
            comp = self.store.get_competition(comp.id)
            back = f"{self._public_base()}/c/{comp.slug}/join/success"
            claimed = 0
            for p in self.store.list_players(comp.id):
                if p.status == "invited" and not p.box_id and not p.claim_url:
                    if claims.start(self.store, comp, p, back_url=back).get("ok"):
                        claimed += 1
            self.store.add_audit(actor, "competition_pool", comp.id,
                                 details_json=json.dumps(
                                     {"pool": None, "claims_started": claimed}),
                                 remote_addr=self.client_address[0] if self.client_address else None)
            message = "Workshop pool cleared; a dedicated pool is provisioned at the next claim."
            if claimed:
                message += f" Started {claimed} VM claim(s)."
            if session is None:
                self._send_json(200, {"ok": True, "pool": None,
                                      "claims_started": claimed})
                return
            self._redirect(f"/admin/competitions/{comp.id}?msg={message.replace(' ', '+')}")
            return
        if action == "delete":
            if comp.status != "ended":
                message = "Only ended competitions can be removed; end it first."
                if session is None:
                    self._send_json(409, {"error": message})
                else:
                    self._render_admin_competition(session, comp.id, error=message)
                return
            # Release every VM this competition handed out. cleanup_pool does
            # this too for pools the engine provisioned, but legacy pins were
            # only unpinned there -- a delete must not leak their VMs.
            base, _secret = claims.config()
            released = 0
            if base:
                for p in self.store.list_players(comp.id):
                    if not p.claim_uid:
                        continue
                    try:
                        workshop.release_vm(base, p.claim_uid)
                        released += 1
                    except workshop.WorkshopError:
                        pass  # portal already reaped it; keep deleting
            pool_stats = claims.cleanup_pool(self.store, comp)
            if not self.store.delete_competition(comp.id):
                message = "The competition could not be removed; reload and retry."
                if session is None:
                    self._send_json(409, {"error": message})
                else:
                    self._render_admin_competition(session, comp.id, error=message)
                return
            self.store.add_audit(actor, "competition_delete", comp.id,
                                 details_json=json.dumps(
                                     {"slug": comp.slug,
                                      "released_vms": released,
                                      "pool": pool_stats}),
                                 remote_addr=self.client_address[0] if self.client_address else None)
            if session is None:
                self._send_json(200, {"ok": True, "deleted": comp.id,
                                      "released_vms": released,
                                      "pool": pool_stats})
                return
            self._redirect("/admin")
            return
        if action == "start":
            # Going live pins the rubric for every player: refuse a draft
            # whose scenario version is no longer the box folder's current.
            current = scenario_mod.current_box_scenario(comp.scenario_name)
            if current is not None and comp.scenario_version != current[0]:
                message = (f"Scenario {comp.scenario_name} v{comp.scenario_version} "
                           f"is not current (engine has v{current[0]}); migrate "
                           f"the competition before starting it.")
                if session is None:
                    self._send_json(409, {"error": message})
                else:
                    self._send_html(409, web.error_page(
                        409, "Scenario version moved on", message,
                        f"/admin/competitions/{comp.id}", admin=True))
                return
            self.store.start_competition(comp.id)
        elif action == "end":
            self.store.end_competition(comp.id)
            # Best effort: hand the pool's VMs back and drop the pool config.
            claims.cleanup_pool(self.store, self.store.get_competition(comp.id))
        elif action == "close-join":
            self.store.set_join_open(comp.id, False)
        self.store.add_audit(actor, f"competition_{action}", comp.id,
                             remote_addr=self.client_address[0] if self.client_address else None)
        if session is None:
            self._send_json(200, {"ok": True, "action": action,
                                  "competition": competition.public_competition_payload(
                                      self.store, self.store.get_competition(comp.id))})
            return
        self._redirect(f"/admin/competitions/{comp.id}")

    def _handle_admin_player_action(self, player_id: str, action: str) -> None:
        ok, actor, session, _via = self._admin_actor()
        if not ok:
            self._send_json(403, {"error": "admin authentication required"})
            return
        try:
            form = self._read_form()
        except Exception:
            form = {}
        if not self._check_csrf(session, form):
            self._send_json(403, {"error": "invalid CSRF token"})
            return
        player = self.store.get_player(player_id)
        if player is None:
            self._send_html(404, web.error_page(
                404, "Player not found",
                "They may have been removed from the competition.", "/admin",
                admin=True))
            return
        comp = self.store.get_competition(player.competition_id)
        if action == "reissue":
            if player.status != "invited" or player.box_id:
                self._send_json(409, {"error": "reissue is only for players without a bound box"})
                return
            code = competition.generate_join_code()
            self.store.update_player(
                player.player_id, status="invited", box_id=None,
                join_code_hash=competition.hash_join_code(self.server_secret, code),
                join_code_plain=code,
                join_code_expires_at=time.time() + 1800,
                claim_error=None)
            base, secret = claims.config()
            if comp and player.claim_uid and base and secret:
                try:
                    workshop.push_prebind(
                        base, player.claim_uid, code, secret=secret,
                        back_url=f"{self._public_base()}/c/{comp.slug}/join/success")
                except workshop.WorkshopError:
                    pass  # the code is still valid for the terminal fallback
            self.store.add_audit(actor, "player_reissue", comp.id if comp else None,
                                 player.player_id, json.dumps({"code": code}))
            if session is None:
                self._send_json(200, {"ok": True, "player_id": player.player_id,
                                      "join_code": code})
                return
            if self.flash_store is not None and comp:
                # The roster no longer displays codes; the fresh one is shown
                # once via the one-time flash after this redirect.
                self.flash_store.put(session.session_hash, comp.id,
                                     f"Reissued code for "
                                     f"{player.display_name}: {code}")
            self._redirect(f"/admin/competitions/{comp.id}" if comp else "/admin")
            return
        if action == "retry-claim":
            if player.status != "invited" or player.box_id:
                self._send_json(409, {"error": "only an unbound slot can claim a VM"})
                return
            back = (f"{self._public_base()}/c/{comp.slug}/join/success"
                    if comp else "")
            result = claims.reclaim(self.store, comp, player, back_url=back)
            self.store.add_audit(actor, "player_retry_claim",
                                 comp.id if comp else None, player.player_id,
                                 details_json=json.dumps(
                                     {"ok": bool(result.get("ok")),
                                      "error": result.get("error")}))
            if session is None:
                self._send_json(200 if result.get("ok") else 502, result)
                return
            self._redirect(f"/admin/competitions/{comp.id}" if comp else "/admin")
            return
        if action == "disqualify":
            self.store.set_player_status(player.player_id, "disqualified")
        elif action == "remove":
            self.store.remove_player(player.player_id)
        self.store.add_audit(actor, f"player_{action}",
                             comp.id if comp else None, player.player_id)
        if session is None:
            self._send_json(200, {"ok": True, "action": action})
            return
        self._redirect(f"/admin/competitions/{comp.id}" if comp else "/admin")

    def _handle_admin_upload_scenario(self):
        """JSON-only scenario import, kept for tooling (boxbuilder engine
        client, scripts). Uploads only seed the serving cache: the admin
        picker lists the box folder exclusively, and sync_box_scenarios
        overwrites/purges cache rows to mirror that folder."""
        ok, status, msg = self._admin_authorized()
        if not ok:
            self._send_json(status, {"error": msg})
            return
        try:
            body = self._read_json_body()
            if not isinstance(body, dict):
                raise ValueError("body must be an object")
            rubric = body["rubric"]
            adversary = body.get("adversary", {})
            if not isinstance(rubric, dict):
                raise ValueError("rubric must be an object")
            if not isinstance(adversary, dict):
                raise ValueError("adversary must be an object")
            scenario_name = rubric["scenario_name"]
            scenario_version = rubric["scenario_version"]
        except Exception:
            self._send_json(
                400,
                {"error": "malformed body; expected engine_record.json shape "
                          "{rubric: {..., scenario_name, scenario_version}, "
                          "adversary: {...}}"},
            )
            return
        errors = scenario_mod.validate_scenario_record(
            rubric, adversary, body.get("services", []), body.get("pool"))
        if errors:
            self._send_json(400, {"error": "invalid scenario record", "details": errors})
            return
        try:
            services = body.get("services", [])
            pool = body.get("pool")
            scenario_mod.save_scenario_record(self.store, rubric, adversary,
                                              services,
                                              pool if isinstance(pool, dict) and pool
                                              else None)
        except Exception:
            print("ERROR: could not persist scenario record", file=sys.stderr)
            self._send_json(500, {"error": "could not persist scenario record"})
            return
        self._send_json(200, {"ok": True, "scenario_name": scenario_name,
                              "scenario_version": scenario_version})

    def _rate_limited(self) -> bool:
        if self.rate_limiter is None:
            return False
        ip = self.client_address[0] if self.client_address else "unknown"
        if self.rate_limiter.allow(ip):
            return False
        self._send_json(429, {"error": "rate limited; retry later", "last_seq": None})
        return True

    def do_POST(self):
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/enroll":
            if self._rate_limited():
                return
            self._handle_enroll()
            return
        if path == "/join":
            if self._rate_limited():
                return
            self._handle_join()
            return
        if path == "/checkin":
            if self._rate_limited():
                return
            self._handle_checkin()
            return
        if path == "/admin/login":
            self._handle_admin_login()
            return
        if path == "/admin/logout":
            self._handle_admin_logout()
            return
        if path == "/admin/api/competitions":
            ok, actor, _session, _via = self._admin_actor()
            if not ok:
                self._send_json(403, {"error": "admin authentication required"})
                return
            try:
                body = self._read_json_body()
                if not isinstance(body, dict):
                    raise ValueError("expected a JSON object")
                theme = json.dumps({"accent": web.sanitize_accent(body.get("accent") or "#5f4a38")})
                slug = str(body.get("slug", "")).strip()
                if not slug:
                    slug = competition.derive_slug(
                        str(body.get("name", "")),
                        {c.slug for c in self.store.list_competitions()})
                scenario_name = str(body.get("scenario_name", ""))
                scenario_mod.sync_box_scenarios(self.store)
                raw_version = body.get("scenario_version")
                current = scenario_mod.current_box_scenario(scenario_name)
                if raw_version is None:
                    # Omitted version means "the box folder's current one".
                    if current is None:
                        raise ValueError(
                            f"scenario {scenario_name!r} is not in the engine's "
                            f"box folder; pass scenario_version explicitly")
                    scenario_version = current[0]
                else:
                    scenario_version = int(raw_version)
                    if current is not None and scenario_version != current[0]:
                        raise ValueError(
                            f"Scenario {scenario_name} v{scenario_version} is not "
                            f"current (engine has v{current[0]}); migrate the "
                            f"competition to the current version.")
                if self.store.get_scenario(scenario_name, scenario_version) is None:
                    raise ValueError(
                        f"Scenario {scenario_name} v{scenario_version} is not on "
                        f"the engine; the engine's box folder has no such "
                        f"scenario.")
                # Pools are provisioned per competition at claim time
                # (claims.ensure_pool); no caller-chosen pool is accepted.
                comp = competition.create_competition(
                    self.store, slug=slug,
                    name=body.get("name", ""),
                    scenario_name=scenario_name,
                    scenario_version=scenario_version,
                    max_players=int(body.get("max_players", 32)),
                    duration_s=int(body.get("duration_s", 7200)),
                    theme_json=theme,
                    join_instructions=body.get("join_instructions"),
                )
            except (ValueError, TypeError, KeyError) as exc:
                self._send_json(400, {"error": str(exc)})
                return
            self.store.add_audit(actor, "competition_create", comp.id)
            self._send_json(200, competition.public_competition_payload(
                self.store, comp))
            return
        if path == "/admin/competitions/new":
            session = self._admin_page_session()
            if session is None:
                self._send_html(401, web.login_page("Sign in to continue."))
                return
            self._handle_admin_new_competition(session)
            return
        if path.startswith("/admin/api/competitions/"):
            rest = path[len("/admin/api/competitions/"):].strip("/").split("/")
            if len(rest) == 2:
                self._handle_admin_competition_action(rest[0], rest[1])
                return
        if path.startswith("/admin/players/"):
            rest = path[len("/admin/players/"):].strip("/").split("/")
            if len(rest) == 2:
                self._handle_admin_player_action(rest[0], rest[1])
                return
        if path == "/admin/scenarios":
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if ctype == "application/json":
                self._handle_admin_upload_scenario()
                return
        if path == "/admin/tokens":
            self._handle_admin_create_token()
            return
        if path.startswith("/api/public/join/") and path.endswith("/claim"):
            if self._rate_limited():
                return
            rest = path[len("/api/public/join/"):].strip("/").split("/")
            if len(rest) == 2 and rest[1] == "claim":
                self._handle_public_reclaim(rest[0])
                return
        if path.startswith("/c/") and path.endswith("/join"):
            slug = path[len("/c/"):].strip("/").split("/")[0]
            self._handle_public_join(slug)
            return
        if path.startswith("/c/") and path.endswith("/leave"):
            slug = path[len("/c/"):].strip("/").split("/")[0]
            self._handle_public_leave(slug)
            return
        self._send_json(404, {"error": "not found"})

    def _handle_join(self):
        try:
            body = self._read_json_body()
        except Exception:
            self._send_json(400, {"error": "malformed JSON body"})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "malformed JSON body"})
            return
        sig = self._sig_header()
        if self._box_header_mismatches(body.get("box_id")):
            self._send_json(400, {"error": "X-HUITZILOPOCHTLI-Box does not match body box_id"})
            return
        status, payload = competition.handle_join(
            self.store, body, sig, self.server_secret)
        if status == 200:
            self.store.add_audit("system", "box_join", details_json=json.dumps(
                {"box_id": body.get("box_id"), "player_id": payload.get("player_id")}),
                remote_addr=self.client_address[0] if self.client_address else None)
        else:
            # Failed joins previously left no trace outside the HTTP response;
            # a line in the journal is how a misconfigured box gets diagnosed.
            print(f"join rejected ({status}): box={body.get('box_id')!r} "
                  f"scenario={body.get('scenario_name')!r} "
                  f"error={payload.get('error')!r}", flush=True)
        self._send_json(status, payload)

    def _handle_enroll(self):
        try:
            body = self._read_json_body()
        except Exception:
            self._send_json(400, {"error": "malformed JSON body"})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "malformed JSON body"})
            return
        sig = self._sig_header()
        if self._box_header_mismatches(body.get("box_id")):
            self._send_json(400, {"error": "X-HUITZILOPOCHTLI-Box does not match body box_id"})
            return
        try:
            result = enrollment.handle_enroll(self.store, body, sig)
        except EnrollError as e:
            self._send_json(e.status_code, {"error": e.message})
            return
        self._send_json(200, result)

    def _handle_checkin(self):
        try:
            body = self._read_json_body()
        except Exception:
            self._send_json(400, {"error": "malformed JSON body", "last_seq": None})
            return
        try:
            bundle = _bundle_from_dict(body)
        except Exception:
            self._send_json(400, {"error": "malformed bundle", "last_seq": None})
            return
        sig = self._sig_header()
        if self._box_header_mismatches(bundle.box_id):
            self._send_json(
                400, {"error": "X-HUITZILOPOCHTLI-Box does not match body box_id",
                      "last_seq": None},
            )
            return

        try:
            response = handle_checkin(
                self.store, bundle, sig, None, self.server_secret, None,
                next_checkin_s=self.next_checkin_s,
            )
        except CheckinError as e:
            self._send_json(
                e.status_code, {"error": e.message, "last_seq": e.last_seq}
            )
            return
        except Exception as e:  # noqa: BLE001 — fail closed with a mapped 500
            # rather than dropping the connection (the agent would treat that
            # as a transient failure and retry forever). The exception text
            # stays engine-side: it can carry rubric content (§2.4).
            print(f"ERROR: check-in for box {bundle.box_id!r} failed: {e!r}",
                  file=sys.stderr)
            self._send_json(
                500, {"error": "internal error during check-in", "last_seq": None}
            )
            return
        self._send_json(200, response)

    def _handle_admin_create_token(self):
        ok, status, msg = self._admin_authorized()
        if not ok:
            self._send_json(status, {"error": msg})
            return
        try:
            body = self._read_json_body()
            if not isinstance(body, dict):
                raise ValueError("body must be an object")
            scenario_name = body["scenario_name"]
            if not isinstance(scenario_name, str) or not scenario_name.strip():
                raise ValueError("scenario_name must be a non-empty string")
            ttl_s = body.get("ttl_s", 3600)
            # json.loads accepts NaN/Infinity: Infinity would mint a token
            # that never expires, NaN would break the NOT NULL insert.
            if (isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float))
                    or not math.isfinite(ttl_s) or ttl_s <= 0):
                raise ValueError("ttl_s must be a positive finite number")
            expires_at = time.time() + ttl_s
        except Exception:
            self._send_json(400, {"error": "malformed body; expected {scenario_name, ttl_s?: number}"})
            return
        token = secrets.token_urlsafe(32)
        self.store.create_token(token, scenario_name, expires_at)
        self._send_json(
            200, {"token": token, "scenario_name": scenario_name, "expires_at": expires_at}
        )



class _EngineHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a connection cap and per-thread TLS.

    Wrapping the listening socket would run each TLS handshake inside the
    single accept loop with no timeout, so one idle client could freeze the
    engine. Here the handshake runs in the worker thread under
    Handler.timeout, and connections beyond max_conns are closed at once.
    """

    # socketserver's default listen backlog is 5. A class checking in at the
    # same second would overflow it and get connections reset before the
    # engine ever saw them; the connection cap below is the real limiter.
    request_queue_size = 128

    def __init__(self, addr, handler, ssl_ctx=None, max_conns=64):
        self._ssl_ctx = ssl_ctx
        self._slots = threading.BoundedSemaphore(max_conns)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def finish_request(self, request, client_address):
        request.settimeout(self.RequestHandlerClass.timeout)
        if self._ssl_ctx is None:
            super().finish_request(request, client_address)
            return
        try:
            tls = self._ssl_ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            tls.close()


def _resolve_server_secret(store: Store) -> bytes:
    """Resolve server secret from env, store, or generate and persist."""
    secret_env = os.environ.get("HUITZILOPOCHTLI_SERVER_SECRET")
    if secret_env:
        return secret_env.encode("utf-8")

    stored = store.get_meta("server_secret")
    if stored is not None:
        return base64.b64decode(stored)

    secret = secrets.token_bytes(32)
    store.set_meta("server_secret", base64.b64encode(secret).decode("ascii"))
    return secret


def main() -> None:
    db_path = os.environ.get("HUITZILOPOCHTLI_DB_PATH", "huitzilopochtli.db")
    store = Store(db_path)

    server_secret = _resolve_server_secret(store)

    engine_record_path = os.environ.get("HUITZILOPOCHTLI_ENGINE_RECORD_PATH")
    if engine_record_path:
        record = _load_engine_record(engine_record_path)
        rubric = record.get("rubric")
        adversary = record.get("adversary", {})
        errors = scenario_mod.validate_scenario_record(rubric, adversary)
        if errors:
            raise SystemExit(
                f"{engine_record_path} is not a valid engine record:\n  "
                + "\n  ".join(errors)
            )
        scenario_mod.save_scenario_record(store, rubric, adversary,
                                          record.get("services", []))
        print(f"loaded scenario record from {engine_record_path}")

    # Mirror the box folder into the store at startup; the sweep loop keeps
    # it current, so a scenario bump purges stale versions without a restart.
    for sync_error in scenario_mod.sync_box_scenarios(store):
        print(f"scenario sync: {sync_error}", file=sys.stderr)

    Handler.store = store
    Handler.server_secret = server_secret
    Handler.admin_token = os.environ.get("HUITZILOPOCHTLI_ADMIN_TOKEN", "")
    Handler.flash_store = _Flash()
    try:
        rate = int(os.environ.get("HUITZILOPOCHTLI_RATE_LIMIT_PER_MIN", "600"))
        burst = int(os.environ.get("HUITZILOPOCHTLI_RATE_BURST", "100"))
    except ValueError:
        rate, burst = 600, 100
    Handler.rate_limiter = _RateLimiter(rate, max(1, burst))
    if not Handler.admin_token:
        print("WARNING: HUITZILOPOCHTLI_ADMIN_TOKEN not set; /admin/* endpoints disabled (503)")

    port = int(os.environ.get("HUITZILOPOCHTLI_PORT", "8080"))
    bind_host = os.environ.get("HUITZILOPOCHTLI_BIND", "127.0.0.1")
    max_conns = int(os.environ.get("HUITZILOPOCHTLI_MAX_CONNS", "64"))

    # Engine-authoritative check-in cadence (the agent sleeps this long
    # between cycles). Deliberately independent of rubric SLA intervals --
    # see the note in checkin.handle_checkin.
    try:
        Handler.next_checkin_s = max(1, int(
            os.environ.get("HUITZILOPOCHTLI_CHECKIN_INTERVAL_S", "60")))
    except ValueError:
        Handler.next_checkin_s = 60

    tls_cert = os.environ.get("HUITZILOPOCHTLI_TLS_CERT")
    tls_key = os.environ.get("HUITZILOPOCHTLI_TLS_KEY")
    scheme = "http"
    context = None
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)
        scheme = "https"
    else:
        print(
            "WARNING: running without TLS; set HUITZILOPOCHTLI_TLS_CERT/HUITZILOPOCHTLI_TLS_KEY "
            "to enable it"
        )

    try:
        sweep_interval = max(5, int(
            os.environ.get("HUITZILOPOCHTLI_SWEEP_INTERVAL_S", "15")))
    except ValueError:
        sweep_interval = 15

    def _sweep_loop() -> None:
        while True:
            time.sleep(sweep_interval)
            try:
                scenario_mod.sync_box_scenarios(store)
            except Exception as exc:  # one bad sweep must not kill the loop
                print(f"scenario sync error: {exc}", file=sys.stderr)
            if not claims.enabled():
                continue
            try:
                claims.sweep(store, server_secret)
            except Exception as exc:  # one bad sweep must not kill the loop
                print(f"sweep error: {exc}", file=sys.stderr)

    threading.Thread(target=_sweep_loop, name="huitz-sweep",
                     daemon=True).start()

    httpd = _EngineHTTPServer((bind_host, port), Handler, ssl_ctx=context,
                              max_conns=max_conns)

    print(f"huitzilopochtli engine listening on {scheme}://{bind_host}:{port} (db={db_path})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
