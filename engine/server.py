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
  POST /admin/scenarios   (gated by X-HUITZILOPOCHTLI-Admin-Token)
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
from urllib.parse import urlsplit, parse_qs

from common.schema import (
    Bundle, Category, CollectorStatus, Evidence, Rubric, RubricEntry, SlaParams,
    SCHEMA_VERSION, validate_rubric,
)
from engine import enrollment, leaderboard
from engine.checkin import CheckinError, handle_checkin
from engine.enrollment import EnrollError
from engine.store import Store


def _rubric_from_dict(d: dict) -> Rubric:
    entries = []
    for e in d.get("entries", []):
        sla = e.get("sla")
        sla_obj = SlaParams(**sla) if sla is not None else None
        entries.append(
            RubricEntry(
                check_id=e["check_id"],
                category=Category(e["category"]),
                matcher=e["matcher"],
                points=e["points"],
                sla=sla_obj,
            )
        )
    return Rubric(
        schema_version=d.get("schema_version", 1),
        scenario_name=d.get("scenario_name", ""),
        scenario_version=d.get("scenario_version", 0),
        entries=entries,
    )


def _load_engine_record(path: str) -> dict:
    """Load engine_record.json for seeding the store via save_scenario."""
    with open(path, "r") as f:
        return json.load(f)


def _validate_adversary_pool(adversary: dict) -> None:
    """Validate adversary pool at upload time; raises ValueError on bad input."""
    events = adversary.get("events", [])
    if not isinstance(events, list):
        raise ValueError("adversary.events must be a list")
    seen_ids = set()
    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"adversary.events[{idx}] must be an object")
        window_s = event.get("window_s")
        if (not isinstance(window_s, (list, tuple)) or len(window_s) != 2
                or not all(isinstance(b, (int, float)) and not isinstance(b, bool)
                            for b in window_s)):
            raise ValueError(
                f"adversary.events[{idx}].window_s must be [min_s, max_s] "
                f"(numeric pair), got {window_s!r}"
            )
        if window_s[0] > window_s[1]:
            raise ValueError(
                f"adversary.events[{idx}].window_s must have min_s <= max_s, "
                f"got {window_s!r}"
            )
        action = event.get("action")
        if not isinstance(action, str) or not action:
            raise ValueError(
                f"adversary.events[{idx}].action must be a non-empty string"
            )
        event_id = str(event.get("id", f"e{idx}"))
        if event_id in seen_ids:
            raise ValueError(
                f"adversary.events[{idx}] has duplicate event id {event_id!r}"
            )
        seen_ids.add(event_id)


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


class Handler(BaseHTTPRequestHandler):
    # Populated by main() before the server starts serving.
    store: Store = None
    server_secret: bytes = b""
    admin_token: str = ""
    next_checkin_s: int = 60

    timeout = 30

    def log_message(self, fmt, *args):  # quiet down default stderr access log
        pass

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
        return json.loads(raw.decode("utf-8"))

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
        if not self.admin_token:
            return False, 503, "admin endpoints disabled (HUITZILOPOCHTLI_ADMIN_TOKEN not set)"
        provided = self.headers.get("X-HUITZILOPOCHTLI-Admin-Token", "")
        # Bytes, not str: compare_digest raises TypeError on non-ASCII str,
        # and header values arrive latin-1-decoded.
        if not hmac.compare_digest(self.admin_token.encode("utf-8"),
                                   provided.encode("latin-1", "replace")):
            return False, 403, "bad admin token"
        return True, 0, ""

    # --- routing -------------------------------------------------------

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/health":
            self._send_json(200, {"ok": True})
            return
        if parts.path == "/leaderboard":
            qs = parse_qs(parts.query)
            scenario = qs.get("scenario", [None])[0]
            if not scenario:
                self._send_json(400, {"error": "missing scenario query param"})
                return
            rows = leaderboard.get_leaderboard(self.store, scenario)
            self._send_json(200, rows)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        parts = urlsplit(self.path)
        if parts.path == "/enroll":
            self._handle_enroll()
            return
        if parts.path == "/checkin":
            self._handle_checkin()
            return
        if parts.path == "/admin/tokens":
            self._handle_admin_create_token()
            return
        if parts.path == "/admin/scenarios":
            self._handle_admin_upload_scenario()
            return
        self._send_json(404, {"error": "not found"})

    def _handle_enroll(self):
        try:
            body = self._read_json_body()
        except Exception:
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

        scenario_row = self.store.get_scenario(bundle.scenario_name)
        if scenario_row is None:
            self._send_json(
                400,
                {
                    "error": "unknown scenario",
                    "scenario_name": bundle.scenario_name,
                    "last_seq": None,
                },
            )
            return
        try:
            rubric = _rubric_from_dict(json.loads(scenario_row["rubric_json"]))
            event_pool = json.loads(scenario_row["adversary_json"]).get("events", [])
        except (ValueError, KeyError, TypeError) as e:
            self._send_json(
                500,
                {
                    "error": f"stored scenario {bundle.scenario_name!r} has a "
                    f"malformed rubric: {e}",
                    "last_seq": None,
                },
            )
            return

        try:
            response = handle_checkin(
                self.store, bundle, sig, rubric, self.server_secret, event_pool,
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
            scenario_name = body["scenario_name"]
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

    def _handle_admin_upload_scenario(self):
        ok, status, msg = self._admin_authorized()
        if not ok:
            self._send_json(status, {"error": msg})
            return
        try:
            body = self._read_json_body()
            rubric = body["rubric"]
            scenario_name = rubric["scenario_name"]
        except Exception:
            self._send_json(
                400,
                {"error": "malformed body; expected engine_record.json shape "
                          "{rubric: {..., scenario_name}, adversary: {...}}"},
            )
            return
        errors = validate_rubric(rubric)
        if errors:
            self._send_json(400, {"error": "invalid rubric", "details": errors})
            return
        adversary = body.get("adversary", {})
        try:
            _validate_adversary_pool(adversary)
        except ValueError as exc:
            self._send_json(400, {"error": "invalid adversary pool", "detail": str(exc)})
            return
        self.store.save_scenario(scenario_name, json.dumps(rubric), json.dumps(adversary))
        self._send_json(200, {"ok": True, "scenario_name": scenario_name})


class _EngineHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a connection cap and per-thread TLS.

    Wrapping the listening socket would run each TLS handshake inside the
    single accept loop with no timeout, so one idle client could freeze the
    engine. Here the handshake runs in the worker thread under
    Handler.timeout, and connections beyond max_conns are closed at once.
    """

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
        scenario_name = record["rubric"]["scenario_name"]
        store.save_scenario(
            scenario_name, json.dumps(record["rubric"]), json.dumps(record.get("adversary", {}))
        )

    Handler.store = store
    Handler.server_secret = server_secret
    Handler.admin_token = os.environ.get("HUITZILOPOCHTLI_ADMIN_TOKEN", "")
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
