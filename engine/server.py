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
import os
import secrets
import ssl
import time
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from common.schema import (
    Bundle, Category, CollectorStatus, Evidence, Rubric, RubricEntry, SlaParams,
    validate_rubric,
)
from engine import enrollment, leaderboard
from engine.checkin import CheckinError, handle_checkin
from engine.enrollment import EnrollError
from engine.store import Store


def _empty_rubric() -> Rubric:
    """A Rubric with no entries. Used when a scenario has no uploaded record
    yet, so /health and /enroll remain smoke-testable without one."""
    return Rubric(schema_version=1, scenario_name="", scenario_version=0, entries=[])


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
    """Load engine_record.json (produced by authoring/compile.py). Returns
    the raw dict {"rubric": {...}, "adversary": {...}} for seeding the store
    via save_scenario (see main())."""
    with open(path, "r") as f:
        return json.load(f)


def _validate_adversary_pool(adversary: dict) -> None:
    """Validate the adversary pool at upload time (§12.1).

    Each event must have:
      - window_s: [min_s, max_s] numeric pair
      - action: non-empty string
    Missing or malformed events cause a 400 rejection so the engine never
    silently ignores a broken pool at check-in time.
    """
    events = adversary.get("events", [])
    if not isinstance(events, list):
        raise ValueError("adversary.events must be a list")
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
        action = event.get("action")
        if not isinstance(action, str) or not action:
            raise ValueError(
                f"adversary.events[{idx}].action must be a non-empty string"
            )


def _bundle_from_dict(d: dict) -> Bundle:
    evidence = []
    for ev in d.get("evidence", []):
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
    )


def _jsonable(obj):
    """Recursively convert dataclasses/Enums into plain JSON-serializable
    structures (dataclasses.asdict doesn't touch Enum values on its own in a
    way that json.dumps can serialize, so normalize explicitly)."""
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

    def _admin_authorized(self) -> "tuple[bool, int, str]":
        """Returns (ok, status_code_if_not_ok, message_if_not_ok)."""
        if not self.admin_token:
            return False, 503, "admin endpoints disabled (HUITZILOPOCHTLI_ADMIN_TOKEN not set)"
        provided = self.headers.get("X-HUITZILOPOCHTLI-Admin-Token", "")
        if not hmac.compare_digest(self.admin_token, provided):
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
        sig = self._sig_header()
        try:
            bundle = _bundle_from_dict(body)
        except Exception:
            self._send_json(400, {"error": "malformed bundle", "last_seq": None})
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
            # A stored rubric that doesn't parse into a valid Rubric means a bad
            # scenario record reached the DB (validate_rubric on upload should
            # prevent this, but a pre-existing/older DB could still hold one).
            # Fail closed with a clean 500 rather than an unhandled traceback.
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
            )
        except CheckinError as e:
            self._send_json(
                e.status_code, {"error": e.message, "last_seq": e.last_seq}
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
            # Guard the type here (inside the try): a JSON string/other type
            # would otherwise raise an unhandled TypeError at `time.time() + ttl_s`
            # below, escaping this handler as a 500. bool is a subclass of int,
            # so reject it explicitly.
            if isinstance(ttl_s, bool) or not isinstance(ttl_s, (int, float)):
                raise ValueError("ttl_s must be a number")
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
        # Validate the rubric BEFORE persisting: a malformed rubric stored here
        # would otherwise crash /checkin with an unhandled 500 deep inside
        # _rubric_from_dict (bad category -> ValueError, missing keys -> KeyError,
        # bad sla -> TypeError), and every box enrolled against it would be
        # permanently stuck. validate_rubric is the same structural check
        # authoring/compile.py applies; reject the upload with a 400 + the list.
        errors = validate_rubric(rubric)
        if errors:
            self._send_json(400, {"error": "invalid rubric", "details": errors})
            return
        adversary = body.get("adversary", {})
        _validate_adversary_pool(adversary)
        self.store.save_scenario(scenario_name, json.dumps(rubric), json.dumps(adversary))
        self._send_json(200, {"ok": True, "scenario_name": scenario_name})


def _resolve_server_secret(store: Store) -> bytes:
    """§4: prefer an explicit env var, else a secret persisted in the store
    (surviving restarts), else generate + persist a fresh one. This keeps
    the adversary schedule (derived from (server_secret, box_id)) stable
    across restarts without requiring an operator to manage the env var."""
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

    # Optional startup convenience: seed the DB from a single engine_record.json
    # via the same save_scenario() path POST /admin/scenarios uses, so the
    # existing enroll->checkin flow keeps working without an admin call.
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
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)

    tls_cert = os.environ.get("HUITZILOPOCHTLI_TLS_CERT")
    tls_key = os.environ.get("HUITZILOPOCHTLI_TLS_KEY")
    scheme = "http"
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        print(
            "WARNING: running without TLS; set HUITZILOPOCHTLI_TLS_CERT/HUITZILOPOCHTLI_TLS_KEY "
            "to enable it"
        )

    print(f"huitzilopochtli engine listening on {scheme}://0.0.0.0:{port} (db={db_path})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
