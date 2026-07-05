"""HTTP endpoints. See architecture.md §11.1. PHASE 2 (integration).

Wires engine.enrollment.handle_enroll / engine.checkin.handle_checkin /
engine.leaderboard.get_leaderboard behind stdlib http.server (or a thin WSGI
server) with a thread pool. Keep handlers themselves small; all logic lives
in the modules above.

Endpoints: POST /enroll, POST /checkin, GET /leaderboard?scenario=...,
GET /health.
"""
import base64
import dataclasses
import json
import os
import secrets
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from common.schema import Bundle, CollectorStatus, Evidence, Rubric, RubricEntry, SlaParams
from engine import enrollment, leaderboard
from engine.checkin import CheckinError, handle_checkin
from engine.enrollment import EnrollError
from engine.store import Store


def _empty_rubric() -> Rubric:
    """A Rubric with no entries. Used when no engine record has been loaded,
    so /health and /enroll remain smoke-testable without a scenario."""
    return Rubric(schema_version=1, scenario_name="", scenario_version=0, entries=[])


def _rubric_from_dict(d: dict) -> Rubric:
    entries = []
    for e in d.get("entries", []):
        sla = e.get("sla")
        sla_obj = SlaParams(**sla) if sla is not None else None
        entries.append(
            RubricEntry(
                check_id=e["check_id"],
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


def _load_engine_record(path: str):
    """Load engine_record.json (produced by authoring/compile.py) and return
    (rubric, event_pool). Known simplification (see final report): there is
    no per-scenario lookup / upload endpoint yet, so this single record is
    used for every check-in regardless of the box's declared scenario_name.
    """
    with open(path, "r") as f:
        record = json.load(f)
    rubric = _rubric_from_dict(record["rubric"])
    event_pool = record.get("adversary", {}).get("events", [])
    return rubric, event_pool


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
    rubric: Rubric = None
    event_pool: list = None

    def log_message(self, fmt, *args):  # quiet down default stderr access log
        pass

    def _send_json(self, status: int, body) -> None:
        payload = json.dumps(_jsonable(body)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _sig_header(self) -> bytes:
        sig_b64 = self.headers.get("X-DAWGSCORE-Sig", "")
        try:
            return base64.b64decode(sig_b64) if sig_b64 else b""
        except Exception:
            return b""

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
        try:
            response = handle_checkin(
                self.store, bundle, sig, self.rubric, self.server_secret,
                self.event_pool,
            )
        except CheckinError as e:
            self._send_json(
                e.status_code, {"error": e.message, "last_seq": e.last_seq}
            )
            return
        self._send_json(200, response)


def main() -> None:
    db_path = os.environ.get("DAWGSCORE_DB_PATH", "dawgscore.db")
    store = Store(db_path)

    secret_env = os.environ.get("DAWGSCORE_SERVER_SECRET")
    if secret_env:
        server_secret = secret_env.encode("utf-8")
    else:
        # NOTE: production would need a persisted secret so the adversary
        # schedule (derived from (server_secret, box_id)) survives restarts.
        # For a first working version we generate a random one per process.
        server_secret = secrets.token_bytes(32)

    engine_record_path = os.environ.get("DAWGSCORE_ENGINE_RECORD_PATH")
    if engine_record_path:
        rubric, event_pool = _load_engine_record(engine_record_path)
    else:
        rubric, event_pool = _empty_rubric(), []

    Handler.store = store
    Handler.server_secret = server_secret
    Handler.rubric = rubric
    Handler.event_pool = event_pool

    port = int(os.environ.get("DAWGSCORE_PORT", "8080"))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"dawgscore engine listening on 0.0.0.0:{port} (db={db_path})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
