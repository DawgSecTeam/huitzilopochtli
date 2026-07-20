"""SQLite-backed storage. See architecture.md §11.2.

FROZEN — the Store class and record dataclasses below are the contract every
other engine/ module (enrollment.py, checkin.py, sla.py, adversary_oracle.py,
leaderboard.py) is built against. They only need these signatures, not this
file's implementation, so all of engine/ can be built in parallel.

PHASE 1 TASK: implement every method body against a sqlite3 schema covering
the tables in §11.2: boxes, enrollment_tokens, checkins, sla_state, scores,
adversary_log. Do not change method signatures.
"""
import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class BoxRecord:
    box_id: str
    public_key: str
    scenario_name: str
    scenario_version: int
    enrolled_at: float
    last_seq: int
    last_boot_id: Optional[str]
    t0: Optional[float]


@dataclass
class SlaStateRecord:
    box_id: str
    check_id: str
    state: str  # "UP" | "DOWN"
    consec_ok: int
    consec_fail: int
    last_credited_at: float
    accrued_points: int


@dataclass
class ScoreRow:
    box_id: str
    scenario_name: str
    total: int
    updated_at: float


_SCHEMA = """
CREATE TABLE IF NOT EXISTS boxes (
    box_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL DEFAULT 0,
    enrolled_at REAL NOT NULL,
    last_seq INTEGER NOT NULL,
    last_boot_id TEXT,
    t0 REAL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token TEXT PRIMARY KEY,
    scenario_name TEXT NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL
);

CREATE TABLE IF NOT EXISTS checkins (
    box_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    received_at REAL NOT NULL,
    bundle_json TEXT NOT NULL,
    UNIQUE(box_id, seq)
);

CREATE TABLE IF NOT EXISTS sla_state (
    box_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    state TEXT NOT NULL,
    consec_ok INTEGER NOT NULL,
    consec_fail INTEGER NOT NULL,
    last_credited_at REAL NOT NULL,
    accrued_points INTEGER NOT NULL,
    PRIMARY KEY (box_id, check_id)
);

CREATE TABLE IF NOT EXISTS scores (
    box_id TEXT PRIMARY KEY,
    scenario_name TEXT NOT NULL,
    total INTEGER NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS adversary_log (
    box_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    issued_at REAL NOT NULL,
    params_json TEXT NOT NULL
);

-- A directive fires at most once per (box, event). The UNIQUE index lets
-- concurrent check-ins race on INSERT OR IGNORE and lets the loser see it lost
-- (rowcount == 0), so a directive is never issued twice. Created as a separate
-- guarded index (not a table constraint) so it applies to pre-existing DBs
-- where `adversary_log` was created before this invariant existed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_adversary_log_box_event
    ON adversary_log (box_id, event_id);

CREATE TABLE IF NOT EXISTS scenarios (
    scenario_name TEXT PRIMARY KEY,
    rubric_json TEXT NOT NULL,
    adversary_json TEXT NOT NULL,
    uploaded_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS engine_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
    def __init__(self, db_path: str):
        """Open (creating if absent) the sqlite3 file at db_path and ensure
        the schema exists."""
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # --- enrollment.py -----------------------------------------------------

    def get_token(self, token: str) -> Optional[dict]:
        """Returns {"scenario_name": str, "expires_at": float,
        "consumed_at": float | None} or None if the token is unknown."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT scenario_name, expires_at, consumed_at FROM enrollment_tokens "
                "WHERE token = ?",
                (token,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "scenario_name": row["scenario_name"],
            "expires_at": row["expires_at"],
            "consumed_at": row["consumed_at"],
        }

    def consume_token(self, token: str) -> None:
        import time

        with self._lock:
            self._conn.execute(
                "UPDATE enrollment_tokens SET consumed_at = ? WHERE token = ?",
                (time.time(), token),
            )
            self._conn.commit()

    def create_box(self, box_id: str, public_key: str, scenario_name: str,
                    scenario_version: int = 0) -> None:
        import time

        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO boxes (box_id, public_key, scenario_name, scenario_version, "
                "enrolled_at, last_seq, last_boot_id, t0) "
                "VALUES (?, ?, ?, ?, ?, 0, NULL, NULL)",
                (box_id, public_key, scenario_name, scenario_version, now),
            )
            self._conn.commit()

    def enroll_box_atomic(self, token: str, box_id: str, public_key: str,
                            scenario_name: str, scenario_version: int = 0) -> str:
        """Atomically validate+consume an enrollment token and create the box.

        Holds `self._lock` across the entire check-and-mutate so two concurrent
        /enroll requests can never both pass the "consumed_at IS NULL" guard for
        the same one-time token (the TOCTOU that get_token + consume_token left
        open). The box row is bound to the *token's* scenario (the token is the
        authority), and a duplicate box_id is caught rather than surfacing as an
        unhandled IntegrityError.

        Returns a status string the HTTP layer maps onto an EnrollError code:
          "ok" | "unknown_token" | "already_consumed" | "expired"
          | "scenario_mismatch" | "duplicate_box"
        On "ok" the box exists and the token is marked consumed.
        """
        import time

        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT scenario_name, expires_at, consumed_at "
                "FROM enrollment_tokens WHERE token = ?",
                (token,),
            ).fetchone()
            if row is None:
                return "unknown_token"
            if row["consumed_at"] is not None:
                return "already_consumed"
            if row["expires_at"] < now:
                return "expired"
            if row["scenario_name"] != scenario_name:
                return "scenario_mismatch"
            try:
                self._conn.execute(
                    "INSERT INTO boxes (box_id, public_key, scenario_name, "
                    "scenario_version, enrolled_at, last_seq, last_boot_id, t0) "
                    "VALUES (?, ?, ?, ?, ?, 0, NULL, NULL)",
                    (box_id, public_key, row["scenario_name"], scenario_version, now),
                )
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return "duplicate_box"
            self._conn.execute(
                "UPDATE enrollment_tokens SET consumed_at = ? WHERE token = ?",
                (now, token),
            )
            self._conn.commit()
            return "ok"

    def create_token(self, token: str, scenario_name: str, expires_at: float) -> None:
        """Insert a fresh, unconsumed enrollment token. Used by the
        POST /admin/tokens endpoint (engine/server.py)."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrollment_tokens (token, scenario_name, expires_at, "
                "consumed_at) VALUES (?, ?, ?, NULL)",
                (token, scenario_name, expires_at),
            )
            self._conn.commit()

    # --- checkin.py ----------------------------------------------------------

    def get_box(self, box_id: str) -> Optional[BoxRecord]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, public_key, scenario_name, scenario_version, enrolled_at, "
                "last_seq, last_boot_id, t0 FROM boxes WHERE box_id = ?",
                (box_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return BoxRecord(
            box_id=row["box_id"],
            public_key=row["public_key"],
            scenario_name=row["scenario_name"],
            scenario_version=row["scenario_version"],
            enrolled_at=row["enrolled_at"],
            last_seq=row["last_seq"],
            last_boot_id=row["last_boot_id"],
            t0=row["t0"],
        )

    def set_t0_if_unset(self, box_id: str, t0: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE boxes SET t0 = ? WHERE box_id = ? AND t0 IS NULL",
                (t0, box_id),
            )
            self._conn.commit()

    def update_box_seq(self, box_id: str, seq: int, boot_id: str) -> bool:
        """Advance the box's last_seq, but only if `seq` is strictly greater
        than what's stored. Returns True if the row was updated, False if a
        concurrent check-in already advanced last_seq to >= seq (so the caller
        should treat this as a replay/stale seq). The `last_seq < ?` guard makes
        the seq check atomic with the write, closing the TOCTOU where two
        concurrent check-ins both read the same old last_seq."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE boxes SET last_seq = ?, last_boot_id = ? "
                "WHERE box_id = ? AND last_seq < ?",
                (seq, boot_id, box_id, seq),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def save_checkin(self, box_id: str, seq: int, received_at: float,
                      bundle_json: str) -> None:
        """Audit log insert into `checkins`."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO checkins (box_id, seq, received_at, bundle_json) "
                "VALUES (?, ?, ?, ?)",
                (box_id, seq, received_at, bundle_json),
            )
            self._conn.commit()

    def upsert_score(self, box_id: str, scenario_name: str, total: int) -> None:
        import time

        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO scores (box_id, scenario_name, total, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(box_id) DO UPDATE SET "
                "scenario_name = excluded.scenario_name, "
                "total = excluded.total, "
                "updated_at = excluded.updated_at",
                (box_id, scenario_name, total, now),
            )
            self._conn.commit()

    # --- sla.py --------------------------------------------------------------

    def get_sla_state(self, box_id: str, check_id: str) -> Optional[SlaStateRecord]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, check_id, state, consec_ok, consec_fail, "
                "last_credited_at, accrued_points FROM sla_state "
                "WHERE box_id = ? AND check_id = ?",
                (box_id, check_id),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return SlaStateRecord(
            box_id=row["box_id"],
            check_id=row["check_id"],
            state=row["state"],
            consec_ok=row["consec_ok"],
            consec_fail=row["consec_fail"],
            last_credited_at=row["last_credited_at"],
            accrued_points=row["accrued_points"],
        )

    def save_sla_state(self, rec: SlaStateRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO sla_state (box_id, check_id, state, consec_ok, "
                "consec_fail, last_credited_at, accrued_points) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(box_id, check_id) DO UPDATE SET "
                "state = excluded.state, "
                "consec_ok = excluded.consec_ok, "
                "consec_fail = excluded.consec_fail, "
                "last_credited_at = excluded.last_credited_at, "
                "accrued_points = excluded.accrued_points",
                (
                    rec.box_id,
                    rec.check_id,
                    rec.state,
                    rec.consec_ok,
                    rec.consec_fail,
                    rec.last_credited_at,
                    rec.accrued_points,
                ),
            )
            self._conn.commit()

    def update_sla_atomic(
        self, box_id: str, check_id: str, apply_fn
    ) -> "SlaStateRecord":
        """Atomically read-modify-write a SLA state row.

        `apply_fn(rec: SlaStateRecord | None) -> SlaStateRecord` is called with the
        current row (or None for a first-ever observation); it returns the new
        record to persist. The lock is held across the read, the apply, and the
        write, so concurrent check-ins updating the same (box_id, check_id) SLA
        cannot interleave and clobber each other (the lost-update race that the
        old get_sla_state -> mutate -> save_sla_state sequence had). This is the
        single correct write path for SLA state.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, check_id, state, consec_ok, consec_fail, "
                "last_credited_at, accrued_points FROM sla_state "
                "WHERE box_id = ? AND check_id = ?",
                (box_id, check_id),
            )
            row = cur.fetchone()
            rec = None if row is None else SlaStateRecord(
                box_id=row["box_id"],
                check_id=row["check_id"],
                state=row["state"],
                consec_ok=row["consec_ok"],
                consec_fail=row["consec_fail"],
                last_credited_at=row["last_credited_at"],
                accrued_points=row["accrued_points"],
            )
            new_rec = apply_fn(rec)
            self._conn.execute(
                "INSERT INTO sla_state (box_id, check_id, state, consec_ok, "
                "consec_fail, last_credited_at, accrued_points) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(box_id, check_id) DO UPDATE SET "
                "state = excluded.state, "
                "consec_ok = excluded.consec_ok, "
                "consec_fail = excluded.consec_fail, "
                "last_credited_at = excluded.last_credited_at, "
                "accrued_points = excluded.accrued_points",
                (
                    new_rec.box_id,
                    new_rec.check_id,
                    new_rec.state,
                    new_rec.consec_ok,
                    new_rec.consec_fail,
                    new_rec.last_credited_at,
                    new_rec.accrued_points,
                ),
            )
            self._conn.commit()
            return new_rec

    # --- adversary_oracle.py ---------------------------------------------------

    def get_issued_event_ids(self, box_id: str) -> set:
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id FROM adversary_log WHERE box_id = ?", (box_id,)
            )
            return {row["event_id"] for row in cur.fetchall()}

    def log_adversary_event(self, box_id: str, event_id: str, action: str,
                             issued_at: float, params: dict) -> bool:
        """Record that (box_id, event_id) fired. Returns True if this call was
        the one that logged it, False if it was already logged (by a concurrent
        check-in or an earlier one). Backed by INSERT OR IGNORE against the
        UNIQUE(box_id, event_id) index, so only the winner of a race returns
        True — the caller issues the directive only when it wins, guaranteeing a
        directive is never issued twice."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO adversary_log (box_id, event_id, action, "
                "issued_at, params_json) VALUES (?, ?, ?, ?, ?)",
                (box_id, event_id, action, issued_at, json.dumps(params)),
            )
            self._conn.commit()
            return cur.rowcount == 1

    # --- leaderboard.py --------------------------------------------------------

    def get_scores(self, scenario_name: str) -> list:
        """Returns list[ScoreRow], ranked descending by total.

        Ties are broken deterministically by earliest updated_at then box_id, so
        the leaderboard is reproducible across runs/DB vacuums (boxes that
        reached the same total at the same instant sort by a stable id rather
        than in unspecified SQLite row order).
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, scenario_name, total, updated_at FROM scores "
                "WHERE scenario_name = ? "
                "ORDER BY total DESC, updated_at ASC, box_id ASC",
                (scenario_name,),
            )
            rows = cur.fetchall()
        return [
            ScoreRow(
                box_id=row["box_id"],
                scenario_name=row["scenario_name"],
                total=row["total"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    # --- engine/server.py: multi-scenario support (POST /admin/scenarios) ---

    def save_scenario(self, scenario_name: str, rubric_json: str,
                       adversary_json: str) -> None:
        """Insert or replace the rubric+adversary record for a scenario."""
        import time

        with self._lock:
            self._conn.execute(
                "INSERT INTO scenarios (scenario_name, rubric_json, adversary_json, "
                "uploaded_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(scenario_name) DO UPDATE SET "
                "rubric_json = excluded.rubric_json, "
                "adversary_json = excluded.adversary_json, "
                "uploaded_at = excluded.uploaded_at",
                (scenario_name, rubric_json, adversary_json, time.time()),
            )
            self._conn.commit()

    def get_scenario(self, scenario_name: str) -> Optional[dict]:
        """Returns {"rubric_json": str, "adversary_json": str,
        "uploaded_at": float} or None if the scenario is unknown."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT rubric_json, adversary_json, uploaded_at FROM scenarios "
                "WHERE scenario_name = ?",
                (scenario_name,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "rubric_json": row["rubric_json"],
            "adversary_json": row["adversary_json"],
            "uploaded_at": row["uploaded_at"],
        }

    # --- engine/server.py: persisted server_secret (§4) ---------------------

    def get_meta(self, key: str) -> Optional[str]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM engine_meta WHERE key = ?", (key,)
            )
            row = cur.fetchone()
        return row["value"] if row is not None else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO engine_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()
