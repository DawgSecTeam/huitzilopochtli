"""SQLite-backed storage. See architecture.md §11.2."""
import contextlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Optional

from engine.store_schema import SCHEMA as _SCHEMA


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
    first_scored_at: float = 0.0




class Store:
    def __init__(self, db_path: str):
        """Open (creating if absent) the sqlite3 file at db_path and ensure
        the schema exists.

        The engine DB holds the engine-only rubric, the adversary server
        secret, live enrollment tokens and signed check-ins. SQLite creates a
        new file with 0666 & ~umask (usually 0644), which is world-readable on
        a multi-user engine host; create/tighten it to 0600.
        """
        # Reentrant so Store methods can run inside atomic() on the same thread.
        self._lock = threading.RLock()
        self._txn_depth = 0
        if db_path != ":memory:":
            directory = os.path.dirname(os.path.abspath(db_path))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700, exist_ok=True)
            fd = os.open(db_path, os.O_RDWR | os.O_CREAT, 0o600)
            os.close(fd)
            try:
                os.chmod(db_path, 0o600)
            except OSError:
                pass
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._migrate_schema()
            self._conn.commit()

    def _table_columns(self, table: str) -> dict:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {row["name"]: row for row in rows}

    def _migrate_schema(self) -> None:
        """Bring a pre-1.0 database up to the current shape in place.

        - scenarios: single row per name -> (name, version) composite key
        - scores: add immutable first_scored_at for stable tie-breaks
        - adversary_log: persist fire_time/affects_check/restored_at so the
          engine can enforce the outage floor
        """
        tables = {
            row["name"] for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        scenario_cols = self._table_columns("scenarios")
        if "scenarios" in tables:
            pk_cols = [name for name, row in scenario_cols.items() if row["pk"]]
            if "scenario_version" not in scenario_cols or pk_cols != [
                    "scenario_name", "scenario_version"]:
                rows = self._conn.execute(
                    "SELECT scenario_name, rubric_json, adversary_json, uploaded_at "
                    "FROM scenarios"
                ).fetchall() if scenario_cols else []
                self._conn.execute("DROP TABLE IF EXISTS scenarios__new")
                self._conn.execute(
                    "CREATE TABLE scenarios__new ("
                    "scenario_name TEXT NOT NULL, scenario_version INTEGER NOT NULL, "
                    "rubric_json TEXT NOT NULL, adversary_json TEXT NOT NULL, "
                    "uploaded_at REAL NOT NULL, "
                    "PRIMARY KEY (scenario_name, scenario_version))"
                )
                for row in rows:
                    try:
                        rubric = json.loads(row["rubric_json"])
                        version = rubric.get("scenario_version", 0)
                        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
                            version = 0
                    except (ValueError, TypeError, AttributeError):
                        version = 0
                    self._conn.execute(
                        "INSERT OR REPLACE INTO scenarios__new "
                        "(scenario_name, scenario_version, rubric_json, "
                        "adversary_json, uploaded_at) VALUES (?, ?, ?, ?, ?)",
                        (row["scenario_name"], version, row["rubric_json"],
                         row["adversary_json"], row["uploaded_at"]),
                    )
                self._conn.execute("DROP TABLE scenarios")
                self._conn.execute("ALTER TABLE scenarios__new RENAME TO scenarios")

        score_cols = self._table_columns("scores")
        if score_cols and "first_scored_at" not in score_cols:
            self._conn.execute(
                "ALTER TABLE scores ADD COLUMN first_scored_at REAL NOT NULL DEFAULT 0"
            )
            self._conn.execute(
                "UPDATE scores SET first_scored_at = updated_at WHERE first_scored_at = 0"
            )

        adv_cols = self._table_columns("adversary_log")
        if adv_cols:
            for column, decl in (
                ("fire_time", "REAL"),
                ("affects_check", "TEXT"),
                ("restored_at", "REAL"),
            ):
                if column not in adv_cols:
                    self._conn.execute(
                        f"ALTER TABLE adversary_log ADD COLUMN {column} {decl}"
                    )

    def _commit(self) -> None:
        """Commit unless an enclosing atomic() block owns the transaction."""
        if self._txn_depth == 0:
            self._conn.commit()

    @contextlib.contextmanager
    def atomic(self):
        """Run several Store calls as one transaction: all commit together on
        success, all roll back on any exception. Holds the store lock for the
        duration, so other threads' Store calls wait."""
        with self._lock:
            self._txn_depth += 1
            try:
                yield
                if self._txn_depth == 1:
                    self._conn.commit()
            except BaseException:
                if self._txn_depth == 1:
                    self._conn.rollback()
                raise
            finally:
                self._txn_depth -= 1

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
            self._commit()

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
            self._commit()

    def enroll_box_atomic(self, token: str, box_id: str, public_key: str,
                            scenario_name: str, scenario_version: int = 0) -> str:
        """Atomically validate and consume token and create box.

        Returns one of: ok | unknown_token | already_consumed | expired |
        scenario_mismatch | duplicate_box.
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
            self._commit()
            return "ok"

    def create_token(self, token: str, scenario_name: str, expires_at: float) -> None:
        """Insert a fresh, unconsumed enrollment token."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrollment_tokens (token, scenario_name, expires_at, "
                "consumed_at) VALUES (?, ?, ?, NULL)",
                (token, scenario_name, expires_at),
            )
            self._commit()

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
            self._commit()

    def get_or_set_t0(self, box_id: str, now: float) -> float:
        """Atomically set T0 if unset and return the authoritative value.

        Reading `box.t0` before the transaction meant two concurrent first
        check-ins could compute different T0s; the scheduler for the loser used
        its own receipt time instead of the committed anchor.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE boxes SET t0 = ? WHERE box_id = ? AND t0 IS NULL",
                (now, box_id),
            )
            row = self._conn.execute(
                "SELECT t0 FROM boxes WHERE box_id = ?", (box_id,)
            ).fetchone()
            self._commit()
            return float(row["t0"]) if row is not None and row["t0"] is not None else now

    def update_box_seq(self, box_id: str, seq: int, boot_id: str) -> bool:
        """Advance last_seq only if seq is strictly greater. Atomic via guard."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE boxes SET last_seq = ?, last_boot_id = ? "
                "WHERE box_id = ? AND last_seq < ?",
                (seq, boot_id, box_id, seq),
            )
            self._commit()
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
            self._commit()

    def upsert_score(self, box_id: str, scenario_name: str, total: int) -> None:
        import time

        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO scores (box_id, scenario_name, total, updated_at, "
                "first_scored_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(box_id) DO UPDATE SET "
                "scenario_name = excluded.scenario_name, "
                "total = excluded.total, "
                "updated_at = excluded.updated_at",
                (box_id, scenario_name, total, now, now),
            )
            self._commit()

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
            self._commit()

    def update_sla_atomic(
        self, box_id: str, check_id: str, apply_fn
    ) -> "SlaStateRecord":
        """Atomically read-modify-write an SLA state row via ``apply_fn``."""
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
            self._commit()
            return new_rec

    # --- adversary_oracle.py ---------------------------------------------------

    def get_issued_event_ids(self, box_id: str) -> set:
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id FROM adversary_log WHERE box_id = ?", (box_id,)
            )
            return {row["event_id"] for row in cur.fetchall()}

    def get_issued_directives(self, box_id: str) -> list:
        """Every directive issued to box_id, oldest first, as
        [{"event_id", "action", "params", "fire_time", "affects_check"}]."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id, action, params_json, fire_time, affects_check "
                "FROM adversary_log WHERE box_id = ? ORDER BY issued_at, rowid",
                (box_id,),
            )
            rows = cur.fetchall()
        return [
            {"event_id": r["event_id"], "action": r["action"],
             "params": json.loads(r["params_json"]),
             "fire_time": r["fire_time"], "affects_check": r["affects_check"]}
            for r in rows
        ]

    def log_adversary_event(self, box_id: str, event_id: str, action: str,
                             issued_at: float, params: dict,
                             fire_time: Optional[float] = None,
                             affects_check: Optional[str] = None) -> bool:
        """Record directive fire; True if this call won the race."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO adversary_log (box_id, event_id, action, "
                "issued_at, params_json, fire_time, affects_check) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (box_id, event_id, action, issued_at, json.dumps(params),
                 fire_time, affects_check),
            )
            self._commit()
            return cur.rowcount == 1

    def get_active_adversary_effects(self, box_id: str,
                                     received_at: float) -> list:
        """Issued events that name an SLA check and are not restored yet."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id, action, params_json, fire_time, affects_check, "
                "issued_at FROM adversary_log "
                "WHERE box_id = ? AND affects_check IS NOT NULL "
                "AND restored_at IS NULL AND fire_time IS NOT NULL "
                "AND fire_time <= ? ORDER BY issued_at, rowid",
                (box_id, received_at),
            )
            rows = cur.fetchall()
        return [
            {"event_id": r["event_id"], "action": r["action"],
             "params": json.loads(r["params_json"]),
             "fire_time": r["fire_time"], "affects_check": r["affects_check"],
             "issued_at": r["issued_at"]}
            for r in rows
        ]

    def mark_adversary_restored(self, box_id: str, event_id: str,
                                restored_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE adversary_log SET restored_at = ? "
                "WHERE box_id = ? AND event_id = ? AND restored_at IS NULL",
                (restored_at, box_id, event_id),
            )
            self._commit()

    # --- leaderboard.py --------------------------------------------------------

    def get_scores(self, scenario_name: str) -> list:
        """Return scores ranked by total, then immutable first-scored time.

        Ties used to be ordered by the *last* check-in timestamp ascending,
        which ranked the box that had been silent longest above active peers
        and let a player freeze a winning tie by stopping check-ins.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, scenario_name, total, updated_at, first_scored_at "
                "FROM scores WHERE scenario_name = ? "
                "ORDER BY total DESC, first_scored_at ASC, box_id ASC",
                (scenario_name,),
            )
            rows = cur.fetchall()
        return [
            ScoreRow(
                box_id=row["box_id"],
                scenario_name=row["scenario_name"],
                total=row["total"],
                updated_at=row["updated_at"],
                first_scored_at=row["first_scored_at"],
            )
            for row in rows
        ]

    # --- engine/server.py: multi-scenario support (POST /admin/scenarios) ---

    def save_scenario(self, scenario_name: str, scenario_version: int,
                       rubric_json: str, adversary_json: str) -> None:
        """Insert or replace one (name, version) scenario record."""
        import time

        with self._lock:
            self._conn.execute(
                "INSERT INTO scenarios (scenario_name, scenario_version, rubric_json, "
                "adversary_json, uploaded_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(scenario_name, scenario_version) DO UPDATE SET "
                "rubric_json = excluded.rubric_json, "
                "adversary_json = excluded.adversary_json, "
                "uploaded_at = excluded.uploaded_at",
                (scenario_name, scenario_version, rubric_json, adversary_json,
                 time.time()),
            )
            self._commit()

    def get_scenario(self, scenario_name: str,
                     scenario_version: int) -> Optional[dict]:
        """Return the record for an exact (name, version), or None.

        Version is part of the key so a v2 upload cannot silently rescore
        v1-enrolled boxes.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT rubric_json, adversary_json, uploaded_at FROM scenarios "
                "WHERE scenario_name = ? AND scenario_version = ?",
                (scenario_name, scenario_version),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "rubric_json": row["rubric_json"],
            "adversary_json": row["adversary_json"],
            "uploaded_at": row["uploaded_at"],
        }

    def get_latest_scenario_version(self, scenario_name: str) -> Optional[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(scenario_version) AS version FROM scenarios "
                "WHERE scenario_name = ?",
                (scenario_name,),
            ).fetchone()
        return row["version"] if row is not None else None

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
            self._commit()
