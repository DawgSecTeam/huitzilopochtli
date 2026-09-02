"""SQLite schema for engine/store.py. See architecture.md §11.2."""

SCHEMA = """
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

    -- Ensure a directive fires at most once per (box, event).
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
