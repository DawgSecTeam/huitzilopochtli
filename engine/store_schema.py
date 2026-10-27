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
    history_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (box_id, check_id)
);
CREATE TABLE IF NOT EXISTS scores (
    box_id TEXT PRIMARY KEY,
    scenario_name TEXT NOT NULL,
    total INTEGER NOT NULL,
    updated_at REAL NOT NULL,
    first_scored_at REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS adversary_log (
    box_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    issued_at REAL NOT NULL,
    params_json TEXT NOT NULL,
    fire_time REAL,
    affects_check TEXT,
    restored_at REAL
);

    -- Ensure a directive fires at most once per (box, event).
    CREATE UNIQUE INDEX IF NOT EXISTS idx_adversary_log_box_event
        ON adversary_log (box_id, event_id);

CREATE TABLE IF NOT EXISTS scenarios (
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    rubric_json TEXT NOT NULL,
    adversary_json TEXT NOT NULL,
    uploaded_at REAL NOT NULL,
    PRIMARY KEY (scenario_name, scenario_version)
);

CREATE TABLE IF NOT EXISTS engine_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Ranked competition mode (v1.1). All additive; legacy rows keep NULL
-- competition_id/player_id and retain the pre-competition behavior.
CREATE TABLE IF NOT EXISTS competitions (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    join_open INTEGER NOT NULL DEFAULT 0,
    max_players INTEGER NOT NULL,
    duration_s INTEGER NOT NULL,
    workshop_pool_code TEXT,
    theme_json TEXT,
    join_instructions TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    ended_at REAL,
    CHECK (status IN ('draft','live','ended'))
);

CREATE TABLE IF NOT EXISTS players (
    player_id TEXT PRIMARY KEY,
    competition_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    display_name_norm TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'invited',
    join_code_hash TEXT,
    join_code_plain TEXT,
    join_code_expires_at REAL,
    joined_at REAL NOT NULL,
    started_at REAL,
    ends_at REAL,
    finished_at REAL,
    box_id TEXT,
    claim_url TEXT,
    claim_uid TEXT,
    claim_ticket TEXT,
    claim_expires_at REAL,
    claim_error TEXT,
    claim_attempts INTEGER NOT NULL DEFAULT 0,
    claim_last_attempt_at REAL,
    claim_last_poll_at REAL,
    UNIQUE (competition_id, display_name_norm)
);

CREATE TABLE IF NOT EXISTS player_boxes (
    player_id TEXT NOT NULL,
    box_id TEXT NOT NULL,
    bound_at REAL NOT NULL,
    unbound_at REAL,
    reason TEXT,
    PRIMARY KEY (player_id, box_id)
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    session_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    competition_id TEXT,
    player_id TEXT,
    details_json TEXT,
    remote_addr TEXT
);
"""
