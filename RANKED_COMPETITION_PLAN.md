# Ranked competition mode — implementation plan

**Status:** implemented 2026-10-23; see Round 4 in `RANKED_TESTING.md`
**Target:** huitzilopochtli v1.1 / ranked competition release
**Scope:** a real competition surface on top of ranked mode: engine VM, public
join + per-competition leaderboard, admin console, per-player timed runs,
self-reported scored services, and a ranked-only box lineage.

---

## 1. Decisions locked from the Q&A

These are the product decisions this plan is built on. If any are wrong, say so
before phase 1.

1. **Identity is one person, one box.** No teams. The leaderboard entry is the
   player's display name.
2. **Players join online.** The join page collects the name, calls
   `workshop-vm-distribution`, and returns a Guacamole link plus a one-time
   join code for the box.
3. **Boxes are pre-built by the admin**, one per slot, from a ranked-only
   template. The engine does not clone Proxmox VMs.
4. **Scored services are self-reported SLA checks.** The box agent probes its
   own services; the engine scores the signed evidence. No engine-side service
   probing in this phase. This is explicitly a ranking ceiling, not a bug.
5. **The admin starts and ends the competition.** During that window anyone can
   join. Each player's clock starts when they join and ends after the configured
   duration. There is no pause.
6. **No TLS/proxy for now.** Engine listens on `0.0.0.0:8080`. Admin auth is
   HTTP Basic (implemented by the engine itself, so it also works later behind
   Cloudflare Tunnel). TLS/Cloudflare is a later phase.
7. **Honor boxes are not converted.** Ranked competitions require a separate
   box lineage with scored services and red-team exposure. This plan adds that
   lineage; it does not add an honor→ranked migration path.

---

## 2. What exists today and what is missing

| Area | Today | Gap |
|---|---|---|
| Engine | `POST /enroll`, `POST /checkin`, `GET /leaderboard?scenario=`, `GET /health`, admin scenario/token APIs | No competition/player/run model, no join flow, no web UI, no per-player clock, no end state |
| Scoring | Point-in-time + SLA ledger + adversary directives | SLA exists but is a low-level `is_sla` flag; no first-class "service" definition, display, or leaderboard breakdown |
| Leaderboard | JSON rows keyed by `box_id`, per scenario | Anonymous, no names, no competition, no services, no live page |
| Admin | Header-token JSON endpoints | No UI, no sessions, no CSRF, no roster, no start/end, no audit |
| Boxes | Honor boxes + a few hand-made ranked test variants | No ranked competition template with services and join support |
| Deployment | Engine run from a checkout/nohup in tests | No dedicated VM, systemd unit, backup, firewall, runbook |
| Handout | `workshop-vm-distribution` can clone a template and return a Guacamole link | No huitz integration; no way to bind a claimed VM to a player |

---

## 3. Product model

```
Competition (admin-created)
  ├─ scenario_name + scenario_version  (one scenario per competition)
  ├─ status: draft -> live -> ended
  ├─ max_players, duration_s
  ├─ workshop_pool_code
  └─ players
       ├─ display_name (unique per competition)
       ├─ join_code (one-time, short-lived)
       ├─ started_at / ends_at  (per-player clock)
       ├─ box_id                (one box per player)
       └─ services[]            (from the scenario)
```

### 3.1 Competition lifecycle

- **draft** — admin is configuring; join page not public.
- **live** — admin pressed Start. Join page accepts players until
  `max_players`, the admin closes joins, or the admin ends the competition.
- **ended** — admin pressed End, or the competition's own end condition fired.
  All runs freeze, check-ins get a `finished` response, leaderboard is final.

There is no pause. The admin can:
- close joins without ending runs,
- end the competition early (all runs end at that instant),
- remove/disqualify a player (audited).

### 3.2 Player run

- Player submits name on the join page.
- Engine reserves a player row, mints a join code, and claims a VM from the
  workshop pool.
- Player opens the Guacamole link, runs `huitz join`, enters the code.
- Engine binds the box to the player, sets `started_at = now`,
  `ends_at = started_at + duration_s`, and `t0 = started_at`.
- The agent checks in normally. The run ends at `ends_at` (or early at admin
  End). No pause, no extension in v1.

### 3.3 Join sequence

```
Player                    huitz engine                 workshop-vm-distribution
  |  POST /c/<slug>/join        |                                  |
  |  name --------------------->|                                  |
  |                            | validate name/slot                  |
  |                            | create player + join_code           |
  |                            | POST /api/claim {code: pool_code} ->|
  |                            |<------------- Guacamole URL -------|
  |<-- page: URL + join_code ---|                                  |
  |  open VM, run huitz join   |                                  |
  |  POST /join {code, pubkey}->|                                  |
  |                            | bind box, start clock, t0           |
  |<-- run_ends_at, interval ---|                                  |
  |  normal signed check-ins ->|                                  |
```

The join page also sets an HttpOnly player cookie so the player can reopen
`/c/<slug>/me` and recover their VM link/status. If they lose it, an admin can
reissue a join code.

### 3.4 Workshop integration

New env/config on the engine:

- `HUITZILOPOCHTLI_WORKSHOP_URL` — e.g. `http://10.0.0.x:5000`
- per-competition `workshop_pool_code`
- optional `workshop_claim_timeout_s` (default 15)

The engine calls `POST {workshop}/api/claim` with `{"code": "<pool_code>"}`.
- `200 {url, ...}` → store the URL on the player and show it.
- `202 {status: "provisioning", ticket}` → poll
  `GET {workshop}/api/redeem/{ticket}` until ready, then show the URL.
- `404/502` → keep the player in `invited` state, show retry, let the admin
  attach a manual URL.

The engine stores only the returned URL (which already contains the Guacamole
token), the workshop `uid` if present, and the expiry. It never needs Proxmox
credentials.

---

## 4. Data model

All changes are additive and migrated in place (`engine/store.py::_migrate_schema`).
Existing pre-1.0/1.0 databases must continue to open.

### 4.1 New tables

```sql
CREATE TABLE competitions (
    id TEXT PRIMARY KEY,                 -- uuid
    slug TEXT NOT NULL UNIQUE,           -- /c/<slug>
    name TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft', -- draft|live|ended
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

CREATE TABLE players (
    player_id TEXT PRIMARY KEY,          -- uuid
    competition_id TEXT NOT NULL REFERENCES competitions(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    display_name_norm TEXT NOT NULL,     -- lowercase/trimmed; UNIQUE with competition
    status TEXT NOT NULL DEFAULT 'invited', -- invited|running|finished|disqualified|removed
    join_code_hash TEXT,
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
    UNIQUE (competition_id, display_name_norm)
);

CREATE TABLE player_boxes (
    player_id TEXT NOT NULL REFERENCES players(player_id) ON DELETE CASCADE,
    box_id TEXT NOT NULL,
    bound_at REAL NOT NULL,
    unbound_at REAL,
    reason TEXT,
    PRIMARY KEY (player_id, box_id)
);

CREATE TABLE admin_sessions (
    session_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    competition_id TEXT,
    player_id TEXT,
    details_json TEXT,
    remote_addr TEXT
);
```

### 4.2 Existing table changes

```sql
ALTER TABLE boxes ADD COLUMN competition_id TEXT;  -- nullable for legacy boxes
ALTER TABLE boxes ADD COLUMN player_id TEXT;       -- nullable for legacy boxes
ALTER TABLE scores ADD COLUMN hardening_points INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scores ADD COLUMN service_points  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scenarios ADD COLUMN services_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE sla_state ADD COLUMN last_observed_at REAL NOT NULL DEFAULT 0;
ALTER TABLE sla_state ADD COLUMN last_changed_at REAL NOT NULL DEFAULT 0;
ALTER TABLE enrollment_tokens ADD COLUMN competition_id TEXT;  -- admin tokens stay compatible
ALTER TABLE enrollment_tokens ADD COLUMN player_id TEXT;
```

`boxes.box_id` remains the signing identity and the `checkins`/`sla_state` key.
`players.box_id` is the *current* box; `player_boxes` preserves history for
replacement/rejoin.

### 4.3 Invariants

- A player has at most one active box. A box has at most one player.
- `players.ends_at` is immutable once set (except admin end, which only shortens).
- A player's run is `running` while `now < ends_at` and competition is live.
- A box with no player (legacy) follows the existing per-box behavior.
- `scores.total = hardening_points + service_points`.
- Leaderboard only includes players in `running`/`finished` statuses; DQ/removed
  are hidden unless the admin views them.

---

## 5. Scored services (self-reported SLA)

### 5.1 Authoring shape

New optional top-level `services:` block in the scenario YAML:

```yaml
services:
  - id: web
    display: "Public web"
    type: http_uptime
    collect: {url: "http://127.0.0.1:8080/health"}
    expect: {equals: 200, field: status}
    interval_s: 60
    points_per_interval: 1
    hysteresis_fail_n: 2
    hysteresis_ok_n: 2
    max_intervals_per_checkin: 3
    timeout_s: 5
```

Supported service check types in v1:

- `service_state` — systemd/OpenRC unit active
- `http_uptime` — HTTP/HTTPS local probe
- `db_query` — TCP socket probe (already the degraded DB behavior)
- **new** `tcp_port` — generic `{host, port}` open probe, raw
  `{open: bool, error: str|null}`, matcher `equals` on `open`
- `command_json` / `powershell_json` — custom read-only probe

### 5.2 Compile

`authoring/compile.py` expands each service into:

- a `CheckSpec` with `id = "svc_" + service.id` (collision-checked),
  `category = vuln`, `is_sla = True`, `display_title = "SERVICE: <display>"`;
- a `RubricEntry` with `points = 0` and `sla = SlaParams(...)`;
- a public `ServiceSpec` in the manifest (id, check_id, display, type,
  interval_s, points_per_interval) — no expected values;
- the same `ServiceSpec` list in `engine_record.json`.

`authoring/validate.py` validates: unique ids, no collision with checks or
forensics, positive interval/points, known SLA keys, and service check types.

### 5.3 Engine scoring

- `sla_state` remains the source of truth for UP/DOWN and accrued points.
- On each check-in, update `last_observed_at`; set `last_changed_at` on a state
  transition.
- Add `service_points` to `scores`; `hardening_points` is the evaluator total.
- The check-in response gains service metadata (display name, state, accrued,
  last change) in addition to `sla_status`; old agents ignore extra fields.
- The leaderboard exposes a per-player `services[]` array.

### 5.4 Explicit ceiling

A self-reported service check proves the box *observed* the service working
from inside the box. It does not prove the service is reachable from the
player network or that a firewall is correct. State this on the competition
page and in the docs. Engine-side probes are a later, separate decision.

---

## 6. Protocol and API changes

### 6.1 New box join endpoint

`POST /join` — signed by the box key, same canonicalization/verification rules
as `/enroll`.

```json
{
  "join_code": "K7Q4M2",
  "box_id": "<uuid>",
  "public_key": "<base64>",
  "agent_version": "1.1.0",
  "scenario_name": "...",
  "scenario_version": 1
}
```

Response:

```json
{
  "ok": true,
  "player_name": "Ada",
  "competition_name": "Friday Night Ranked",
  "run_ends_at": 1730007200.0,
  "checkin_interval_s": 60,
  "last_seq": 0
}
```

Errors: `400` malformed, `403` bad signature/bad code, `409` competition
closed/full/name taken/box already bound, `410` code expired.

Validation order: shape → cheap code lookup → box/competition state → signature
→ bind + start (one transaction). Rate-limit per source IP.

### 6.2 Check-in changes

`CheckinResponse` gains (additive, defaults keep old agents working):

```python
run_status: str = "running"       # running|finished|disqualified|ended
run_ends_at: Optional[float] = None
player_name: Optional[str] = None
competition_name: Optional[str] = None
```

Behavior:

- `now >= player.ends_at` or competition `ended`: compute no new points, no SLA
  accrual, no adversary directives; return the frozen score with
  `run_status="finished"`.
- Otherwise `t0 = player.started_at` (not first check-in).
- A check-in that arrives after `ends_at` never credits the gap.
- Agent stops its loop and exits cleanly on `finished`/`ended` (keeps the cached
  final report).

### 6.3 Public API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/public/competitions` | live/upcoming/ended summaries |
| `GET` | `/api/public/competitions/<slug>` | detail + join state |
| `GET` | `/api/public/competitions/<slug>/leaderboard` | ranked players + services |
| `POST` | `/api/public/competitions/<slug>/join` | name + claim VM |
| `GET` | `/api/public/join/<player_id>/status` | poll workshop claim |
| `GET` | `/api/public/me` | player cookie → own status/link |

Existing `GET /leaderboard?scenario=` stays for compatibility but is superseded
by the competition endpoint.

### 6.4 Admin API

All admin routes require the admin session (Basic login + cookie) and a CSRF
header for state changes:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/admin/login` | Basic auth → session cookie + CSRF |
| `POST` | `/admin/logout` | clear session |
| `GET/POST` | `/admin/api/competitions` | list/create |
| `GET/PUT` | `/admin/api/competitions/<id>` | edit settings |
| `POST` | `/admin/api/competitions/<id>/start` | start competition |
| `POST` | `/admin/api/competitions/<id>/end` | end competition |
| `POST` | `/admin/api/competitions/<id>/close-join` | stop new joins |
| `GET` | `/admin/api/competitions/<id>/players` | roster + scores + services |
| `POST` | `/admin/api/players/<id>/reissue` | new join code |
| `POST` | `/admin/api/players/<id>/replace-box` | bind a new box, preserve score |
| `POST` | `/admin/api/players/<id>/disqualify` | remove from leaderboard |
| `POST` | `/admin/api/players/<id>/remove` | free the slot |
| `GET` | `/admin/api/competitions/<id>/export.csv` | results |
| `POST` | `/admin/api/scenarios` | upload engine record (multipart or JSON) |
| `GET` | `/admin/api/audit` | audit log |

Scenario upload reuses the existing validation path; the UI wraps
`POST /admin/scenarios` rather than duplicating it.

---

## 7. Web surface

### 7.1 Public pages

- `/` — competition index: live first, then upcoming/ended; join buttons.
- `/c/<slug>` — the main page:
  - competition name, status, player count, join button;
  - big total table: rank, player, total, hardening, services, status,
    time remaining, last check-in;
  - service chips per player (`web UP`, `db DOWN`);
  - auto-refresh every 5 s via `fetch`, with a `<noscript>` meta refresh;
  - "last updated" + engine health indicator.
- `/c/<slug>/join` — name form; validates length/characters; shows max-player
  state; handles workshop claim progress.
- `/c/<slug>/join/success` — Guacamole link button, join code, one-line
  "inside the VM run: `huitz join`", copy buttons, warning to save the page.
- `/c/<slug>/me` — player cookie: own status, VM link, join code, score.
- `/c/<slug>/display` — big-screen mode: no nav, large type, auto-refresh,
  top 10 + service summary.
- `/static/*` — one CSS file, one or two vanilla JS files, no CDN, no external
  fonts/images.

Rendering: stdlib only. Server-side HTML built with `html.escape` and a small
template helper; JS only for polling, copy buttons, and progressive enhancement.
All player names escaped; no `box_id`, IP, token, or rubric data in public HTML
or JSON.

### 7.2 Admin pages

- `/admin` — login + overview: competitions, live player counts, engine health,
  workshop health, recent audit.
- `/admin/competitions/new` — create: name, slug, scenario name/version,
  max players, duration (minutes), workshop pool code, optional theme/accent,
  join instructions, optional join secret.
- `/admin/competitions/<id>` — settings; Start/End/Close joins; roster with
  status/score/last check-in/services; reissue code; replace box; DQ/remove;
  export; scenario detail; audit.
- `/admin/scenarios` — upload/list engine records; validation errors rendered.
- `/admin/audit` — filterable admin action log.

UI style: same CSS as public, darker admin chrome. No SPA framework; forms post
to JSON endpoints and reload. Confirmation dialogs for destructive actions.
All state-changing calls require `X-CSRF-Token`.

### 7.3 Auth

- `HUITZILOPOCHTLI_ADMIN_USER` (default `admin`),
  `HUITZILOPOCHTLI_ADMIN_PASSWORD` required for admin; if unset, `/admin*`
  returns 503 (fail closed).
- HTTP Basic is verified once; then a random 256-bit session cookie
  (`HttpOnly`, `SameSite=Lax`, `Secure` when `PUBLIC_URL` is https) and a CSRF
  token. Session rows expire (default 8 h) and are purged.
- Login rate limit per IP (e.g. 10/min), constant-time compare, no username
  enumeration.
- Security headers: CSP (self only), `X-Content-Type-Options`, `X-Frame-Options:
  DENY` (except `/display` maybe SAMEORIGIN), `Referrer-Policy`.
- Direct HTTP is documented as lab-only; Cloudflare Tunnel/TLS is phase 8.

---

## 8. Engine VM

### 8.1 Provisioning

- **Name:** `huitzilopochtli-engine`
- **Base:** `base-ubuntu24.04-fix` (vmid 955), full clone (not linked, so the
  engine does not depend on a superseded template disk).
- **Resources:** 4 vCPU, 4 GB RAM, 15 GB disk (extend to 30 GB if logs/backups
  warrant). Engine is I/O-light; CPU matters for Ed25519 verification.
- **Network:** `vmbr0`, static LAN IP (TBD; collision-check first) or DHCP
  reservation. Set a stable hostname/DNS name; the signed manifest embeds
  `engine_url`, so the address must not drift.
- **VMID:** next free (currently 168) or a reserved engine block; verify before
  create.
- Create with `pmx.py clone 955 huitzilopochtli-engine --full --start`, wait for
  agent/IP (allow the documented 25–40 min first-boot case), then configure via
  guest exec.

### 8.2 Guest layout

```
/opt/huitzilopochtli/engine/          # common/ + engine/ + deploy/
/etc/huitzilopochtli/engine.env        # 0600, huitz:huitz
/var/lib/huitzilopochtli/engine.db     # 0600
/var/backups/huitzilopochtli/          # daily sqlite backups
/usr/local/bin/huitz-engine-health
```

Install: `python3`, `qemu-guest-agent`, `chrony`, `ufw`,
`unattended-upgrades`, `curl`, `ca-certificates`. No Docker, no database
server, no Node.

### 8.3 systemd

`huitzilopochtli-engine.service`:

- `User=huitz`, `Group=huitz`
- `WorkingDirectory=/opt/huitzilopochtli/engine`
- `ExecStart=/usr/bin/python3 -m engine.server`
- `EnvironmentFile=/etc/huitzilopochtli/engine.env`
- `Restart=on-failure`, `RestartSec=3`
- hardening: `NoNewPrivileges=true`, `PrivateTmp=true`,
  `ProtectSystem=strict`, `ProtectHome=true`,
  `ReadWritePaths=/var/lib/huitzilopochtli /var/backups/huitzilopochtli`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`.

`huitzilopochtli-backup.timer` runs a Python `sqlite3 .backup` to
`/var/backups/huitzilopochtli/engine-YYYYmmdd.db`, retains 7 daily + 4 weekly,
and verifies the copy opens and has the expected table count.

### 8.4 Env

```
HUITZILOPOCHTLI_BIND=0.0.0.0
HUITZILOPOCHTLI_PORT=8080
HUITZILOPOCHTLI_DB_PATH=/var/lib/huitzilopochtli/engine.db
HUITZILOPOCHTLI_ADMIN_USER=admin
HUITZILOPOCHTLI_ADMIN_PASSWORD=<generated, 0600>
HUITZILOPOCHTLI_SERVER_SECRET=<generated, persisted, backed up>
HUITZILOPOCHTLI_CHECKIN_INTERVAL_S=60
HUITZILOPOCHTLI_RATE_LIMIT_PER_MIN=600
HUITZILOPOCHTLI_RATE_BURST=100
HUITZILOPOCHTLI_MAX_CONNS=128
HUITZILOPOCHTLI_MAX_VERIFY=4
HUITZILOPOCHTLI_WORKSHOP_URL=http://<workshop-host>:5000
HUITZILOPOCHTLI_PUBLIC_URL=http://<engine-ip>:8080
```

### 8.5 Firewall / access

- allow `8080/tcp` from the player/workshop LAN;
- allow `22/tcp` from the admin workstation only;
- deny everything else inbound;
- document that Basic auth over HTTP is lab-only; Cloudflare Tunnel/Caddy TLS
  is a follow-up (phase 8) with `Secure` cookies and `https` `PUBLIC_URL`.

### 8.6 Deployment artifact

Add `engine/deploy/`:

- `install.sh` — idempotent: users, dirs, code copy, env, unit, timer, firewall;
- `engine.env.example`;
- `huitzilopochtli-engine.service`;
- `backup.py` + `.timer`;
- `healthcheck.py` — `/health`, DB writable, disk free, workshop reachable;
- `README.md` — VM clone, first boot, verify, backup/restore, upgrade.

`packaging/build_engine_bundle.py` builds a versioned tarball of `common/` +
`engine/` + `deploy/`, so the VM does not run from a git checkout.

---

## 9. Ranked competition box lineage

Honor boxes are explicitly **not** convertible. The ranked competition box is a
different build:

1. Start from a clean Linux/Windows base, not an honor template.
2. Scenario has:
   - hardening checks (point-in-time),
   - `services:` block (SLA),
   - adversary pool,
   - theme/handbook,
   - `mode: ranked`;
3. Boxbuilder adds a competition install mode:
   - installs `.pyz`, signed manifest, authoring public key, config with
     `engine_url`;
   - **no** `rubric.json`, no `.score.dat`, no pre-minted enrollment token;
   - agent unit starts disabled; `huitz join` writes identity and enables it.
4. `huitz join` is added to the CLI:
   - prompts for the one-time code (or takes `--code`);
   - calls `/join` (signed) and stores the returned run window;
   - enables/starts the ranked agent unit.
5. Build exactly one box per slot from this template, via
   `workshop-vm-distribution` (pool code stored on the competition).
6. The template must be network-exposed the way the competition expects:
   services reachable, firewall/rules intentional, no honor answer key, and
   disposable/resettable. Human red-team access is a separate network/ops
   decision, not something the engine grants.

Add a `boxbuilder` guard: a ranked competition install must refuse an
honor-sealed box unless the install dir has been fully cleared and the scenario
has at least one service; document the rebuild path instead of "converting".

---

## 10. Implementation phases

### Phase 0 — spike and contract checks (0.5–1 day)

- Verify `workshop-vm-distribution` `/api/claim` + ticket polling from a
  non-browser client.
- Verify `pmx.py` clone → agent → static network on 955.
- Confirm engine Ed25519 throughput at 30–50 boxes/60 s.
- Freeze the join/competition contract in a short design note.

**Exit:** no unknowns in VM/workshop mechanics; sample claim URL obtained.

### Phase 1 — competition/player/run foundation (2–3 days)

- Schema + migrations (`competitions`, `players`, `player_boxes`,
  `admin_sessions`, `audit_log`; scores/scenarios/sla columns).
- Store methods and unit tests.
- Competition create/start/end/close-join logic.
- Player join reservation, name normalization/uniqueness, max players,
  join-code mint/hash/expiry, reissue.
- Run clock (`started_at`, `ends_at`, `t0`) and frozen run behavior.
- `/join` signed endpoint; `/checkin` run-state handling; response fields.
- `/api/public/competitions*` JSON.

**Exit:** integration test creates a competition, joins a player, enrolls a
simulated box, scores two check-ins, ends the run, and shows a frozen score.

### Phase 2 — scored services (2–3 days)

- `services:` YAML schema + compile + validation.
- `tcp_port` check type.
- Manifest/engine-record service metadata.
- `sla_state` timestamps, `hardening_points`/`service_points` split.
- Check-in/leaderboard service payloads.
- Agent report/CLI service display.
- Unit + integration tests (UP/DOWN hysteresis, cap/forfeit, service split).

**Exit:** a scenario with 3 services shows per-service UP/DOWN and a
hardening/services/total breakdown in the leaderboard API.

### Phase 3 — engine VM and deployment (1 day + clone wait)

- Clone/configure `huitzilopochtli-engine` (955).
- Install code bundle, env, systemd unit, backup timer, firewall.
- Static IP/hostname, verify `/health`, admin Basic auth, DB 0600.
- Snapshot `engine-clean`; optional `huitzilopochtli-engine-template`.
- Backup/restore drill.

**Exit:** engine survives reboot; `/health` and `/admin` reachable from the
admin workstation; DB and env are `0600`; backup restores to a scratch DB.

### Phase 4 — public site (3–4 days)

- Static CSS/JS + template helper.
- `/`, `/c/<slug>`, `/c/<slug>/join`, success, `/me`, `/display`.
- Workshop claim client + polling + retry.
- Player cookie, name validation, join-code display/copy.
- Public JSON + auto-refresh; XSS/escaping tests.

**Exit:** two browser sessions can join, claim (mock) VMs, see names/codes, and
watch a live leaderboard update.

### Phase 5 — admin console (3–4 days)

- Basic login → session + CSRF; rate limit; security headers.
- Competitions list/create/edit; start/end/close joins.
- Roster, reissue code, replace box, DQ/remove, export.
- Scenario upload UI + validation display.
- Audit log.
- Admin page auth/CSRF/XSS tests.

**Exit:** an admin can run a full competition from the UI with no curl/JSON
editing.

### Phase 6 — ranked box + workshop pool (3–4 days)

- Boxbuilder competition install mode (`--no-enroll` / `mode:
  ranked-competition`).
- `huitz join` CLI; systemd unit enable/start.
- Build one ranked competition template with 3 services + 1 adversary event.
- Create a private workshop pool from it; claim a VM; join; score.
- Guard against honor→ranked conversion; docs.

**Exit:** fresh worked example: template → pool → join → live score with
services; honor box rejected with a clear message.

### Phase 7 — end-to-end competition test (3–5 days)

- 4–8 real VMs, 2 concurrently joined players, 2-hour clock shortened to 5 min
  for the test; services killed/restored; admin end; export.
- Engine restart mid-run; player rejoin/replace; workshop claim failure path.
- Load test 32 simulated boxes at 60 s.
- Backup/restore during a live test.

**Exit:** ranked competition round report with pass/fail, defects fixed, and a
runbook.

### Phase 8 — hardening and follow-ups (2–3 days)

- Cloudflare Tunnel/TLS, `https` PUBLIC_URL, Secure cookies.
- Optional engine-side service probes (only if explicitly re-scoped).
- Multi-box teams (not in this plan).
- Generic template with engine-served manifest (not in this plan).

---

## 11. Test plan

### Unit

- Competition/player/run state machine; max players; duplicate names; join-code
  expiry/reuse; reissue; replace-box score preservation.
- `services:` compile/matcher; `tcp_port`; SLA hysteresis/cap; score split.
- Admin session/CSRF/Basic auth; HTML escaping; CSP headers.
- Workshop client: 200/202/404/502/timeout; ticket polling.
- Migration from a 1.0 DB.

### Integration

- Full join → claim (mock workshop) → `/join` → check-in → leaderboard.
- Join while draft/ended/full/closed; bad code; expired code; duplicate box.
- Per-player clock; frozen score after `ends_at`; admin early end.
- Service UP→DOWN→UP with hysteresis and no back-pay.
- Engine restart mid-run (seq, T0, player clock, leaderboard survive).
- Public/admin pages: no rubric/box_id leak; auth required; CSRF rejected.
- Concurrent join race for the last slot.

### Proxmox / live

- Engine VM install and reboot.
- One ranked box template with services; claim via workshop; join; kill a
  service; verify score/leaderboard; restore.
- Two-player live competition with admin start/end.
- `tests/proxmox` opt-in tier, skipped without credentials.

### Security

- Basic auth brute force + timing.
- Join-code enumeration; rate limits; oversized bodies.
- XSS via display names; path traversal on static; SQLi on filters.
- No answer key in public HTML/JSON or box; no admin secret in logs.
- Check-in signature/replay/scenario-version paths remain covered.

### Load

- 32 simulated boxes at 60 s for 10 min; p95 check-in < 2 s; no seq gaps;
  leaderboard consistent; SQLite busy errors zero. Tune `MAX_VERIFY`/`MAX_CONNS`
  if needed.

---

## 12. Risks and explicit non-goals

**Risks**

- **Self-reported services are forgeable.** A root player can fake a healthy
  service. This is the existing ranked ceiling; do not present service points
  as independently verified.
- **Basic auth over HTTP** exposes the admin credential on the LAN. Lab-only
  until TLS/Cloudflare.
- **Per-player clocks** mean the live leaderboard compares players at different
  elapsed times. Show status/time remaining clearly; final standings are only
  meaningful at competition end.
- **Workshop coupling**: if the workshop portal is down, joins fail; keep a
  manual attach-URL admin path.
- **SQLite + Ed25519**: 30–50 boxes is plausible, but the verify gate and
  connection cap must be tuned and measured.
- **Ranked boxes are exposed to red team.** Network isolation, snapshots, and
  resets are ops requirements; huitz does not provide them.

**Non-goals in this plan**

- Teams / multi-box aggregation.
- Engine-side service probing.
- Pausing a competition.
- Engine-driven Proxmox cloning.
- Honor→ranked conversion.
- TLS/Cloudflare in phase 1.
- A generic box image that can join any scenario (per-competition template for
  now).

---

## 13. Docs to add/update

- `RANKED_COMPETITION.md` — operator runbook: create competition, upload
  scenario, build ranked template, create workshop pool, start, monitor, end,
  export, restore.
- `architecture.md` — competition/player/run model, `/join`, run clock, services,
  admin/public surface, engine deployment.
- `README.md` / `AGENTS.md` — new entry points and invariants (honor ≠ ranked).
- `boxbuilder/README.md` — competition install mode and `huitz join`.
- `tests/README.md` — new competition tiers.
- `CLI.md` — `huitz join`.

---

## 14. Decisions taken during implementation

1. **Engine address:** static `10.0.0.160/24` on `vmbr0`; vmid 168, name
   `huitzilopochtli-engine`. The address is embedded in signed manifests, so
   changing it requires rebuilding box manifests.
2. **Defaults:** `max_players = 32`, `duration = 120 min`; the live test used
   smaller values. Joins open at admin Start and close at admin End or when the
   player cap is hit.
3. **Workshop pool creation:** performed through the workshop portal's admin
   API on its own host; huitz only calls `/api/claim`. A helper script was not
   added.
4. **Ranked box template:** one template per competition (manifest baked in)
   for v1. A generic engine-served-manifest template remains a future option.
5. **Red team:** only the existing signed directive executor was exercised.
   Human/automated red-team access is a network/ops decision outside huitz.
6. **Admin auth:** engine-side HTTP Basic over HTTP for the first round;
   Cloudflare Tunnel/TLS remains the planned follow-up.
