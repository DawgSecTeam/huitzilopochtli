# Huitzilopochtli — Architecture & Implementation Specification

**Status:** decision-complete design spec; every architectural fork is resolved. *Non-goal* and *Open* sections are intentionally out of scope.
**Audience:** the engineer/agent implementing the tool. This is the source of truth for component contracts; where it and intuition disagree, follow this document or raise the conflict.
**Mental model:** identical collector everywhere; the only two knobs are where the evaluator runs and where the rubric (answer key) lives.

## 1. Purpose & Scope

Huitzilopochtli is a self-contained security-hardening scoring engine in the lineage of CyberPatriot (point-in-time hardening) and eCitadel/CCDC (continuous SLA + live adversary). It serves two use cases:

- **Honor** — offline, self-paced boxes distributed after workshops. No network; the person scored is trusted (cheating only cheats themselves).
- **Ranked** — an always-on external engine aggregates scores during timed practice, supports a live adversary, and keeps the answer key off the box.

The engine is portable: no mesh VPN, reverse proxy, or orchestration platform is assumed. Ranked mode's only infrastructure assumption is outbound reachability from box to one engine endpoint.

## 2. Design Principles (Invariants)

These are load-bearing.

1. **Collect/evaluate split.** The on-box collector gathers *facts* and makes **no scoring decisions**; scoring is a pure function of `(evidence, rubric, clock)`. That is what lets the same code run offline and online by relocating the evaluator.
2. **Checks emit structured evidence + a human reason, never a bare boolean.** The evaluator computes the verdict; the collector never asserts it.
3. **Offline is untimed.** Temporal scoring (SLA drip, adversary schedule) exists only in ranked mode, where the engine supplies the trusted clock. The box's wall clock is diagnostic only and never a scoring input.
4. **The box never holds the answer key in ranked mode.** The rubric (expected values + points) lives only on the engine; the manifest says *what to collect*, never *what is correct*.
5. **The box is stdlib-only, pure Python.** No third-party dependency runs on target; shared crypto is vendored. This is what makes the zipapp portable.
6. **Signing protects identity and transit integrity, not fact-honesty.** A root user can lie about facts; the signature proves *which* box sent a bundle and that it was not altered in flight (§3).
7. **The adversary cannot perform arbitrary outbound network activity.** Its action API is a closed allowlist; no scenario can author a callback.

## 3. Trust Model & The Honest Ceiling

State this in user-facing docs; do not let it be implied.

| Mode | Evaluator runs on | Rubric lives on | Clock | Timed? | Adversary? | Trust of the reported score |
|---|---|---|---|---|---|---|
| **Honor** | box | box (ships with manifest) | none | no | no | Self-verified. Cheating is self-harm. No anti-tamper. |
| **Ranked** | engine | engine only | engine (authoritative) | yes | yes | **Signed self-report scored against a hidden rubric.** Attributable and tamper-evident *in transit*. NOT cheat-proof. |

**The ranked ceiling, plainly:** transport is push-only (§14), so the engine never reaches the box and cannot independently probe anything. Every fact — permissions, user lists, *and* service uptime — is self-reported by an agent the operator has root over. The per-box signature does not prove truthfulness.

**What ranked still buys** over offline honor mode:

1. **The rubric never touches the box.** The operator cannot read the answers and cannot fake a perfect score without reverse-engineering the agent and forging internally consistent evidence — the primary anti-casual-cheat lever.
2. **A trusted clock**, so timed scoring cannot be farmed by rolling the box clock.
3. **Central aggregation / leaderboard** across many boxes.
4. **Clean attribution** via per-box identity.

**Do not** stake consequential outcomes (grades, prizes with real value) on ranked scores. It is built for practice, workshops, and friendly leaderboards.

## 4. Terminology

- **Agent / Collector** — the on-box `.pyz` that collects facts and, in honor mode, scores and reports.
- **Engine** — the always-on ranked server.
- **Evidence** — a structured record of observed state from one check; no verdict.
- **Manifest** — signed JSON shipped to the box: what to collect + display metadata; no expected values.
- **Rubric** — expected values, points, and SLA parameters; engine-only in ranked, on-box in honor.
- **Scenario** — authored YAML compiling to a manifest, a rubric, and an engine record.
- **Bundle / check-in** — a signed evidence set the agent pushes (ranked) or evaluates locally (honor); one check-in is one push/response cycle.
- **Directive** — an engine instruction to the box (currently: adversary actions to run).
- **T0** — engine receipt time of a box's first check-in (or its competition run start); the timed-scoring anchor.

## 5. System Overview

### 5.1 Components

- **Authoring toolchain** (author's machine; may use PyYAML): compile, validate, sign.
- **Common library** (`common/`, stdlib, imported by agent and engine): schema, canonical serialization, vendored crypto, and the evaluator — so scoring is byte-identical wherever it runs.
- **Agent** (`.pyz` on box): check runtime, platform layer, evidence assembly, identity, transport (ranked), reporter, adversary executor (ranked).
- **Engine** (server): enroll/join/check-in endpoints, SLA ledger, adversary scheduler, SQLite storage, competitions, leaderboard.

### 5.2 The two-knob model

```
HONOR:  collector -> evidence -> evaluator (rubric on box) -> local HTML report
RANKED: collector -> evidence -> sign+push -> engine evaluator (rubric here)
                                  <- authoritative score + directives <- cached HTML
```

The collector path is identical; only the evaluator's and rubric's location change.

## 6. Data Model

All types live in `common/schema.py` as stdlib `@dataclass`; serialization is JSON (no Pydantic; validation is explicit, §6.7). `SCHEMA_VERSION = 1`; enums are `Mode` (`honor`, `ranked`), `Category` (`vuln`, `penalty`, `prohibited`), and `CollectorStatus` (`ok`, `error`, `timeout`).

### 6.1 CheckSpec (in Manifest — safe to ship to box)

`id`, `type`, `category`, `host_id` (`localhost` for single-host), `collect_params` (type-specific: **what to read**), `display_title`, `display_max_points` (UI only; points are rubric-side), `timeout_s` (5.0), `is_sla`. **Invariant:** `collect_params` must be sufficient to collect but never contain the expected/correct value — a `file_regex` spec carries the path and extraction pattern, not whether the extracted value is correct.

### 6.2 Evidence (collector output — no verdict, no points)

`check_id`, `check_type`, `host_id`, `status`, `raw` (type-specific collected values), `reason` (what was observed), `collected_monotonic` (local ordering), `collected_wall_claim` (**diagnostic only**).

### 6.3 RubricEntry (engine-only in ranked; on-box in honor)

`SlaParams`: `interval_s`, `points_per_interval`, `hysteresis_fail_n` (2), `hysteresis_ok_n` (2), `max_intervals_per_checkin` (3). `RubricEntry`: `check_id`, `category`, `matcher` (§10.2), `points` (signed; negative for penalty/prohibited), `sla` (`SlaParams | None`).

### 6.4 Manifest (signed, shipped to box)

`schema_version`, `scenario_name`, `scenario_version`, `mode`, `engine_url` (ranked only), `hosts`, `checks`, optional `theme`, `forensics` (`ForensicsQuestion`: `id`, `question`, `max_points`), `services` (`ServiceSpec`: `id`, `check_id`, `display`, `type`, `interval_s`, `points_per_interval`). It carries **no rubric, no adversary schedule, no seed**; forensics and service metadata are public only.

**Forensics:** the `forensics:` block compiles 1:1 into a public `CheckSpec(type="forensics_answer")` (question, points, answers-file path) plus an answer-key rubric entry. The agent writes `Forensics-Questions.txt` to the primary desktop user on first boot (write-if-missing — answers are never clobbered); the collector reads it each pass, and `answer_equals` scores it (normalized; blank/wrong earns nothing, never deducts). Ranked needs no engine changes: answers ride the bundle, keys stay engine-side.

### 6.5 Rubric (JSON; engine-held in ranked, ships with box in honor)

`schema_version`, `scenario_name`, `scenario_version`, `entries`. The adversary schedule, seed, and workshop pool live only in the engine record (§12, §21) — never in the manifest or on a ranked box.

### 6.6 Scoring result types (evaluator output)

`CheckResult`: `check_id`, `category`, `awarded_points`, `passed`, `reason`. `SlaStatus`: `check_id`, `state` (`UP`/`DOWN`), `accrued_points`, `history` (oldest → newest post-hysteresis states, ≤ `SLA_HISTORY_MAX = 10`). `ScoreBreakdown`: `scenario_name`, `scenario_version`, `total`, `results`, `sla_status` (empty in honor), `computed_at`.

### 6.7 Validation

`validate_manifest(obj)` and `validate_rubric(obj)` return human-readable errors (empty = valid). The authoring toolchain fails the build on errors; the agent refuses invalid or unsigned input. No silent coercion.

## 7. Canonical Serialization & Signing

Signatures must be computed over identical bytes on both sides.

- **Canonical form** (`common/canon.py`): `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`, no trailing newline. String values and dict keys are NFC-normalized before serialization, so composed and decomposed Unicode sign identically; keys that normalize to the same string are rejected.
- **Crypto** (`common/crypto/`): vendored pure-Python **Ed25519** pinned to a known reference implementation, plus `signing.py` (`keypair`, `sign`, `verify`). Do not hand-roll field arithmetic; pin the implementation and gate CI against published vectors (§19).
- **What is signed:** every scenario manifest by the authoring key (the agent verifies before running); every bundle/check-in by the box key (the engine verifies against the enrolled public key).
- **Transport:** TLS (stdlib `ssl`) on top of signing, so the box also knows it is talking to the real engine.

## 8. Scenario Authoring & Build Pipeline

Authors write readable YAML; PyYAML lives only here, on the author's machine.

### 8.1 One file, two targets

`boxes/<box>/scenario.yaml` holds the mode-independent base (`scenario`, `checks`, `theme`, `forensics`) — the honor box. An optional top-level `ranked:` block holds everything ranked-only: `engine_url`, extra `checks` (appended), scored `services`, the `adversary` schedule, and the workshop `pool`. `scenario.mode` is the *default build target*: `honor` means both targets are buildable, `ranked` means ranked-only (an honor build is refused). `--mode ranked` selects the ranked target. An honor build never reads the `ranked:` block, so ranked content cannot leak into an honor manifest or rubric structurally. There are no `scenario.ranked.yaml` / `box.ranked.yaml` files.

The authored field list (every key the block accepts, with examples) is
canonical in [`boxbuilder/README.md`](boxbuilder/README.md#the-inputs-you-author);
this section pins the behaviour it must have.

`common/scenario_record.py` is the single implementation of the merge (`merge_effective`) and of the whole source→engine-record pipeline, shared by `authoring/compile.py`, `boxbuilder/spec.py`, `boxbuilder/lint.py`, and the engine's box-folder source. `compile_scenario(..., mode=, engine_url=)` defaults to the file's `scenario.mode`. Engine address precedence: `--engine-url` > `$HUITZILOPOCHTLI_ENGINE_URL` > `ranked.engine_url` (a legacy top-level `scenario.engine_url` is also accepted); `http://127.0.0.1:8080` is the explicit "not configured" placeholder.

### 8.2 Build pipeline

`authoring/compile.py`: (1) parse and validate with actionable, path/index-referenced errors; (2) merge the target — honor strips ranked content, ranked appends `ranked.checks` and resolves the engine URL; (3) split into **manifest** (public collection instructions + display metadata), **rubric** (expected values + points + SLA params), and **engine record** (rubric + adversary + services + optional pool; never distributed to boxes); (4) sign the manifest with the authoring key; (5) emit `manifest.signed.json`, `rubric.json` (honor only, `0600`), `engine_record.json` (`0600`), and `authoring_public_key.b64`, surfacing `readme_warnings` from the spoiler lint.

### 8.3 Deployment facts

`boxes/<box>/box.yaml` is minimal: `scenario`, `nakon_config`, and `provider: {name, user[, port]}`. Provider host and password come from `--provider-*` or `$HUITZILOPOCHTLI_PROVIDER_*` at deploy time, never the committed file. The build workflow (compile/plant/install/package, `boxbuilder lint`) is in [`boxbuilder/README.md`](boxbuilder/README.md); promoting a build to a template is in [`boxbuilder/DEPLOY.md`](boxbuilder/DEPLOY.md).

## 9. The Collector (Agent)

Ships as a `.pyz` zipapp; entry point `agent/__main__.py`. Reads a local config (§9.7) giving the mode, manifest path, and (ranked) identity store path.

### 9.1 Check plugin system (`agent/checks/base.py`)

- A **registry** maps `type_key -> Check` subclass; `@register` makes a new type one self-contained file.
- `Check.collect(spec, ctx) -> Evidence`. Checks run **concurrently** (thread pool), each wrapped in its `timeout_s`; a hung check yields `Evidence(status=TIMEOUT)` and never stalls the run.
- Collection is **read-only** with respect to the scored system; the adversary is the only component allowed to mutate state (§12).

### 9.2 Concrete check types

`common/check_types.py` is the authoritative registry, and each check module documents its fixed `raw` shape. The architectural distinctions: `service_state`/`package` use the platform layer (§9.3); `http_uptime`/`db_query`/`tcp_port` are SLA-capable; `command_json`/`powershell_json` fail closed on bad output; `forensics_answer` is scored by `answer_equals` (§6.4).

### 9.3 Platform Abstraction Layer (`agent/platform/`)

Only distribution-specific operations are abstracted: init detection (`/run/systemd/system` → systemd; else `/sbin/openrc` or `rc-status` → OpenRC; else Windows), service state, and package presence. The result is a `PlatformContext` passed to every `collect()`; adding a distro is one strategy class with no check-code changes.

### 9.4 Evidence bundle assembly

`Bundle`: `box_id`, `seq` (monotonic per box, persisted in the identity store — the replay/dedup key), `boot_id` (`/proc/sys/kernel/random/boot_id`), `agent_version`, `scenario_name`, `scenario_version`, `evidence`, `created_wall_claim` (**diagnostic only**), `schema_version`. `boot_id` is reboot evidence; the engine does not reset SLA or uptime on a boot change — a reboot is observed through the next evidence, like any other gap.

### 9.5 Transport client — push-only, queue-and-forward (`agent/transport.py`)

**Ranked only.** The box always initiates; the engine never connects inward.

- Each cycle the agent builds a bundle, signs its canonical form, and `POST`s it to `<engine_url>/checkin` over TLS.
- If the network is unavailable, the signed bundle is queued to a local append-only file and retried. The engine deduplicates by `(box_id, seq)` and rejects `seq <= last_seq`; queued bundles keep their original `seq` and flush in order.
- Offline windows earn no SLA credit (§11.3): queueing is for correctness/attribution, not for reclaiming lost time. The response updates the cached score/report and executes any directives (§12).

### 9.6 Identity & enrollment (`agent/identity.py`)

**Ranked only.** On first boot, generate an Ed25519 keypair; the **private key never leaves the box** (identity file, `0600`). Read a one-time enrollment token (single-use, short TTL, low value: it only authorizes a pubkey binding), then `POST <engine_url>/enroll` over TLS with `{enrollment_token, box_id, public_key, agent_version, scenario_name, scenario_version}`. The engine binds `token -> box_id -> public_key`, consumes the token, and confirms; later check-ins authenticate against that key. `box_id` is generated at provisioning (UUID) and stored beside the key.

### 9.7 Local config

On-box JSON read at startup: `{mode, manifest_path, rubric_path (honor only), identity_path (ranked only), report_path, checkin_interval_s (ranked only), authoring_public_key_path, enrollment_token (ranked, consumed once), allow_unsigned_manifest (development escape hatch that fails closed without it), notifications}`. The only secret is the identity file (separate, `0600`); the enrollment token is useless after enrollment.

### 9.8 Local reporter

See §13.

## 10. The Evaluator (Pure Scorer)

Lives in `common/evaluator.py`, so honor agent and engine run **identical** logic. Pure function, no I/O:

```python
def evaluate(evidence: list[Evidence], rubric: Rubric, clock: "Clock") -> ScoreBreakdown: ...
```

### 10.1 Point-in-time scoring

For each non-SLA entry, match the corresponding evidence's `raw` against the entry's `matcher`, then award `points`:

- `VULN`: award `points` (positive) if matched, else 0.
- `PENALTY`: award `points` (negative) if the required state is **broken** (match fails), else 0.
- `PROHIBITED`: award `points` (negative) if the forbidden state **is present** (match succeeds), else 0.

`passed` and a `reason` are recorded per check. Missing/`ERROR`/`TIMEOUT` evidence scores as "not satisfied" for every category (VULN 0, PENALTY/PROHIBITED no negatives): a collector fault is never a confirmed observation.

### 10.2 Matchers

A matcher is a tagged dict evaluated against a check type's `raw`; each is a pure `(matcher, raw) -> (bool, reason)` in a registry. Tags: `equals`, `not_equals`, `contains`, `regex`, `mode_at_most`, `user_absent`, `user_present`, `group_members_subset_of`, `answer_equals`. The YAML shorthand (`expect: {equals: "no"}`) is tagged by the compiler without rewriting its keys.

### 10.3 SLA scoring

SLA entries are not scored in the point-in-time pass. The engine's SLA ledger (§11) scores them statefully, calling the matcher per check-in. Honor mode has no SLA (offline is untimed), so the on-box evaluator ignores them.

## 11. The Engine (Server)

Always-on and portable: a plain HTTP service behind TLS, stdlib-first.

### 11.1 Endpoints

- `POST /enroll` — §9.6/§14.1.
- `POST /join` — bind a competition box to a player slot (§21.2).
- `POST /checkin` — the core loop (§14.2).
- `GET /leaderboard?scenario=...` — aggregated scores (§11.4); `400` without the parameter, `200 []` for an unknown scenario.
- `GET /health` — liveness.
- `POST /admin/scenarios` — upload or replace an engine record (`{rubric, adversary, services?, pool?}`); `400` on invalid input. Tooling-only: it seeds the serving cache and never affects the admin picker.
- `POST /admin/tokens` — mint a one-time enrollment token (`{scenario_name, ttl_s?}`).
- Competition pages plus `/admin/*` CRUD and `/api/public/*` (§21.4).

Admin requests use the `X-HUITZILOPOCHTLI-Admin-Token` header compared against `HUITZILOPOCHTLI_ADMIN_TOKEN`, or an admin Basic/session login; the admin surface answers `503 disabled` when no credential is configured. Configuration is environmental: `HUITZILOPOCHTLI_DB_PATH`, `_PORT` (8080), `_BIND` (default `127.0.0.1`; `0.0.0.0` for real boxes), `_ADMIN_TOKEN`, `_TLS_CERT`/`_TLS_KEY` (plain HTTP with a loud warning otherwise), `_MAX_CONNS`, `_CHECKIN_INTERVAL_S` (poll cadence handed to boxes, default 60), `_MAX_VERIFY` (verify concurrency; saturation answers `503 engine busy`), `_RATE_LIMIT_PER_MIN`/`_RATE_BURST` (`/enroll` and `/checkin`, `429` when exhausted), `_SERVER_SECRET`, and `_ENGINE_RECORD_PATH` (single-scenario bootstrap). Request bodies are capped at 1 MiB and evidence nesting at 64 levels; oversized or non-JSON bodies get a clean `400`. The SQLite database is created `0600` because it holds the engine-only rubric, server secret, and live tokens.

### 11.2 Storage (`engine/store.py`)

Stdlib `sqlite3` by default; an optional Postgres backend behind the same interface remains *Open*. `engine/store_schema.py` is the authoritative table/column list: boxes, enrollment tokens, check-in audit, SLA state (including the tick-history ring), scores (with the hardening/service split), adversary log, scenario records keyed by `(scenario_name, scenario_version)` but pruned by `sync_box_scenarios` to exactly one current version per name (the box folder's), engine metadata, and the competition tables (§21). The database is created `0600`.

### 11.3 SLA ledger & hysteresis (`engine/sla.py`)

Per `(box_id, check_id)` the engine keeps a state machine. Each check-in reads the SLA evidence's up/down (via the matcher), then applies:

```
UP    --(consec_fail >= fail_n)-->  DOWN
DOWN  --(consec_ok   >= ok_n)  -->  UP
```

Counters reset on the opposite observation; a single flap does not change state. Missing or failed SLA evidence counts as **DOWN**, so a broken collector cannot hold a prior UP indefinitely.

**Accrual (engine clock only):** while `UP`, credit `floor(elapsed / interval_s)` intervals since `last_credited_at`, capped at `max_intervals_per_checkin`. Any excess is **forfeited** — the anchor moves to `received_at` minus only the sub-interval remainder — so a long silence or queued backlog cannot be drained later. No credit accrues while `DOWN` or during gaps. `T0` (first check-in; for a competition, run start) anchors the timeline, and all timing uses the engine's `received_at`, never the box clock.

**Invariant:** the box's self-reported clock never influences accrual; engine receipt time is the sole temporal authority.

### 11.4 Leaderboard / aggregation

`GET /leaderboard` returns ranked rows per scenario. On each check-in `scores.total` is the point-in-time total plus accrued SLA points (split into `hardening_points`/`service_points`). An adversary outage costs points only through the SLA it forces down; there is no separate penalty channel. Live rank is derived after the score write.

## 12. The Adversary

Ranked/live only (offline is untimed and has no adversary). The box does **not** hold the seed or schedule: the engine schedules and the box executes directives in check-in responses. Future events stay unknowable to the operator, and this is the only box-influencing channel consistent with push-only transport.

### 12.1 Engine-side scheduler (`engine/adversary_oracle.py`)

- Per box, derive a deterministic RNG per event from `(server_secret, box_id, event_id)` — reproducible for audit, unguessable to the operator, stable when a re-upload changes other events.
- Pick a concrete fire time within the event's `window_s`, anchored to `T0`.
- On each check-in, include due, unissued events in `directives` and persist them. **Delivery is at-least-once:** every response re-sends all issued directives (`issued_directives`), so a lost response cannot lose one. The agent records executed `event_id`s in `<identity_path>.directives` and skips repeats; a re-sent directive can run late.
- An event may name `affects_check: <sla-check-id or service id>`. The engine persists the fire time and forces that SLA **DOWN** from the issuing check-in until a *later* check-in's evidence shows health; the issuing check-in cannot count as restoration (its evidence predates execution). Recovery then follows `hysteresis_ok_n`. An event without `affects_check` costs only what its normal SLA evidence shows. The §3 caveat still applies: a root operator can falsely report instant restoration.

### 12.2 Box-side executor (`agent/adversary/`)

- Directives are parsed from the response and run through a **closed action vocabulary** (`actions.py`); there is no generic "run command" primitive.
- The allowlist (local, reversible by the student as the challenge): `flush_firewall`; `kill_service <service>` via the platform layer; `drop_inert_artifact <path>` — a benign inert marker inside a confined directory, never an executable payload or callback.
- **Hard constraint (§2.7):** no action may open an outbound connection to any host other than the engine. The action API has no network-egress primitive at all — enforced structurally, not by policy.

## 13. Reporting

Static HTML generated from the machine-readable `ScoreBreakdown`, so report and protocol share one payload. The page carries a `<meta http-equiv="refresh">`; **the refresh interval is display cadence only, never a scoring input.**

- **Honor box:** has the rubric, runs the evaluator locally, renders the real score on demand and each refresh.
- **Ranked box:** has no rubric and cannot compute anything. Its dashboard is a **cache of the engine's last response** (persisted in `report.json`, so an agent restart does not blank it). Before the first response it shows "submitted — awaiting engine" and labels the number as the engine's authoritative score. Countdowns anchor to the box's receipt time, so clock skew cannot make a fresh report read `00:00`.

Elements: cumulative total; point-in-time results (category, awarded, reason); SLA status (UP/DOWN, accrued); ranked, a "last confirmed by engine at <time>" stamp. Ranked opens with an **event bar** (time remaining, current position, both from the engine response), then two tabs: **Configuration & forensics** (point-in-time results) and **Service uptime** (current state plus the last ~10 engine-scored ticks per service). Tick history is engine-authoritative: a bounded per-service ring in `sla_state` ships in every response, so a box restart cannot rewrite it.

### 13.1 Derived board (`agent/board.py`)

Player-facing derived facts — fixed vulnerabilities, active penalties, forensics state, progress — are computed once from `(ScoreBreakdown, manifest)` and consumed by every renderer (HTML, `report.json`, `huitz`). Honor is positive-only in every medium: failed checks are never identified, only counted. Ranked is the full diagnostic (safe: the rubric is off-box).

### 13.2 Report snapshot (`agent/snapshot.py`, `report.json`)

Every grade writes a versioned snapshot (`snapshot_version: 1`) beside the HTML report; `sync-report.sh` (or the Windows task wrapper) mirrors both to each user's `~/Documents/huitzilopochtli/` and removes legacy Desktop copies. The snapshot is a *presentation* of the score — nothing feeds it back into the evaluator. Honor snapshots carry the derived board only (no per-check results or reasons), matching the HTML spoiler contract. Ranked snapshots add diagnostic results and SLA history, live `rank`/`rank_total`, and the run's `run_ends_at`.

### 13.3 Terminal report (`agent/cli.py` — `huitz`)

The zipapp doubles as a terminal console via verb dispatch (`huitz score|watch|readme|forensics|join|grade`; a bare config path keeps the classic one-shot run). `score`/`watch`/`readme`/`forensics` render the **snapshot**, so they work as any user — the sealed install dir is never touched (the Documents mirror is the source, as for the browser). `watch` is a live frame (1 s tick, alternate screen, a bell on changes seen while watching). `forensics` reads/edits the answers file in place (`agent/answers.py`, shared with the collector and template writer). `grade` re-runs the honor pipeline as root and is refused on ranked boxes; `join` is the ranked binding path. Terminal behavior (color depth honoring `NO_COLOR`, unicode, width, key polling without curses) lives in `agent/term.py`.

## 14. Protocol Specification

All requests use canonical JSON (§7) and TLS. Box→engine bodies are signed by the box key; the signature travels in `X-HUITZILOPOCHTLI-Sig` (base64) alongside `X-HUITZILOPOCHTLI-Box` (box_id). A `Box` header naming a different box than the body's `box_id` is rejected `400` before verification (the signed body is authoritative).

### 14.1 Enrollment

`POST /enroll` body: `{enrollment_token, box_id, public_key, agent_version, scenario_name, scenario_version}`. Response `200`: `{ok, box_id, checkin_interval_s}`. Errors: `400` malformed (non-object body; missing, wrong-typed, or out-of-range fields — `scenario_version` is a required 64-bit non-negative integer bound at enrollment) or unknown token; `409` token consumed or box already enrolled; `410` token expired. The request is signed with the key in the body (proof of possession), and cheap token-state checks run **before** signature verification, so an unauthenticated caller cannot burn verify capacity. Token validation, consumption, and box creation are one atomic store operation, so a race yields exactly one winner.

### 14.2 Check-in

`POST /checkin` takes the canonical `Bundle` (§9.4). The handler fails closed at each step:

1. Look up `box_id` → public key; unknown box → `403`.
2. `schema_version` or agent **major**-version mismatch → `400`, before signature work (leaks no enrollment info).
3. Verify the signature over the canonical body; bad signature → `403`. Verification is pure Python and holds the GIL for seconds, so a bounded verify gate answers `503 engine busy; retry` when saturated.
4. `scenario_name` mismatch → `400`; `scenario_version` mismatch → `409` (re-provision). Both run after verification, so they leak nothing unauthenticated. The rubric is loaded after verification by the enrolled `(scenario_name, scenario_version)`; a missing record is `409` with `last_seq`, never a pre-auth oracle.
5. `seq <= last_seq` → `409` with `last_seq` so the agent can resync.
6. T0-stamp through score-update runs as **one transaction** (`Store.atomic`): failure rolls back the seq advance, audit row, SLA ledger, and adversary log together, so retrying the bundle is scored rather than 409-rejected. Stamp `received_at = engine_now()` (the first check-in, or competition run start, sets `T0`); persist the audit row; evaluate point-in-time evidence against the engine rubric (`common.evaluate`); update the SLA ledger (§11.3) and adversary scheduler (§12.1); update `scores.total` and reply. Before sending, replace matcher reasons with the box's own evidence reasons: matcher reasons embed expected values (the answer key), and the box gets only its own evidence plus pass/points.

Response `200`: `server_time`, `score` (`total`, `results`, `sla_status[]` with `check_id`, `state`, `accrued_points`, `history`), `directives` (newly issued only), `issued_directives` (everything ever issued, for at-least-once delivery), `next_checkin_s`, `last_seq`, `run_status`, `run_ends_at`, `rank`, and `rank_total`. The `history` ring is oldest → newest (~10 observations); rank is the live position at scoring time. All are presentation facts, additive for older agents, never fed back into scoring.

`next_checkin_s` is the **engine's poll cadence** (`HUITZILOPOCHTLI_CHECKIN_INTERVAL_S`, default 60), deliberately not derived from rubric SLA intervals: accrual is elapsed-based and capped per check-in, so any cadence is correct, whereas a `min(interval_s)` cadence made fast rubrics spin boxes and slow rubrics freeze scoreboard updates. Errors: `400` client/verification (with `last_seq: null`), `403` unknown box/bad signature, `409` replay/stale seq or scenario-version mismatch (with authoritative `last_seq`), `500` internal (generic body — exception text can carry rubric content, §2.4).

### 14.3 Versioning

Every bundle and manifest carries `schema_version`, `agent_version`, and `scenario_version`. The engine rejects an incompatible `schema_version` and a mismatched agent major version. The box folder holds exactly one current version per scenario; the engine mirrors it into the store (startup, admin pages, sweep loop) and purges every other version — there is no backwards compatibility. Creating, starting, or rerunning a competition against a non-current version is refused with a migrate-the-competition error, and a check-in from a stale-version enrollment returns `409` (with `last_seq`) naming the current version. Competitions are migrated by creating them anew on the current version.

## 15. Interaction Flows

- **Honor run:** verify signed manifest → collect concurrently → assemble evidence → load local rubric → `common.evaluate(evidence, rubric, no-clock)` → write HTML + snapshot. No network, time axis, or adversary.
- **Ranked enrollment:** first boot → keypair (private key stays) → read one-time token → signed `POST /enroll` → engine binds pubkey and consumes token.
- **Ranked check-in loop:** every `checkin_interval_s` → collect → sign bundle (`seq++`) → `POST /checkin` → apply score/directives; on network failure queue and retry next cycle.
- **SLA accrual:** each check-in advances per-check hysteresis; while `UP`, capped drip accrues against engine-observed elapsed time; gaps and `DOWN` earn nothing.
- **Adversary lifecycle:** engine derives the schedule from `(server_secret, box_id, event_id)` → a due check-in returns a directive and starts docking → box executes locally → student remediates → later evidence shows restoration → credit resumes.
- **Offline queue flush:** bundles queue with preserved seq → reconnect flushes in order → engine dedups and scores each, but the SLA cap prevents cashing the backlog as continuous uptime.

## 16. Trust Boundaries & Security Requirements

| Boundary | Guarantee | Non-guarantee |
|---|---|---|
| Box → engine transit | TLS confidentiality + box-signature integrity | — |
| Box identity | Proves which enrolled box sent the bundle | Does not prove the box's facts are true |
| Rubric secrecy (ranked) | Answers never on the box; operator cannot read expected values | A root operator can forge internally consistent evidence |
| Clock (ranked) | Engine clock authoritative; time cannot be farmed | — |
| Adversary egress | Structurally no outbound connection except to the engine | — |
| Enrollment token | Single-use, short TTL, low value | Deliver over the provisioning channel, not in a shared image |

Requirements: the private box key is `0600` and never transmitted; the engine DB stores only public keys, so its compromise does not enable impersonation; every verification step in §14.2 fails closed; the authoring private key stays offline, and only the public authoring key ships.

## 17. Packaging & Deployment

- **Agent artifact:** Python **zipapp** (`.pyz`), stdlib plus vendored crypto; assumes `python3`. Minimal Alpine needs `apk add python3`. Native compilation is optional packaging convenience, irrelevant to security (ranked never trusts the box); glibc binaries do not run on musl, so prefer the zipapp.
- **Install:** systemd unit or OpenRC script starting at boot, plus an install dir (default `/opt/.huitzilopochtli/`) holding the `.pyz`, signed manifest, config, and (honor) rubric. The dir is dot-hidden and sealed `0700 root:root`; the honor rubric is obfuscated and `0600` (`common/rubric_codec.py`) — friction against casual discovery, not a security boundary. Windows uses `C:\ProgramData\huitzilopochtli\` with a SYSTEM scheduled task.
- **Player conveniences:** a world-readable copy of the `.pyz` at `/usr/local/bin/huitz` (a copy, not a symlink — the sealed dir blocks non-root traversal) and an `/etc/update-motd.d/` first-login banner. Windows gets a build-time hardening pass (`packaging/huitz-hardening-win.ps1`): Edge first-run off, logon modals off, Python MSI advertised-shortcut repair.
- **Distribution:** export the configured VM as `.ova`/`.qcow2`; the engine ships as a versioned tarball (`packaging/build_engine_bundle.py`) installed by `engine/deploy/install.sh` as a hardened systemd unit with a daily SQLite backup.
- **Re-arm/reset:** resets local state (seq, cached score, report, per-user mirrors, and — with `--reset-identity` — queue/directive/enrollment state) so a take-home box can be replayed without redeploy.
- **Version stamping:** engine, agent, scenario, and schema versions on every payload (§14.3).

## 18. Suggested Module Layout

| Path | Contents |
|---|---|
| `common/` | schema, canon, evaluator, matchers, check types, adversary vocabulary, crypto, rubric codec |
| `agent/` | entrypoint, collector, checks, platform, adversary executor, transport, identity, reporter/board/snapshot, `cli.py` |
| `engine/` | server, enrollment/check-in, scenario records, SLA, adversary oracle, store, competitions, web |
| `authoring/` | compile, validate, sign, readme lint, scenario modes |
| `boxbuilder/` | practice-box factory (own README and DEPLOY) |
| `packaging/` | zipapp and engine bundles, units, re-arm/reset |
| `tests/` | unit, integration, crypto vectors |

## 19. Build, Test & CI Requirements

The suite pins this document's contracts:

- Ed25519 known-answer vectors every commit; canonical-serialization byte tests across processes.
- Evaluator golden tests for every category and missing/`ERROR`/`TIMEOUT` evidence.
- Hysteresis and SLA-cap forfeit state-machine tests.
- Table-driven systemd/OpenRC/Windows mappings; a zipapp smoke-run across interpreter versions.
- An assertion that the action API exposes no network-egress primitive.
- Fail-closed tests for every `400/403/409/410/503` path in §14.

## 20. Non-goals & Open Items

**Non-goals:** cheat-proof ranked scoring (impossible under push-only + root, §3); engine-initiated probing (transport is push-only by decision); multi-host *implementation* (schema supports `host_id`; the first build is single-host); mode conversion (a box's mode is fixed at provisioning; an offline run cannot be promoted).

**Open (deferred, not blocking):** optional Postgres storage behind the `store.py` interface; additional check types (sysctl, cron, scheduled tasks) and matchers via the registries; multi-host execution once single-host is proven.

## 21. Ranked competition mode

Extends §11/§14 with the competition layer. It does not change the collect/evaluate split, the engine-authored rubric rule, or the engine receipt clock.

### 21.1 Model

A **competition** binds one `(scenario_name, scenario_version)`, a max player count, a per-player run duration, and the private workshop pool provisioned for it (§21.2). Status is `draft → live → ended`; there is no pause. A **player** is one display name, at most one active box, and one run: `started_at` at join and `ends_at = started_at + duration_s`, both engine-stamped; `T0` for that box is `started_at` (not its first check-in), and all scoring timestamps remain engine receipt time (§11.3). The admin can end early, freezing every run. A competition is provisioned from a ranked scenario with scored services and red-team exposure; its boxes are a separate lineage from honor boxes.

### 21.2 Join and provisioning

`POST /join` is the only binding operation: signed by the box key, consuming a one-time join code stored as an HMAC hash, so the box proves possession of its own key. The engine reserves a slot, mints the code, and claims a VM from the competition's own workshop pool. The claim carries the code and a shared prebind secret to the portal, which returns a **stable open link** (each open re-mints the console session) and, before the console appears, runs `huitz join --code <code>` in the guest through qemu-guest-agent. The box binds itself, and `started_at` — hence `T0` — is stamped at that bind (the player's click, not clone time). Without a prebind secret the page falls back to a terminal `huitz join`. Claim state and failures are tracked per player and shown on the join page, with a retry action.

**Each competition provisions its own workshop pool**, cloned on demand from the ranked template named in the scenario record's `pool:` block. The engine never selects among the portal's pre-existing pools, so a competition can never be handed an honor-mode box; a `pool:` block on an honor scenario is a validation error. Existing pins are honored, a template mismatch is refused, and ending a competition releases its VMs and deletes only the pool this engine provisioned.

### 21.3 Scoring and run end

Point-in-time scoring is unchanged. Self-reported **scored services** are declared in the ranked block's `services:` list; the compiler expands each into a check `id = svc_<id>` with `is_sla: true` and an SLA rubric entry, plus public `ServiceSpec` metadata in the manifest. `tcp_port` is a generic service probe. The engine splits `scores.total` into `hardening_points` + `service_points`. Self-reported service checks are explicitly **not** independent uptime verification (root-controlled evidence, §3). After `ends_at` (or admin End), check-ins are still accepted for seq continuity but return `run_status: finished|ended` and a frozen score; no SLA or adversary work runs.

### 21.4 Web surface

Public competition pages (`/`, `/c/<slug>`, join/join-success/me/display) and JSON under `/api/public/*`. Admin `/admin` (HTTP session + CSRF) covers competition CRUD, start/end/close-joins, roster, join-code reissue, disqualify/remove, audit, and CSV export; the scenario picker serves the committed box folder, which the engine parses itself (§8.2); `/admin/api/*` also accepts the legacy `X-HUITZILOPOCHTLI-Admin-Token`, and `POST /admin/scenarios` remains as a tooling-only cache seeder. The engine is stdlib + `sqlite3` + PyYAML (`http.server`, `sqlite3`, `yaml`); HTML is server-rendered and escaped.

### 21.5 Deployment and boxes

The engine ships as the tarball in §17. Ranked competition boxes are a **separate lineage**: a ranked template is built by installing the ranked variant over a clone of the sealed honor template (agent + signed manifest, no enrollment token); the build uses `compile --no-bundle`, so it needs neither nakon nor vulndb, and `install` only places files. The player binds with `huitz join`; the box carries no rubric and no token. An honor box cannot be converted, and there is no honor→ranked shortcut. The deploy/template loop is [`boxbuilder/DEPLOY.md`](boxbuilder/DEPLOY.md).
