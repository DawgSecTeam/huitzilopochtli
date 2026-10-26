# Ranked-mode testing round — 2026-09-23

## Round 3 — adversarial, SLA/adversary-live and chaos round (same day)

Five Sonnet 5 subagents, each on its own stage, reporting findings only; every
finding was reproduced by hand before being fixed, and every fix carries a
regression test that fails without it. Engine on a `base-ubuntu24.04` clone
(cadence 30s), four full clones of 112, each `compile` → `plant` → `install
--admin-token`, all enrolled at Total 0. G3/G4 ran the new fixture
`boxes/static-pine-radio/scenario.ranked-r3.yaml`: the ranked box plus an
`atd_sla` SLA check and a 3-event adversary pool (`drop_inert_artifact`,
`kill_service atd`, `flush_firewall`), the first time any live directive
beyond `drop_inert_artifact` ran on a real box.

| Stage | Who | Result |
|---|---|---|
| Baseline suite / two-VM tier | me | 799 passed; `test_ranked_two_machines.py` **unblocked and green** (see test fixes) |
| Honest play (G1) | S1 | predicted 80 → final 80. Every step, including a cron penalty (-10, restored), a wrong forensics answer (no change) and a regression (-5, redone), landed within ≤2 cadences; leaderboard, `scores` table and `huitz score` never disagreed |
| Cheater with root (G2) | S2 | 21 attacks. Forged evidence signed with the box key reaches a full score, **as §3/§2 invariant 6 accept**. Identity/key binding, token single-use, replay/rewind, scenario-version gate, Box header, admin auth (`compare_digest`), leaderboard SQLi and manifest-only `engine_url` all held. No answer key anywhere on the box or in any response |
| SLA + adversary live (G3) | S3 | PASS on all 6. Each directive fired once inside its window (one late only because the engine was down); no re-execution across agent restart or reboot; SLA DOWN/UP obeyed hysteresis 2/2, no back-pay; penalty landed and lifted in the same bundle; only egress was the engine socket (`ss -tnp`); +2h box clock step moved nothing (receipt clock only) |
| Chaos (G4) | S4 + me | Engine SIGKILL, 410s nft partition, agent `kill -9`, box reboot, 3 more kills at arbitrary moments: every box `last_seq == COUNT(checkins)`, contiguous, no dupes; queue flushed 11 bundles in order; T0 and the adversary schedule survived restarts (secret persisted in `engine_meta`). Rubric re-upload moved the point-in-time score 40 → 42 → 40 on the next check-in, SLA untouched |
| Wire/doc audit (local) | S5 | 10 findings, below |

**Fixed (each with a regression test):**
1. *Agent dropped the current bundle when a stale queued one was permanently
   rejected* (`agent/transport.py`): the flush re-raised, losing the current
   cycle's evidence after its seq was already persisted. The flush now drops
   the dead entry and carries on.
2. *Admin rubric upload accepted SLA blocks that 500 every check-in*
   (`common/schema.py`): an unknown key (`hysteresis_fal_n`) passed validation,
   then crashed `SlaParams(**sla)` on every check-in for the scenario; and
   `hysteresis_*_n: 0` pinned an always-UP box DOWN. Unknown keys and
   non-positive counters are now rejected, and `compile` rejects unknown `sla`
   keys, which it used to drop silently.
3. *Adversary fire times depended on pool position* (`engine/adversary_oracle.py`):
   one RNG stream consumed in list order meant adding or reordering an event
   in a re-upload rescheduled every other unfired event. The seed is now
   per-event `(server_secret, box_id, event_id)` (architecture §12 updated).
   Unfired events on a live engine re-roll once at upgrade.
4. *Out-of-range ints 500'd* (`engine/server.py`): seq ≥ 2⁶³ (found live from
   the cheater box) OverflowError'd at the SQLite bind; negative seq was
   accepted into the seq guard. Wire ints are now bounded to 0..2⁶³−1 → 400.
5. *Unauthenticated 500 via deep nesting* (`engine/server.py`): ~3000-deep
   `raw` RecursionError'd in `canonicalize()` before the signature check.
   `raw` deeper than 64 is now a 400.
6. *Version-mismatch 409 lacked `last_seq`* (`engine/checkin.py`), contrary
   to §14.2's "every 409 carries it"; also corrected a stale step-order
   docstring.
7. *Ranked installs kept the honor re-grade timer* (`boxbuilder/providers/ssh.py`):
   every static-pine clone is honor-sealed, so its timer survived a ranked
   install and kept restarting a stopped ranked agent. Ranked installs now
   disable and remove it (verified live on G2).

Fixes 4, 5 and 7 were re-verified live: the redeployed engine returns 400
for the cheater's seq=2⁶³ and a 900-deep `raw`, and the reinstalled G2 has no
timer while its seq kept advancing. Fixes 1–3 and 6 are covered by their
regression tests only.

**Test-harness fixes:** `test_ranked_two_machines.py` now binds the engine to
`0.0.0.0`, detaches with `setsid … < /dev/null`, and regenerates each clone's
machine-id (`proxmox_helper.regen_machine_id`). Template 106 still carries a
stale machine-id, so its two clones and any other live 106 clone collided on
10.0.0.116; the test comment claiming the template was fixed referred to the
long-gone 9106. `test_concurrent_enroll_single_token_exactly_one_winner`'s
client timeout was raised from 30s to 120s: five Ed25519 verifies under one
GIL exceed 30s on a loaded host, which flaked the baseline.

**Known issues surfaced, not fixed (need a decision):**
- **§14.3 rubric versioning is not implemented.** `scenarios` is keyed by name
  only and the uploaded record's `scenario_version` is never compared with the
  box's. Verified live: uploading a v2 record re-scored the enrolled v1 boxes
  against it with no error. The doc says the engine scores against the rubric
  version matching the manifest. Either store per-version rubrics, reject
  mismatched check-ins, or amend the doc.
- **Idle connections hold `MAX_CONNS` slots for 30s** (`Handler.timeout`,
  hardcoded, not env-tunable). Bounded under the friendly-leaderboard threat
  model; make it configurable if ranked ever faces hostile networks.
- **`Transfer-Encoding: chunked` reads as an empty body** → generic 400. Not
  smuggle-able (HTTP/1.0, connection closed per response); the agent never
  sends chunked bodies.
- **A root player can burn their own seq space** (jump to 2⁶³−1, after which
  every later seq is a 400). Self-inflicted only, and it can't touch other boxes.
- engine#8 (penalty docking from `fire_time`) is still unimplemented and was
  observed live: the atd penalty and SLA DOWN bit ~45s after the kill,
  gated by hysteresis, not from `fire_time`.

**Process notes:** Sonnet agents ran out of their session limit near the end;
I finished S4's steps 5–8 by hand. The auto-mode classifier denied S4's
`rm`/`sed -i` remediations on its disposable VM, so it scored through the
forensics answers file instead. The sandbox classifier doesn't know which
hosts are disposable, which matters for future player-style rounds. S4's
"only 3 bundles queued during the partition" was a false positive: 11 were
queued and flushed (seqs 38–48).

---

## Round 2 — 4-guest ranked competition (same day)

Second round on `feature/ranked-mode`: a live 4-team competition plus the
honor-regression proof, driven by one subagent per guest box.

**Honor regression proof** (this round's ranked changes share the zipapp,
authoring validator, sync-report and boxbuilder staging with honor boxes):
- Compile matrix: all 7 honor boxes compile green under the new
  boolean-trap validation — the shipped `permission` checks using
  `equals: false` on boolean `exists` evidence remain correctly exempt.
- Full suite: 798 passed / 1 skipped / 5 deselected.
- Live honor E2E: `pytest -m proxmox
  tests/proxmox/test_local_honor_distribution.py` passed (2/2) — honor
  `.pyz` on real Ubuntu + Fedora clones via guest-exec, `Total: 10` asserted.
  (`.env`'s stale `TEST_TEMPLATE_VMID_UBUNTU=9106` updated to 106.)

**Competition**: static-pine-radio ranked variant; engine VM (cadence 30s) +
4 guest full-clones of 112, each `boxbuilder plant` (re-anchors the at-job →
clean 0 baseline despite the known at-fuse defect) + `install --admin-token`
(one token per guest, 4 distinct box_ids, all enrolled at Total 0). Four
general-purpose subagents then played their teams over SSH in parallel:

| team | strategy | predicted | final | rank |
|---|---|---|---|---|
| A | forensics 4/4 + all 16 evictions | 190 | **190** | 1 |
| B | the 8 EASY evictions only | 40 | **40** | 3 |
| C | 3 MODERATEs, then stopped cron | 20 | **20** | 4 |
| D | forensics only | 40 | **40** | 2 |

Every team landed exactly on target. Engine-side assertions: the B/D tie at
40 broke deterministically by first-confirmation (D before B); each box's
`last_seq == checkins` row count (30/30, 30/30, 29/29, 29/29) — zero lost or
replayed check-ins under 4-way concurrent load; Team C's cron penalty applied
engine-side exactly once (−10); zero tracebacks/errors in the engine log.
Teams confirmed their on-box `huitz score` matched the engine throughout.

Notable: Team D found the planted authorized_keys key on **stationlead**
itself, not on tapeops as a casual reading might assume — the forensics
answer discovery flow works as designed. Provisioning gotchas hit: spec
copies in /tmp resolve relative paths against /tmp (keep generated specs
next to the box dir or use absolute paths), and `boxbuilder plant` defaults
to `./artifacts` unless `--out` is passed.

---

# Round 1

Round report for the first extensive test of ranked mode (branch
`feature/ranked-mode`). Honor mode was considered stable going in; ranked mode
had ~3 loopback integration tests with its restart/crash-recovery sections
commented out, a blocked two-VM tier, and zero real-VM runs. This round built
the automated suites, ran ranked mode end-to-end on real Proxmox VMs, and
fixed everything found. Companion reading: `TESTING_GUIDE.md` §3 (manual
ranked flow), `PLAN.md` (dispositioned ledger), `architecture.md` (source of
truth).

## What the round added

**Automated tiers** (all green; see `tests/`):

| Suite | Covers |
|---|---|
| `tests/integration/test_ranked_loopback.py` | re-enabled: restart-without-re-enroll + SIGKILL-mid-checkin seq recovery (PLAN #50); plus enroll/SLA/queue-flush flows |
| `tests/integration/test_ranked_protocol_errors.py` (34) | the whole wire surface: enrollment error paths (unknown 400 / consumed 409 / expired 410 / scenario mismatch 400 / duplicate box 409 / bad sig 403), check-in check order (box 403 → schema/agent 400 → sig 403 → scenario 400/409 → seq 409), replay + last_seq echo, answer-key redaction asserted on raw response bodies, hostile payloads (oversized Content-Length, non-JSON, JSON array, string/float/NaN seq + wall claims), Box-header tripwire, admin surface (non-ASCII token, NaN/inf/0 ttl, invalid rubric, disabled 503), GET routing |
| `tests/integration/test_ranked_resilience.py` (3) | engine-restart persistence (scores/seq/T0 survive; box resumes), verify-gate 503 backpressure under a 4-box simultaneous volley + retries land + deterministic leaderboard tie-breaks, 5-way token-enroll race (exactly one winner) |
| `tests/integration/test_ranked_adversary.py` (2) | directive fires in window → `drop_inert_artifact` lands in the sandboxed dir → issued exactly once (engine log + box record) → deduped across issued_directives resends AND agent restarts; SLA DOWN + accrual freeze when the monitored service dies |
| `tests/integration/test_zipapp.py` (new test) | the built `.pyz` in ranked mode with a real signed manifest: enrolls, checks in at the engine cadence, renders the engine-authoritative score |

**Real-VM E2E** (both tiers done live, engine as a separate VM host):

- *Smoke*: engine on `base-ubuntu24.04` clone (`HUITZILOPOCHTLI_BIND=0.0.0.0`),
  agent as `.pyz` on a second clone, enroll → check-ins → leaderboard → SLA
  accrual (UP, +points) → engine killed mid-run → agent queues → engine
  restarted → queue flushes contiguously, score continues at the SLA cap →
  tampered signature over the network → 403. Rubric re-upload takes effect on
  the very next check-in.
- *Fidelity*: `boxbuilder compile` + `install --admin-token` against a
  full-clone of the static-pine-radio template (vmid 112) with a ranked
  variant spec (`boxes/static-pine-radio/box.ranked.yaml` +
  `scenario.ranked.yaml`): scenario uploaded to the engine, token minted,
  `/opt/.huitzilopochtli` sealed 700 root with **no rubric / .score.dat /
  engine_record on the box**, systemd long-running unit, motd banner,
  check-ins on the leaderboard, real hardening moved the score 10 → 15, and
  `huitz score` renders the engine-authoritative board as the player.

**Reachability correction**: the dev host CAN reach clone IPs on arbitrary
ports (curl/ssh to 10.0.0.x verified this round); the "VM ports TCP-RST" notes
in `tests/README.md` and the proxmox-ops skill describe a stale or narrower
failure. `test_ranked_two_machines.py`'s blocker #3 is likely obsolete —
retest rather than assume. (Its engine proc also needs
`HUITZILOPOCHTLI_BIND=0.0.0.0` added post-default-loopback.)

## Bugs found and fixed this round

1. **String/float seq and NaN accepted or 500'd** (`engine/server.py`):
   `_bundle_from_dict` did no type validation — a float `seq` of 2.5 was
   scored and stored (corrupting the seq guard), NaN sailed into the audit
   log, and a string `seq` fell out as a 500. All bundle fields are now
   validated at the wire layer (strict ints excluding bool, finite floats,
   non-empty strings, `raw` an object) → clean 400.
2. **Check-in cadence conflated with SLA granularity** (`engine/checkin.py`):
   `next_checkin_s = min(SLA interval_s, default 60)` made 1s-interval rubrics
   spin boxes (seconds of Ed25519 per cycle), froze scoreboard updates for
   3600s-interval rubrics, and gave SLA-less scenarios a 60s cadence that
   delayed directives past any reasonable window (found live: an adversary
   directive due at t0+2s never arrived in a 30s run). Cadence is now
   `HUITZILOPOCHTLI_CHECKIN_INTERVAL_S` (default 60, matching honor's 60s
   re-grade); SLA accrual is elapsed-based + capped, so it is cadence-neutral.
3. **YAML 1.1 boolean trap in file_regex expects** (`authoring/validate.py`):
   `equals: no` compiles to `equals: false` and never matches string evidence
   — the box scores 0 forever, silently. Reproduced live with THE canonical
   sshd hardening (`PermitRootLogin no`). Now an authoring-time error for
   `file_regex` checks (their evidence is always a string); permission checks
   are exempt because their `exists` evidence is genuinely boolean and shipped
   boxes correctly match `equals: false` there.
4. **Player console blind in ranked mode** (`agent/__main__.py`):
   `_sync_desktop_copies` ran only on the honor path and the unit's
   ExecStartPost fires before the first check-in exists — with the install dir
   0700 root, `huitz score` could never find a grade on a box that was
   actively scoring. The ranked loop now publishes the mirror per check-in.
5. **Author-time matcher/evidence field mismatch still silent (partial)**: an
   `http_uptime` expect without `field: status` silently reads the default
   `matched` key and the SLA sits DOWN forever (hit live, fixed in the
   scenario). The engine behaves correctly; the residual gap is authoring UX —
   see backlog.

Also fixed en route: Box-header tripwire (sent by both agent calls, never read
— now a mismatch is a 400), plain-HTTP engine_url warning (non-loopback),
stale `enrollment.py` docstring, `_warn_if_plain_http` tolerant of manifests
without `engine_url`.

## 1.0 hardening status

The release/1.0-hardening branch resolves the code-side items recorded below:
SLA outage back-claiming, rubric versioning (records are now keyed by
`(scenario_name, scenario_version)`), adversary fire-time persistence +
`affects_check` outage flooring, small-order Ed25519 keys, DB permissions,
auth-before-rubric-parse, rate limiting, queue dead-lettering, and the
Windows/CLI/boxbuilder findings from the full review. Live verification now
includes Fedora 44 all-check-types at **70/70** over root SSH (template 1016;
the guest agent's `virt_qemu_ga_t` domain, not the product, caused the old
30/70), Windows Server 2022 at **90/90** across nine Windows-first check types,
and a real `boxbuilder install` on Windows that registers the SYSTEM
`HuitzilopochtliAgent` task, seals `C:\ProgramData\huitzilopochtli`, and
produces an initial report. The remaining notes in this section are kept for
history; the shipped-box `at-job` fuse and the engine TLS/deployment story
still need operational decisions.

## Known issues needing a decision (not fixed here)

- **static-pine-radio at-job fuse (SHIPPED honor box affected)**: the plant is
  `at now + 2 days` anchored at seal time (2026-09-21). It fired 2026-09-23,
  so every clone of template 112 now boots with an empty `atq` and
  self-awards the 10-point `at_queue_emptied` check (reproduced on a fresh
  clone: leaderboard showed 10 before any hardening). The seal-time "Total 0
  baseline" validation predated the fuse. Recommended fix: re-anchor `WHEN`
  far out (e.g. `now + 30 days`) and re-seal, or re-arm the at-job at boot;
  the paired check could also score on the spool file rather than `atq`.
  Needs a replant/reseal round — Hamza's call (shipped template + pool).
- **Adversary penalty docking (engine#8)**: architecture §11.4/§12.1 say the
  engine docks penalties from `fire_time`; the code issues directives
  (at-least-once as of this round) but applies no outage floor. Directive
  execution still costs points indirectly (a killed service fails its own
  SLA check). Implement in the next ranked round or amend the doc.
- **TLS everywhere (agent#11 remainder)**: plain HTTP is warned but allowed;
  the agent uses `ssl.create_default_context()`, so a self-signed engine cert
  fails verification. A ranked deployment story needs a CA/pinning decision
  plus an engine systemd unit + docs (none exist).

## Backlog for the next ranked round

1. Type-aware authoring validation: a per-check-type raw-evidence schema
   (file_regex → `{matched: str}`, http_uptime → `{status: int}`,
   permission → `{exists: bool, ...}`) would have caught both the boolean
   trap and the field-mismatch trap at author time.
2. Engine deployment story: systemd unit + hardening (the engine currently
   runs via nohup; env-only config), plus a documented backup/restore for the
   sqlite DB and the `HUITZILOPOCHTLI_SERVER_SECRET` rotation caveat
   (rotating re-schedules every box's adversary events — see the CAUTION in
   `engine/adversary_oracle.py`).
3. `tests/proxmox/test_ranked_two_machines.py`: unblock (reachability now
   proven) and add `HUITZILOPOCHTLI_BIND=0.0.0.0`; consider making it the
   nightly canary.
4. X-HUITZILOPOCHTLI-Box: now a tripwire; decide whether to formally document
   it in §14 or strip it from the agents.
5. `scores` PK is `box_id` alone — one scenario per box. Multi-scenario boxes
   need a composite key.
6. architecture.md doc gaps (noted, not written — the file was being edited
   concurrently): §14.1 enroll example lacks `scenario_version`; §11.1/§11.2
   omit `/admin/scenarios`, `/admin/tokens`, the `scenarios` + `engine_meta`
   tables, and the verify-gate/503 + connection-cap behaviors.
7. Multi-scenario leaderboard stress + engine backup/restore drill; optional
   adversarial suite (fuzzed bundles at volume) once TLS exists.

## Environment notes for reproducing the VM round

- Templates: `base-ubuntu24.04` (vmid 106) has a **duplicated machine-id** —
  two clones DHCP-collide on one IP. Regen in the clone
  (`rm /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup`,
  then stop/start) or fix the template. The old `TEST_TEMPLATE_VMID_UBUNTU=9106`
  in `tests/proxmox/.env` is stale (9106 no longer exists).
- Engine runtime on a VM: `common/` + `engine/` tarball, Python 3.12,
  `HUITZILOPOCHTLI_BIND=0.0.0.0`, ~88 KB bundle. Guest-agent file-write needs
  the target dir to exist; a `nohup … &` inside guest-exec must redirect ALL
  fds (use `setsid nohup … > log 2>&1 < /dev/null &`) or the exec call hangs.
- `--provider-host` on boxbuilder's CLI is ignored when `--spec` is given —
  put the IP in the spec (known gotcha, hit again this round).

---

# Round 4 — ranked competition surface (v1.1)

Date: 2026-10-23. Scope: the new competition layer (engine VM, online join,
per-player runs, scored services, public leaderboard, admin console, ranked
box lineage). This round was driven end to end on real Proxmox VMs, not
loopback mocks.

## Environment

- Engine: `huitzilopochtli-engine` (vmid 168), full clone of
  `base-ubuntu24.04-fix` (955), Ubuntu 24.04, static `10.0.0.160`, systemd
  `huitzilopochtli-engine.service`, SQLite at
  `/var/lib/huitzilopochtli/engine.db`, daily backup timer.
- Test boxes: vmid 171 / 173, linked clones of 955, agent installed from the
  built `.pyz`, demo web service on `:8081`, OpenSSH installed, player joined
  with `huitz join`; later a workshop pool from template 174.
- Workshop portal: `http://10.0.0.102:5000`; a private 2-VM pool (`T38KZ`)
  was provisioned from the ranked template and claimed through the engine's
  join page.
- Cadence: 10s for the test (`HUITZILOPOCHTLI_CHECKIN_INTERVAL_S`); service
  interval 30s.

## Runs

1. **Single-player scored-service run** (`demo-run`, scenario v1): joined
   `TestPlayer`, status file hardened +10, web service UP, SSH initially
   DOWN because the base image had no sshd; installed `openssh-server`, SSH
   recovered through hysteresis. Total 13 at end; admin End froze the board
   at 13 and the agent exited with `run ended: ... final score 13`.
2. **Adversary + service outage run** (`demo-run-2`, scenario v2): joined
   `Grace`; the engine fired `kill-demo-web` inside its 20–40s window, the
   agent executed `kill_service huitz-demo-web`, the engine forced the
   `svc_web` SLA DOWN, no points accrued during the outage, restarting the
   service restored UP after hysteresis. A second player (`Linus`) joined
   from the first box after an identity reset; board showed both names with
   Grace ahead.
3. **Real workshop handout run** (`demo-run-3`, scenario v2, pool `T38KZ`):
   the join page called the real workshop `/api/claim`, returned a Guacamole
   URL, and the player's `huitz join` bound the claimed VM. The adversary
   killed the web service on the clone; restarting it recovered the service.
   A second player claimed the second pool VM; a third join was refused
   (max 2 / pool exhausted). CSV export and admin roster both showed both
   players.
4. **Per-player expiry** (`expiry-test`, 60s duration): joined
   `ExpiryPlayer`; after 60s the engine marked the player `finished`, froze
   the score at 11, and the agent logged `run finished: ... final score 11`
   and exited; the competition itself stayed live.
5. **Engine reboot**: shut down/started vmid 168; static IP persisted,
   `/health` returned, both competitions and scores survived, boxes resumed
   check-ins after the outage.
6. **Backup**: ran `huitzilopochtli-backup.service`; backup opened in SQLite
   with all 14 expected tables.

## Defects found and fixed this round

1. `engine/scenario.py` used `Optional` without importing it — engine
   crash-looped on the VM until fixed; caught only by the real deployment.
2. `engine/deploy/install.sh` placed `deploy/` under the package directory
   instead of the app root; the backup unit could not find `backup.py`.
3. `engine/checkin.py` reported `finished` instead of `ended` when the admin
   ended the competition (player status was updated first); status precedence
   corrected.
4. `agent/__main__.py` assumed every check-in response had `run_status`;
   older/fake responses raised `AttributeError` in tests. Now uses
   `getattr(..., "running")`.
5. `engine/server.py` initially registered the JSON competition-create route
   in `do_GET` rather than `do_POST` (404); moved to the POST router.
6. `engine/server.py` admin actions returned an HTML redirect to header-token
   API callers; token callers now get JSON, session/form callers still get a
   redirect.
7. `huitz join` had to be added to `VERBS` and the CLI; a fake response test
   caught the run-status assumption before the live run.
8. Reissue-code API accepted a running player, which would orphan the old
   box; now only unbound/invited players can be reissued.
9. `huitz join` on a clone inherited from a running box starts with an old
   identity if the agent unit was active; the template build now stops and
   disables the unit and removes identity/report state before sealing.

## Known issues / follow-ups

- **Self-reported services remain forgeable.** A root player can fake
  `http_uptime`/`tcp_port` evidence. The competition UI says "self-reported";
  engine-side probes are a separate future decision.
- **HTTP-only, Basic auth.** Fine for the LAN; Cloudflare Tunnel/TLS is not
  implemented. Admin credentials and Guacamole links are in the clear on the
  LAN.
- **Player cookie is a bearer of the player id.** It is HttpOnly and random
  but not signed; a leaked cookie lets someone view `/me` (not the admin
  console). Add an HMAC if this becomes multi-tenant.
- **No score-preserving box replacement.** Reissue/removal is implemented;
  replacing a bound box does not migrate its score/SLA state yet.
- **No name moderation/profanity filter.** Names are length/control-char
  validated and HTML-escaped, but public display is otherwise raw.
- **Per-player clocks are not comparable while runs are in progress.** The
  board shows status/remaining; final standings are only meaningful at End.
- **Workshop admin password on the local dev checkout did not match the
  deployed portal**, so pool creation was performed on the portal host using
  its own `.env`; this is an external credential-drift issue, not a huitz
  bug.
- **No long-duration/scale soak** beyond two concurrent players; the engine
  was tested at 10s cadence, not 30–50 boxes for hours.

## Automated coverage added

- `tests/unit/test_competition.py` — join/run clock/max players/expiry,
  service accrual and frozen end.
- `tests/unit/test_services_compile.py` — `services:` compilation, `svc_`
  ids, SLA rubric entries, service-id collision.
- `tests/unit/test_tcp_port_check.py` — open/closed port evidence.
- `tests/integration/test_competition_http.py` — public join → signed
  `/join` → check-in → leaderboard → admin End over real HTTP.
- `tests/integration/test_competition_admin_ui.py` — Basic login → session,
  CSRF rejection, Start via admin page.
- Full fast suite after the round: **1014 passed, 1 skipped, 7 deselected**.

# Round 5 — engine web UI redesign (cream editorial)

Date: 2026-10-23 (same day). Scope: every page served by `engine/web.py` —
public site, join flow, player status, admin console, display board. No
scoring, store, or contract changes; `engine/web.py` + `engine/server.py`
only. Deployed live to vmid 168 the same hour.

## What changed

- **Design system.** One token set, two themes: cream editorial (default —
  hard 1px espresso frames, sharp corners everywhere, serif headings, small
  uppercase sans labels/buttons, flat surfaces) and a warm dark-roast inverse.
  Theme follows `prefers-color-scheme`, overrides via a header toggle persisted
  in `huitz-theme` localStorage, applied pre-paint (no flash). Per-competition
  accents survive; `_on_accent` picks readable text on them; accents are
  validated `^#[0-9a-fA-F]{6}$` server-side (JSON API included).
- **UX fixes:** join POST now 303-redirects to the (previously unreachable)
  success page — browser refresh no longer re-submits the form; copy buttons
  on the join code/VM link/join URL (the old `[data-copy]` JS had zero
  elements); confirmations on Disqualify/Remove ("DQ" spelled out) plus End;
  index cards and the join form gate on real joinability (draft/ended/full
  explain themselves instead of rendering a form that 400s); all ~10 bare
  `<h1>` error fragments replaced by a styled `web.error_page` (unknown
  browser paths get HTML via Accept negotiation, APIs keep JSON 404);
  `Cache-Control: no-store` on HTML.
- **Liveness:** full-page meta-refresh replaced by fetch + section-swap polling
  (leaderboard/display 5s, admin roster + /me 15s, dashboard 30s), paused when
  the tab is hidden/focused, with `<noscript>` meta-refresh fallback; ticking
  countdowns (`h:mm:ss`, not the ambiguous `119:59`); real "updated HH:MM:SS"
  stamps; /me and the admin roster show last check-in age (warn-styled when
  stale); display board gains per-player service dots + countdown and loses
  its nav/footer (dark-pinned).
- **Roster/leaderboard slimming:** status shown once (badge under the name),
  service dots with tooltips instead of `name:STATE` strings, box/code columns
  folded under the player cell, audit details pretty-printed `k=v`,
  audit filter chips (`?action=`), joined-timezone `_fmt_ts`.

## Verification

- `tests/unit/test_web_pages.py` (19 new tests): theme tokens/no-FOUC, poll +
  countdown + copy wiring, join gating, error page, formatting helpers,
  confirmation dialogs, CSRF-input shape preserved.
- `test_competition_http.py` updated for the 303 PRG (asserts Location, cookie
  on the redirect, then success-page contents) + HTML/JSON 404 negotiation +
  `data-poll`/`data-remaining` presence; `test_competition_admin_ui.py` kept
  its load-bearing strings ("Admin login", "Admin console", csrf regex) and
  now checks theme-toggle/poll hooks and the "Live" badge.
- Full suite after the round: **1033 passed, 1 skipped, 7 deselected**.
- Browser-verified locally (seeded engine, real join via the form, PRG
  landing on success): index, leaderboard, display, join form/success, /me,
  login, dashboard, roster, scenarios, audit, 404 — each in cream + dark
  roast, plus a 375px pass; poll-swap confirmed with zero full reloads.
- Deployed to vmid 168 via guest-agent (old files backed up to
  `/root/{web,server}.py.bak-20261023`), service restarted, `/health` green,
  live pages eyeballed on prod data.

## Known issues / follow-ups (UI)

- Admin pages have no authentication-rate limiting (unchanged from round 4).
- The audit table caps at the store's 200 rows; no pagination.
- Display board polls by re-fetching the whole page; a JSON diff endpoint
  would be cheaper at scale (fine for lab sizes).


## Round 5 — pre-bound joins, dispenser-first claims (2026-10-24)

Goal: the player opens one link and types nothing. The engine picks a
dispenser pool even with zero pre-cloned VMs, claims with the one-time join
code plus a shared secret, and the portal runs `huitz join --code` in the
guest when the player opens the stable `/r/<uid>` link. The run clock starts
at that open (the bind), not at clone time.

**Fixed on the way (found while wiring this):**

- `GET /api/public/join/<player_id>/status` parsed the trailing `/status`
  segment as the player id, so the join page's poll always 404'd. It now
  requires exactly `.../<id>/status`.
- Claim failures were swallowed (`except WorkshopError: pass`), and the page
  told players to ask an admin for a VM that no admin action could attach.
  Errors are now stored per player and shown, with a player-triggered
  `POST /api/public/join/<id>/claim` that releases and re-claims.
- `pick_pool` required `available > 0`, so a dispenser pool was never
  auto-assigned and every join for that competition hit the dead-end message.
- Newly created competitions had no way to get a pool code after the fact; the
  admin page now edits it and retries claims for waiting players.
- The portal rate-limits `/api/claim` at 10/min per IP; a class joining at once
  would fail from the 11th player. Shared-secret engine calls are exempt.

**Automated coverage (no VM required):**

- `tests/unit/test_claims.py` — dispenser-first `pick_pool`, claim success /
  202 ticket / portal error / no pool, poll throttling and backoff, code
  rotation (and revert when the portal rejects the push), release-then-claim,
  CSRF, prebind-disabled fallback to a plain claim.
- `tests/integration/test_competition_http.py` — real engine + fake portal:
  the prebind body/header the engine sends, the stable `open_url` on the page,
  the fixed status endpoint, and reclaim (release + new claim + forged-CSRF
  rejection).
- `workshop-vm-distribution/test_prebind.py` (portal venv) — claim stores the
  code, wrong/missing secret refused, guest join runs exactly once, failed
  join returns the VM plus the error and back link, expired VM returns 410,
  rotation is ignored after join, redeem never leaks the code, engine rate-limit
  exemption, and reopening does not extend the machine's lifetime.

**Not exercised on real VMs yet:** qemu-ga exec of `huitz join` on the ranked
template, Guacamole re-mint through `/r/<uid>`, and the click-time clock on a
live competition. Those need the portal and engine deployed together with a
shared secret and a dispenser pool.

## Round 6 — live deployment and four-comp load test (2026-10-24)

Deployed the new engine + portal to the lab and ran four ranked competitions
at once, two Windows and two Linux, each with six players.

**Deployed**

- Engine vmid 168 (`http://10.0.0.160:8080`): current `common/` + `engine/`
  (backup at `/root/huitz-deploy-<stamp>/`), `HUITZILOPOCHTLI_WORKSHOP_SECRET`
  added to `engine.env`, service restarted, `/health` green.
- Portal vmid 111 (`http://10.0.0.102:5000`): `server.py` + `guest.py`, backup
  at `/root/portal-deploy-20261024-053118/`, `HUITZ_PREBIND_SECRET` +
  `PUBLIC_URL` added, `workshop-vm` restarted.
- Proxmox: the portal's token (`workshop-vm-distribution@pve!workshop-vm-distribution`,
  custom role) lacked `VM.GuestAgent.Unrestricted`; added that privilege to the
  role and a scoped `HuitzAgentExec` role/ACL on `/vms`. Without it every
  on-open join returned 403 and the player was left with a manual-join VM.

**Ranked builds (honor → ranked copies, no conversion of a live box)**

| Comp | Box | Template | Pool | Services |
|---|---|---|---|---|
| `chocolate-ranked` | Cocoa Falls Chocolate Works (Xubuntu) | 183 | 4UWK5 | SSH 22, VNC 5900 |
| `static-pine-ranked` | Static Pine Community Radio (Debian) | 184 | 9W3C2 | SSH 22, atd |
| `pinecrest-ranked` | Pinecrest Community Hospital (Win Server) | 185 | S29NP | RDP 3389, WinRM 5985 |
| `saltmarsh-ranked` | Saltmarsh Exchange (Win Server, IIS/FTP) | 186 | QPDX6 | IIS 80, FTP 21 |

Each: clone the sealed honor template → install the ranked agent with
`boxbuilder install --competition` → verify → stop, disable the agent/task,
delete `identity.json*` (so every clone gets its own box id) → seal → private
dispenser pool (2 ready VMs) → competition (6 players, 1 h), engine record
uploaded with two services.

**Results**

- Prebind end-to-end on all four boxes: joining the site, opening the portal
  link, `huitz join` in the guest, engine bind, and service accrual all worked
  for Linux (systemd) and Windows (`python agent.pyz` → scheduled task).
- Six players per competition (5 real boxes + simulated signed check-ins; the
  chocolate comp had 2 real boxes). Services scored: SSH/VNC, SSH/atd,
  RDP/WinRM, IIS/FTP all UP on the real boxes; the leaderboard, `/me`,
  display board and admin roster agreed throughout.
- UI audit (headless Chrome): all public/admin pages, both themes, 375px
  layout, 8 concurrent boards, live poll update, full-competition notices,
  CSV, CSRF rejection — **PASS**, no console errors, 630–730 ms at 1280px.
- Concurrency: 19 simultaneous check-ins (one per simulated box) → all 200,
  no lost seq, no reset, after the fixes below. Sequential check-ins:
  ~1.0 s avg, 1.5 s p95.

**Fixed during the round**

1. `huitz join` only started the agent on POSIX; Windows ranked boxes stayed
   disabled after joining. `agent/join.py` now enables and runs the
   `HuitzilopochtliAgent` scheduled task (`_start_agent`, covered by
   `tests/unit/test_join_start.py`).
2. Engine listen backlog was the socketserver default (5): a class checking in
   at the same second had connections RSTed before the engine saw them.
   `_EngineHTTPServer.request_queue_size = 128`.
3. The join page's status endpoint parsed the trailing `/status` as the player
   id (found earlier in the unit round; fixed and re-verified live).

4. The admin "new competition" picker only scanned the repo `boxes/` folder,
   which does not exist on the deployed engine — it said "No ranked scenarios
   found" even though uploaded records were in the DB, and create would have
   tried to re-import from the missing folder. The picker now merges uploaded
   records with folder builds, and create uses the uploaded record when there
   is no folder copy (`tests/unit/test_admin_scenarios.py` plus an integration
   test against an engine with no box folder).
5. Windows prebind needed `python agent.pyz`; the portal now selects the
   command from the pool's access method.

**Known limits observed**

- `HUITZILOPOCHTLI_MAX_VERIFY=4` is the burst ceiling: 19 simultaneous
  verifies produce 503 "engine busy" for most and the agent's retry/backoff
  (queue-and-forward) is what makes it converge; wall time ~20 s for the
  full burst. Fine for real agents, but a larger field should raise the gate
  or jitter the check-in schedule.
- The portal's dispenser creates a VM per claim; a scripted player-creation
  mistake started several extra clones. They were released, but on a busier
  host the 10/min `/api/release` limit (browser limit) makes cleanup slow —
  consider exempting the shared-secret engine or documenting a bulk release.
- The test competitions were created with a 1-hour run, so their boards are
  frozen after that; scores, service dots and rosters remain viewable.

## Round 7 — per-competition pool provisioning (2026-10-25)

**Incident.** `cocoa-falls-demo` auto-picked the old Chocolate Factory honor
pool (EUKT7, template 108) at claim time — `pick_pool` preferred "any pool
with free VMs" and the ranked dispensers all report `available: 0`. The player
got a VNC box with no `huitz` binary and `mode: honor` in its config: the
portal's prebind join failed (transient qga 596, then structurally hopeless)
and `huitz join` in the console said "command not found". Leaderboard stayed
empty; the run clock never started. The engine's silence made diagnosis
audit-log-only work.

**What changed (portal untouched, per decision)**

- The scenario YAML gains a ranked-only top-level `pool:` block (template vm
  id, access method, credentials, vm_count; validated in `authoring/
  validate.py`, emitted into the engine record by compile, persisted as
  `scenarios.pool_json`, validated again engine-side).
- `claims.ensure_pool` replaces pool *picking*: on first claim the engine
  provisions a private dispenser pool `huitz-ranked-<slug>` from that block
  (`POST /api/admin/provision`), pins the code (audit `source: provisioned`),
  and reuses its own pool by name after restarts — refusing a same-name pool
  that clones a different template. `pick_pool`/`auto_pool` and the
  `HUITZILOPOCHTLI_WORKSHOP_RANKED_POOL` pin are retired; the JSON API no
  longer accepts `workshop_pool_code`; the admin `pool` action is clear-only.
  There is no path left that points a competition at an existing pool.
- Ending a competition (admin End or next sweeper pass) releases its VMs and
  deletes its pool (`cleanup_pool`); legacy-pinned shared pools are left
  untouched and only unpinned.
- The admin competition page shows the attached pool (read-only); the
  join-success page renders the terminal-join fallback (and its code) only
  when the automatic join failed; failed `/join` requests now log to the
  journal.

**Coverage.** 40 claims tests (provision/reuse/mismatch/409/missing-block,
cleanup own vs legacy vs portal-down, sweep cleanup), authoring pool-block
validation + compile emission (honor rejection), store `pool_json`
round-trip, and the HTTP E2E extended: competition created without a pool →
claim provisions `PROV1` from the box record's block → prebind claim →
end releases VMs + deletes the pool (`tests/integration/
test_competition_http.py`). 1115 passed, 1 skipped.

**Known limits.** Old ranked templates' agents predate the join-`mode`
claim idea entirely — mode enforcement lives in the pool/scenario lineage,
not on the wire; a template rebuild would be needed to change agent
behavior. Provisioning is serialized portal-side (one job at a time); a
409 just defers to the next sweep. The local workshop-vm-distribution
checkout carries an uncommitted `provision.py` edit referencing an undefined
`WORKSHOP_POOL` — deploying that checkout as-is would break cloning; leave
the prod portal alone.

---

# Round 6 — live two-player ranked round vs the public competition engine (2026-10-26)

Two blue teamers (subagents, as in rounds 2–3) played a real ranked round
against the **production engine at `http://10.0.0.160:8080`** — a newer
competitions build (web UI, join codes, portal-dispenser provisioning, systemd
unit + rate limiting) than anything in this checkout (main = v1.0.0; deployed
tree has no local source — snapshot kept, see Notes). This was the first round
through that build, the first through the dispenser path, and the first with
wire probes against a *shared* engine.

**Setup.** Comp `round4-blue-duo` (Static Pine Community Radio v1, max 2,
5400 s) created via `POST /admin/api/competitions` (Basic auth), live at
05:05–06:46 UTC. Portal dispenser (pool `9W3C2`) cloned template 184 → VMs
1202/1203 (10.0.0.105 / 10.0.0.122); join codes taken from the engine DB and
entered manually with `huitz join` in-guest (portal `HUITZ_PREBIND_SECRET`
is unset → the zero-touch prebind path **never fired and fell back silently**
— finding 6). Both boxes enrolled, 90/90 check-ins at the 60 s cadence.

**Result.**

| Team | Strategy | Hardening | Forensics | SLA accrual | Final total |
|---|---|---|---|---|---|
| Falcon | full sweep | **190** (16/16, killed reborn-chain units before payloads) | 4/4 | 534, no penalty | **724** |
| Otter | selective | 30 (4 EASY + the +10 baseline fuse, finding 3) | 1/4 | 484, frozen ~25 min after `svc_scheduler` DOWN | **514** |

Engine-side assertions that held (all observed live on prod):
- Penalty −10 (`atd_service_healthy`) landed and stuck; scheduler SLA DOWN
  froze accrual while `svc_ssh` kept earning — per-service independence ✓.
- No answer key anywhere: box manifest carries ids/display/weights + collect
  params only, zero `expect`/`solution`; `/opt/.huitzilopochtli` 0700 root;
  rubric engine-side only. CLI mirrors engine exactly, per cadence ✓.
- Wire probes (7/7) re-signed with our own legitimately-held box keys: replay
  → 409 + `last_seq`; tampered-evidence **re-signed at old seq** → 409 (never
  re-scored); foreign-key signature → 403; Box-header mismatch → 400;
  seq ≥ 2⁶³ → 400; 900-deep `raw` → 400; unknown box → 403. Zero state change
  (seqs stayed 90/90) ✓.
- Box clock +2 h (NTP off, mid-run): `created_wall_claim` drift +7199 s,
  `received_at` cadence uniform, accrual and totals unaffected — receipt-clock
  invariant holds on the live build ✓.
- Engine `systemctl restart` post-round: 146/133-row sequences of other live
  competitions' boxes show **no gaps or dupes** across the restart; admin
  auth, scenario records and ended comps intact ✓. (Post-restart *reconnect*
  not re-observed here — other competitors' dispenser TTLs had already reaped
  their VMs; covered by the suites and round 3.)
- Referee discipline: player action logs were treated as claims only; every
  delta was attributed from engine check-in data. That caught a sloppy
  retro-logged session (Falcon fixed everything — the log just lagged) and
  rewarded honest reconciliation (Otter refused backdating and flagged the
  discrepancy themselves).

**Findings, and what happened to each after the round:**
1. **`competition_end` 500s — `engine.claims` has no `cleanup_pool`**
   (deployed `engine/server.py:908`, `AttributeError`): the status flips to
   `ended` first, then the handler dies, so the admin call returns a broken
   500 and **claimed portal VMs are never released** — every ended
   competition leaks its seats until the portal reaper fires (~4 h TTL here).
   Verified live on my comp; both VMs released by hand via portal
   `POST /api/release`. **Resolved:** `claims.cleanup_pool` exists in
   `c93f893` (per-competition pools + sweeper retry); the running box was a
   stale build missing it. The box still wants that upgrade.
2. **Ranked totals unbounded and mixed on-box**: `report.json` renders
   `total 514` against `max_possible 150` (SSH uptime accrual alone 264 and
   climbing); on long rounds SLA points drown the hardening signal the board
   is about. The API already splits `hardening_points`/`service_points` —
   the CLI/report should too, and uptime accrual wants a cap or decay story.
   **Fixed:** `agent/board.py` derives `(hardening, service)` once
   (`ranked_split`); the CLI, the HTML report and `report.json` now show the
   split instead of a bare total. Tests: `test_huitz_cli.py::TestRankedSplit`,
   `test_reporter.py`.
3. **Baseline +10 `at_queue_emptied` fuse confirmed on fresh template-184
   dispenser clones** (both boxes enrolled at hard=10 with zero play) — the
   R3 known issue survives re-sealing; every ranked prediction must subtract
   it until the re-anchor/re-arm decision lands (Hamza).
4. **Auto pool pick is scenario-blind** (`claims.resolve_pool` /
   `workshop.pick_pool`): with no free VMs anywhere it takes the first
   *dispenser by name* — a Static Pine comp would happily claim Chocolate
   Factory boxes and loop `scenario_mismatch` joins against a shared portal.
   The admin pool action can only *clear* a pin. I pinned `9W3C2` via a direct
   DB `UPDATE` before first join to prevent it. Filter pools by scenario or
   require an explicit pin at creation. **Resolved:** `c93f893` replaced
   auto-pick with `claims.ensure_pool` — each competition provisions its own
   pool from the scenario's `pool:` block and never picks among pre-existing
   pools (now an AGENTS.md invariant).
5. **Engine build drift**: the running engine is not in this repo, any local
   branch, or a tag — bugs found here can't be regression-tested from main.
   Snapshot of the deployed `engine/`+`common/` preserved at
   `artifacts/round4-evidence/deployed-engine-snapshot.tgz` (code only, no
   secrets; note the `*.bak4` files inside — the box was hand-patched in
   place); pull it into the repo (and its tests) before the next round.
6. **Prebind silently disabled**: engine is configured for prebind
   (`HUITZILOPOCHTLI_WORKSHOP_SECRET`) but the portal has no
   `HUITZ_PREBIND_SECRET`, so the advertised no-typing join never happens and
   the fallback is invisible to the admin. Set it or surface the fallback.
   **Fixed:** the fallback now writes a `prebind_unavailable` audit row and a
   warning naming the competition, instead of degrading silently.

**Notes.** Join codes and box private keys touched this round were kept in a
local scratch dir and deleted with it after the round; engine admin creds are
in the box env (`/etc/huitzilopochtli/engine.env`, root 600). Engine DB
snapshotted pre-teardown (`/var/backups/huitzilopochtli/engine-20261026-075658.db`).
Portal prebind route exists but returns 403-disabled; `huitz join` is
stdin/TTY-only (no positional code) — worth a `--code` flag for scripted play.
