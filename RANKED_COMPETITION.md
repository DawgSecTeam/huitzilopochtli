# Ranked competitions — operator runbook

How to put a ranked competition on the engine: upload a scenario, create and
start the competition, build the ranked template it hands out boxes from, then
end and release it. The engine contract is `architecture.md`; building and
sealing a box is `boxbuilder/README.md` + `boxbuilder/DEPLOY.md`.

Use placeholders, never committed values: `$HUITZILOPOCHTLI_ENGINE_URL`,
`$HUITZILOPOCHTLI_ADMIN_TOKEN`, `$HUITZILOPOCHTLI_WORKSHOP_URL`,
`$HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD`, `$HUITZILOPOCHTLI_WORKSHOP_SECRET`,
`<box>`, `<clone-address>`, `<template-vmid>`. The engine is HTTP unless
`$HUITZILOPOCHTLI_TLS_CERT`/`$HUITZILOPOCHTLI_TLS_KEY` are set; put TLS in
front. Admin auth is a header token or HTTP Basic; public pages are open.

## 1. Write and upload the scenario

One authored file per box: `boxes/<box>/scenario.yaml`. Its base content is
the **honor** box; an optional top-level `ranked:` block holds only what a
ranked build needs — `engine_url`, extra `checks`, scored `services`, the
`adversary` schedule, and the workshop `pool`:

```yaml
scenario:
  name: "Ranked Demo"
  version: 1
  mode: honor                 # default build target
  hosts: ["localhost"]

checks:
  - {id: banner, type: file_regex, category: vuln, max_points: 10,
     display: "Status file says hardened",
     collect: {path: /etc/huitz-demo-status, extract: '(hardened|vulnerable)'},
     expect: {equals: hardened, points: 10}}

ranked:
  engine_url: "http://127.0.0.1:8080"   # placeholder; overridden at build time
  services:
    - {id: web, display: "Demo web", type: http_uptime, interval_s: 30,
       collect: {url: "http://127.0.0.1:8081/health"},
       expect: {equals: 200, field: status},
       points_per_interval: 1, max_intervals_per_checkin: 3}
  adversary:
    events:
      - {id: kill-demo-web, action: kill_service, window_s: [20, 40],
         params: {service: "huitz-demo-web"}, affects_check: web}
```

- **`scenario.mode` is the default target.** `honor` builds the base as an
  honor box and, with a `ranked:` block, the same file as a ranked box under
  `--mode ranked`; `ranked` is ranked-only and refuses an honor build. There
  is no separate ranked fork file.
- **An honor build never reads `ranked:`**, so ranked checks, services,
  adversary, and pool cannot leak into an honor manifest or rubric.
- **Engine address:** `--engine-url` > `$HUITZILOPOCHTLI_ENGINE_URL` >
  `ranked.engine_url`. The committed loopback URL is the "not configured"
  placeholder; `install` warns when a build still uses it.
- **Scored services** compile to `svc_<id>` checks with SLA parameters; the
  box probes itself, so uptime is self-reported, not independent network
  verification.

Compile the record and upload it (`--no-bundle` needs neither nakon nor
vulndb; a scenario carrying a `pool:` block also needs the vars from §3.1):

```bash
export HUITZILOPOCHTLI_ENGINE_URL=https://<engine-host>
python3 -m boxbuilder compile --spec boxes/<box>/box.yaml --mode ranked \
  --no-bundle --out artifacts/<box>-ranked
curl -sS -X POST "$HUITZILOPOCHTLI_ENGINE_URL/admin/scenarios" \
  -H 'Content-Type: application/json' \
  -H "X-HUITZILOPOCHTLI-Admin-Token: $HUITZILOPOCHTLI_ADMIN_TOKEN" \
  --data-binary @artifacts/<box>-ranked/engine_record.json
```

The engine does not need the compiled record at all: it parses the committed
`boxes/<box>/scenario.yaml` files itself, and **the admin picker lists exactly
that folder** (`$HUITZILOPOCHTLI_BOXES_DIR`, default `<app dir>/boxes` — the
deployment bundle ships it). Each scenario appears once, at its current
authored version; versions are never shown in the UI. Running a competition
against anything but the current version is refused — when you bump
`scenario.version`, end and recreate (or rerun) competitions on the new
version; there is no backwards compatibility. `POST /admin/scenarios` still
exists for tooling, but an upload only seeds the scoring cache and never adds
a picker entry.

## 2. Create and start a competition

Admin console `/admin/competitions/new`, or `POST /admin/api/competitions`:

```bash
curl -sS -X POST "$HUITZILOPOCHTLI_ENGINE_URL/admin/api/competitions" \
  -H 'Content-Type: application/json' \
  -H "X-HUITZILOPOCHTLI-Admin-Token: $HUITZILOPOCHTLI_ADMIN_TOKEN" \
  -d '{"name": "Friday Night Ranked", "scenario_name": "Ranked Demo",
       "max_players": 32, "duration_s": 7200}'
```

`scenario_version` may be omitted — it defaults to the box folder's current
version for that scenario; an explicit older version is refused.

Fields: **name** (slug derived; the API also takes an explicit one — that is
`/c/<slug>`), **scenario**, **max players** (hard cap), **run duration** (each
clock starts at join; no pause), **accent**. There is **no pool field**:
the first claim provisions a private dispenser pool from the scenario's
`pool:` block (§3.1).

**Start** moves `draft → live` and opens joins; **Close joins** stops new
players without ending runs; **End** freezes every run and the board. A draft
can be **discarded** the same way (End on the draft page): it becomes ended and
the normal end cleanup runs, so an abandoned draft cannot strand its
pre-deployed pool. An ended competition can be **rerun** (fresh, same settings)
or **removed** — removal releases its VMs, cleans its pool, and deletes the
competition and its slots; boxes and scores remain as history.

**End also tears the pool down.** It releases claimed VMs, destroys the pool's
remaining pre-provisioned clones, and deletes the pool configuration. If the
portal is unreachable the pool pin is kept and the sweeper retries. Ending
seconds after the first claim is safe: the engine waits briefly for clones
that are still registering, then sweeps again after deleting the pool. If the
pool config is already gone, it still enumerates the portal's VMs by pool
code/student_id and destroys the clones; a DELETE 404 is success, and the pin
survives until a fresh listing shows zero VMs.

## 2.1 Running several competitions at once

Any number of competitions can be live on one engine. Each owns its own
players, clock, board, portal pool (`huitz-ranked-<slug>`), and teardown; the
engine serializes pool work **per competition**, not process-wide.

What to know before a day of back-to-back events:

- **Stagger the pre-deploys.** The portal accepts one provision job and one
  destroy job at a time. A second pre-deploy is queued (the admin page shows
  "Queued") and a second End waits for the running destroy job; neither fails,
  but both are slow. Warm the first pool, open its joins, then warm the next.
- **Avoid sibling slugs.** `demo` and `demo-2` are fine and isolated (teardown
  matches the exact pool code / anchored pool name), but a slug that is a
  prefix of another makes operator cross-checks harder for no benefit. Rerun
  derives `-2` automatically.
- **End before rerunning.** A rerun is a new competition with a new pool. Its
  predecessor's pool should already be gone (`GET /api/admin/pools` shows no
  `huitz-ranked-<old-slug>`); if End was interrupted, run
  `python3 -m engine.cleanup --slug <old-slug>` (or `--all-ended`) first.
- **A version bump keeps live runs alive.** The serving cache retains the
  version a live competition pins; create/start/rerun still refuse anything but
  the folder's current version, and the retained row is purged after that
  competition ends.
- **Auto-end.** Tick it on the new-competition form (or toggle it on the
  competition page) and the sweeper ends the competition once joins are closed
  and every run has finished, releasing the pool without an operator.
- **A player is in one competition at a time** (by cookie and by live display
  name). Overlapping rosters produce "already competing in X" join failures;
  that is intentional, not a bug.
- **`/leaderboard?scenario=` is ambiguous with several competitions.** It
  answers `400` with the candidate slugs; use `?competition=<slug>`. The
  competition pages and `/api/public/competitions/<slug>/leaderboard` are
  always per-competition.
- **Deploys are still engine-wide.** `/health` lists the live competitions and
  the deploy guard refuses while any is running (`HUITZ_DEPLOY_FORCE=1` to
  override); a mid-run code swap can orphan End-time cleanup.
- **`/join` is rate-limited by client IP.** Several events joining at once
  behind one NAT can exhaust the default budget and answer `429`; raise
  `$HUITZILOPOCHTLI_RATE_LIMIT_PER_MIN` / `$HUITZILOPOCHTLI_RATE_BURST` on the
  engine for the event window.
- **Recovering a stuck teardown:** `python3 -m engine.cleanup --all-ended
  --dry-run` lists every ended competition still holding a pool pin; drop
  `--dry-run` to release them in one pass (`--slug` still tears down one).

**Ties share a rank.** Equal totals get the same rank on the board, the
per-box report, and the CSV (standard competition ranking: `1, 2, 2, 4`).
Rows keep a stable display order, but that order does not change a tied
player's rank.

## 3. Build the ranked template

Ranked competition boxes are a separate lineage; an honor box is never
converted. Clone the sealed honor template, deploy the ranked competition
agent over it, verify, and seal that clone as the ranked template — the full
rollback/machine-id loop is `boxbuilder/DEPLOY.md`. Nothing is planted on this
clone:

```bash
export HUITZILOPOCHTLI_ENGINE_URL=https://<engine-host>
python3 -m boxbuilder compile --spec boxes/<box>/box.yaml --mode ranked \
  --no-bundle --out artifacts/<box>-ranked
python3 -m boxbuilder install --spec boxes/<box>/box.yaml --mode ranked \
  --competition --out artifacts/<box>-ranked --provider-host <clone-address>
```

Pass the **same engine URL** to both (or export it once): build state
fingerprints it and `install` refuses state from different inputs.
`--competition` mints no enrollment token and does not upload the scenario. It
places the agent, the signed manifest, the authoring public key, and an
`agent_config.json` whose `enrollment_token` is null — **no rubric, no engine
record, no answer key** — and leaves the agent unit (or Windows task)
disabled. Confirm no `identity.json*` or report artifacts remain, then seal;
`huitz join` enables and starts the unit on the player's clone.

**Seal on a network that can reach the engine.** A template on an isolated
bridge can only check in if that bridge's gateway allows the engine's port
(and only that port) and the engine has a return route to the bridge's subnet.
If either side is missing, `huitz join` times out and the box never checks in;
no engine-side fix can compensate.

**Do not deploy under a live field.** `install.sh` reads `/health` and refuses
when a competition is live unless `HUITZ_DEPLOY_FORCE=1` is set. A mid-run
code swap can orphan End-time cleanup even though scores persist.

```bash
python3 -m boxbuilder lint --all    # plant/check cross-check, every box
```

### 3.1 The scenario's `pool:` block

Each competition provisions **its own private pool** at the first claim,
cloned from the ranked template named in the scenario record's `pool:` block.
The engine never selects among the portal's pre-existing pools, so a ranked
competition can never be handed an honor-mode box. Fields mirror the portal's
`POST /api/admin/provision` 1:1; deployment values are `${...}` placeholders
expanded at ranked-build time:

```yaml
ranked:
  pool:
    template_vm_id: "${HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID}"
    template_vm_access_method: vnc      # ssh | vnc | rdp
    template_vm_username: "${HUITZILOPOCHTLI_POOL_TEMPLATE_USER}"
    template_vm_password: "${HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD}"
    vm_count: 2      # pre-provisioned; the dispenser clones more on demand
    # defaults: dispenser: true, private: true, group: Challenge,
    #           guac_link_ttl_seconds: 7200
```

When the engine parses `boxes/` directly, one global
`HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID` cannot describe several ranked boxes
that clone different templates. Put the deployment values in a local,
gitignored map keyed by scenario name:

```yaml
# /etc/huitzilopochtli/pools.yaml (0600; never committed)
scenarios:
  "Broadneck Post":
    template_vm_id: <template-vmid>
    template_vm_access_method: ssh
    template_vm_username: <template-login-user>
    template_vm_password: <template-login-password>
```

`HUITZILOPOCHTLI_POOLS_FILE` overrides the path. A box with no entry falls
back to the committed `${VAR}` expansion (single-box deployments). The
installer creates an empty map if none is supplied and copies one from
`HUITZ_POOLS_FILE` when given.

**The file must be readable by the engine's own user** (`huitz` under the
reference install — `chown huitz:huitz`, `chmod 640`). A root-owned 0600 file
fails the scan exactly like a malformed one: the store keeps serving the last
good mirror, claims answer *"the scenario has no pool provisioning block"*,
and nothing else looks wrong. The admin competition picker shows the error,
and the sweep loop now repeats it to stderr on first sight and on every
change (`scenario sync: …` / `scenario sync: recovered`); a `Permission denied`
there names the user that must be granted read.

Add the block after the template is sealed (the VM id only exists then), then
recompile and upload. `compile` fails on an unset variable rather than
shipping an empty id or password:

```bash
export HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID=<template-vmid>
export HUITZILOPOCHTLI_POOL_TEMPLATE_USER=<template-login-user>
export HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD='<template-login-password>'
python3 -m boxbuilder compile --spec boxes/<box>/box.yaml --mode ranked \
  --no-bundle --out artifacts/<box>-ranked
```

A `pool:` block on an honor scenario is a validation error. What the engine
does with it:

- On the first claim (or a sweeper retry) it has the portal provision a private
  dispenser pool named `huitz-ranked-<competition-slug>` from that template,
  pins the code (audit `competition_pool`, `source: "provisioned"`), and
  claims from it. Provisioning is asynchronous portal-side; claims work
  immediately because the dispenser clones on demand.
- A same-name pool from an earlier attempt or restart is reused, but only if it
  clones the same template; a mismatch is refused loudly.
- **Ending a competition** (admin End or the next sweep) releases its VMs and
  deletes its pool. Pools this engine did not provision are left alone; only
  the pin is cleared.
- The only admin operation is read-only visibility plus **clearing** a pinned
  pool (`POST /admin/api/competitions/<id>/pool` with an empty `pool_code`) so
  the next claim provisions afresh. A competition can never be pointed at an
  arbitrary existing pool.
- **Pre-deploy** (the competition page's *Pre-deploy boxes* card) warms the
  pool ahead of the joins. It can only work with something to clone from: a
  pin the portal still lists, or the scenario's `pool:` block. With neither,
  the admin console flags the competition row, the card states the reason, and
  the click is refused before any job starts — the card clears itself on the
  next poll once the scenario or the engine's pools file is fixed. A pin whose
  pool the portal no longer lists is not a dead end: the next pre-deploy or
  join re-clones one from the scenario's template (audit
  `competition_pool_stale`).
- **Seat sizing.** `vm_count` is the pool's pre-provisioned size. A claim that
  finds every seat spoken waits in `invited` (retry tickets) until one frees —
  a player leaving or a run clock expiring releases its VM promptly — or until
  the portal's dispenser adds one. Size it to expected concurrency; joining
  into a saturated pool is not an error, but the player sees a wait.

### 3.2 Pre-bound joins (no terminal, no code)

The engine sends the portal the one-time join code; opening the player's link
re-mints a Guacamole session and runs `huitz join --code <code>` in the guest
through the QEMU guest agent. The run clock starts at that bind, not at clone.
A failed join shows the error, the VM link, a link back, and the fallback code.

```bash
# engine.env
HUITZILOPOCHTLI_WORKSHOP_SECRET=<hex>
# portal .env
HUITZ_PREBIND_SECRET=<hex>
PUBLIC_URL=https://<portal-host>          # if players reach the portal by another name
HUITZ_BIN=/usr/local/bin/huitz            # if huitz is not there
```

`engine/deploy/install.sh` writes `engine.env` only on a fresh install; add
these by hand and restart the unit (and the portal). With only the engine side
set, the portal rejects the prebind and the engine falls back to an audited
plain claim; with only the portal side set, nothing changes.

- **The portal's Proxmox token needs `VM.GuestAgent.Unrestricted`** (the
  provisioning token usually has `Audit` only). Without it the on-open join
  fails with a 403 and the VM comes back `joined: false`; grant it (a small
  `HuitzAgentExec` role works) or add it to the portal's custom role.
- **Windows boxes have no `huitz` shim.** The portal runs
  `python C:\ProgramData\huitzilopochtli\agent.pyz join --code <code>` for
  `rdp` pools (`HUITZ_WIN_PYTHON` / `HUITZ_WIN_AGENT`); the join enables the
  `HuitzilopochtliAgent` task, shipped registered but disabled.
- **Prebind fires on *open*, never on claim.** The join command runs inside
  the guest only when the player opens their VM link. A claimed box nobody
  opens — headless `ssh`-method boxes whose Guacamole session has nothing to
  show are the usual case — sits bound-to-nobody indefinitely. Nothing is
  broken: the player's page carries the code, and `huitz join --code <code>`
  run any way the operator can reach the box completes the same bind.
- **`guest-exec` is a hard dependency of prebind.** A hypervisor whose QEMU
  guest agent API does not implement `guest-exec` (stripped or shimmed PVE
  installs answer 501) fails every prebind, Windows included, and no amount
  of portal config fixes it — treat terminal fallback as the primary flow
  there, and note prebind was never the security boundary: the code is
  one-time, per-player, and rotates.
- **A ranked pool template is only sealed AFTER its plant step.** An
  install-only template (agent placed, `boxbuilder plant` skipped) binds,
  scores, and accrues SLA perfectly while every vulnerable-state check passes
  vacuously — there is nothing for players to harden, and several scenarios'
  "is absent" checks silently award points. Verify plant evidence exists on
  the box (a named planted user/file per `nakon.json` config) before
  `seal-prepare`, and re-verify the installed `manifest.signed.json` carries
  THIS scenario's `scenario_name` — a template sealed with the wrong
  manifest rejects every player bind with 409 "built for a different
  scenario". (Both failure modes were found in the 2026-11 range rehearsal.)
- **Some forensics evidence is adversary-authored.** In scenarios whose
  adversary actions plant or overwrite evidence (Broadneck: the
  `mailchute` forward in `/home/postmaster/.forward` replaces a benign
  seeded forwarder only when the replay action fires), an early answer that
  reads the on-disk artifact is scored against the rubric's post-event truth.
  Brief players that forensics may need a re-check later in the run, and
  prefer answering after the run's midpoint.
- **A big Windows rubric takes minutes for its first score.** A 90-check
  Windows scenario runs each check as a PowerShell invocation, so the first
  scored check-in can land 3-5 minutes after `huitz join` says "the ranked
  agent is starting". A freshly bound Windows box that shows no score yet is
  not broken — watch the engine until the first check-in arrives before
  calling a template dead. (Verification mistake made in the 2026-11
  rehearsal: Windows templates were marked unscored after a 90-second wait.)
- **`--competition` is what makes a pool template installable.** A plain
  `install --mode ranked` uploads the scenario record and demands the
  engine's admin token; pool templates carry no token (`--competition`),
  because the engine already serves the box folder and every player binds
  with `huitz join`. Missing the flag fails the install *after* plant and
  compile have succeeded, which looks like a plant problem.

## 4. Player join flow

**One competition at a time.** A slot is reserved per browser (`huitz_player`
cookie) and a live display name cannot be reused elsewhere; another join is
refused with a link back to the run until that competition ends or the slot is
left. While active, `/` is the run dashboard (score, clock, uptime strip,
board, VM actions, **Leave competition**); `/c/<slug>/me` is the permanent
per-competition link.

1. Open `/c/<slug>`, click **Join**, enter a display name.
2. The engine reserves the slot, mints a one-time code, claims a VM from the
   competition's pool (provisioning it first if needed), and redirects to `/`.
3. The dashboard shows **Open my VM**, a stable portal link; failed claims
   retry automatically and **Get a new VM** forces an attempt.
4. Opening the link mints a fresh Guacamole session and runs `huitz join`.
5. The engine binds the box and starts that player's clock; signed check-ins
   begin, and the dashboard flips to "your box is joined".

The link stays valid for the life of the claim: reopening it always mints a
new session; if the VM is gone, the portal says so and links back.

**Leaving is a forfeit.** **Leave competition** releases the VM, removes the
slot and its score from the board, clears the player cookie, and frees the
player to join another competition. It cannot be undone. ("The board" is the
competition page. `GET /leaderboard?scenario=…` is the scenario's historical
view: it lists every score ever submitted, and a forfeited box simply stops
checking in — rows age out by silence, they are not deleted.)

**Scripted players.** The join POST is a PRG: it answers 303 with the
`huitz_player` cookie *on the redirect*, and every later call needs it.
Browsers carry it across redirects; HTTP clients that follow redirects
without storing `Set-Cookie` (urllib's default opener is the classic) end up
cookie-less and see `/c/<slug>/join/success` 404 "No player session" — even
though the join itself created the invited player and started the claim.
Suppress redirects (or capture the cookie jar on the 303) and replay the
Location by hand.

**Fallback.** The join page's "Join from the terminal" section carries
`huitz join` and the code; an admin can reissue it (rotating the portal's copy)
from the roster. The fresh code is shown once in a banner, never in the page
or URL.

## 5. Admin and engine ops

Disqualification (§7.1) is a board exclusion, not an eviction: the
disqualified player keeps their VM and their full clock, keeps checking
in (told via the box report banner and their pages), and their score is
simply absent from the board; only Remove releases the box and frees the
seat, and Reinstate walks a disqualified run back onto the board.
Console `/admin` (competitions, counts, audit), `/admin/competitions/<id>`
(start/end/close joins/rerun, roster, reissue, disqualify/reinstate/remove, CSV; ended
competitions add **Remove**), `/admin/audit` (every admin and system action,
newest first: engine-local time, actor plus the address it came from, action,
the competition/player it touched, and the logged detail; query strings
`?competition=<slug or id>` and `?limit=<n>` (default 200, max 1000,
clamped). A filtered view searches the newest 2000 entries -- `list_audit()`
reads a bounded window of the append-only table -- and the page says which
window it searched). API: `/admin/api/competitions` and `/admin/players/<id>`;
CSRF applies to session forms only. A sweeper
(`$HUITZILOPOCHTLI_SWEEP_INTERVAL_S`, 15s) retries failed claims, rotates
expiring codes, and cleans ended pools. Engine install, upgrade, and
backup/restore are in `engine/deploy/README.md`.

## AD scenarios: build order that actually works

Meridian and Harborline are domain-controller scenarios, and three things must
be true before the plant runs or the template is worthless:

1. **Set the local Administrator password first.** `Install-ADDSForest` refuses
   to promote while the built-in Administrator password is blank
   ("Verification of prerequisites for Domain Controller promotion failed").
   The base image ships it blank, so run `net user Administrator "<pw>"` before
   promoting.
2. **Promote, then wait for real DC health.** The promotion reboots and the AD
   PowerShell cmdlets only work once AD Web Services is up. Gate on all three:
   `Get-ADDomain` returns the expected DNSRoot, `Get-Service NTDS` is Running,
   and `C:\Windows\NTDS\ntds.dit` exists. Checking only for a substring like
   "DOMAIN=" is not a gate — PowerShell echoes the failing command line, so the
   marker matches its own error text (this shipped two domain-less templates).
3. **Plant only on a healthy DC, and require every `ad-*` step to pass.** With
   ADWS down, all 13 (Meridian) / 18 (Harborline) domain steps fail with
   "Unable to find a default server with Active Directory Web Services
   running" while the theme steps still succeed — a template that looks built
   and has no domain vulnerabilities at all.

Two consequences worth knowing:

- **After promotion, the local `sysadmin` account no longer authenticates.**
  The local Administrator becomes the domain Administrator; SSH and
  `boxbuilder install` must use `Administrator` with the password set in step 1
  (re-set `sysadmin`'s password afterwards so players can still log in).
- **A correctly-promoted DC template clones fine.** Verified on the range: a
  clone of the rebuilt Meridian template comes up with `meridian.local`, NTDS
  and ADWS running, and the planted AD accounts present. The failures seen
  before the rebuild were the broken promotion, not clone detection.
