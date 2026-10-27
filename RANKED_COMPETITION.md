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
players without ending runs; **End** freezes every run and the board. An ended
competition can be **rerun** (fresh, same settings) or **removed** — removal
releases its VMs, cleans its pool, and deletes the competition and its slots;
boxes and scores remain as history.

**End also tears the pool down.** It releases claimed VMs, destroys the pool's
remaining pre-provisioned clones, and deletes the pool configuration. If the
portal is unreachable the pool pin is kept and the sweeper retries. Ending
seconds after the first claim is safe: the engine waits briefly for clones
that are still registering, then sweeps again after deleting the pool.

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
player to join another competition. It cannot be undone.

**Fallback.** The join page's "Join from the terminal" section carries
`huitz join` and the code; an admin can reissue it (rotating the portal's copy)
from the roster. The fresh code is shown once in a banner, never in the page
or URL.

## 5. Admin and engine ops

Console `/admin` (competitions, counts, audit), `/admin/competitions/<id>`
(start/end/close joins/rerun, roster, reissue, disqualify/remove, CSV; ended
competitions add **Remove**), `/admin/audit`. API: `/admin/api/competitions` and `/admin/players/<id>`;
CSRF applies to session forms only. A sweeper
(`$HUITZILOPOCHTLI_SWEEP_INTERVAL_S`, 15s) retries failed claims, rotates
expiring codes, and cleans ended pools. Engine install, upgrade, and
backup/restore are in `engine/deploy/README.md`.
