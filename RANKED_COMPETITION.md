# Ranked competitions — operator runbook

This is the operator-facing companion to
[`RANKED_COMPETITION_PLAN.md`](RANKED_COMPETITION_PLAN.md). It describes the
implemented v1.1 competition surface: engine VM, online join, per-player timed
runs, self-reported scored services, public leaderboard, and admin console.

## Deployed lab instance

| Item | Value |
|---|---|
| Proxmox VM | `huitzilopochtli-engine` (vmid 168), Ubuntu 24.04 |
| Address | `http://10.0.0.160:8080` |
| Engine service | `huitzilopochtli-engine.service` (systemd) |
| Database | `/var/lib/huitzilopochtli/engine.db` (0600) |
| Env | `/etc/huitzilopochtli/engine.env` (0600) |
| Admin credentials | `/root/huitz-engine-credentials.txt` on the engine VM (0600) |
| Workshop portal | `http://10.0.0.102:5000` (`HUITZILOPOCHTLI_WORKSHOP_URL`) |
| Backups | `/var/backups/huitzilopochtli/` daily at 03:15, 14 kept |

The engine is HTTP-only for now; put Cloudflare Tunnel or a TLS reverse proxy
in front before exposing it beyond the lab. Admin auth is HTTP Basic at the
engine (`HUITZILOPOCHTLI_ADMIN_PASSWORD`); the leaderboard/join pages are public.

`HUITZILOPOCHTLI_ADMIN_TOKEN` remains supported for the legacy JSON admin API
(`/admin/scenarios`, `/admin/tokens`) and for automation.

## 1. Create/upload a scenario

A ranked competition scenario needs `mode: ranked`, an `engine_url`, checks,
and (for scored services) a `services:` block:

```yaml
scenario:
  name: "Ranked Demo"
  version: 2
  mode: ranked
  engine_url: "http://10.0.0.160:8080"
  hosts: ["localhost"]

checks:
  - id: banner
    type: file_regex
    category: vuln
    display: "Status file says hardened"
    max_points: 10
    collect: {path: /etc/huitz-demo-status, extract: '(hardened|vulnerable)'}
    expect: {equals: hardened, points: 10}

services:
  - id: web
    display: "Demo web"
    type: http_uptime
    collect: {url: "http://127.0.0.1:8081/health"}
    expect: {equals: 200, field: status}
    interval_s: 30
    points_per_interval: 1
    max_intervals_per_checkin: 3
  - id: ssh
    display: "SSH"
    type: tcp_port
    collect: {host: 127.0.0.1, port: 22}
    expect: {equals: true, field: open}
    interval_s: 30
    points_per_interval: 1

adversary:
  events:
    - id: kill-demo-web
      action: kill_service
      params: {service: "huitz-demo-web"}
      window_s: [20, 40]
      affects_check: web          # service id is mapped to svc_web at compile
```

Compile:

```bash
python3 - <<'PY'
from common.crypto import signing
from authoring.compile import compile_scenario
priv, pub = signing.keypair()
out = compile_scenario("boxes/ranked-demo/scenario-r2.yaml",
                       "boxes/ranked-demo/artifacts-r2", priv)
open("boxes/ranked-demo/artifacts-r2/authoring.key", "wb").write(priv)
print(out)
PY
```

The admin console's scenario picker lists records uploaded to the engine **and** ranked records found in the box folder (when the engine has one). Selecting a folder build re-imports it; an uploaded record is used as-is.

Upload the resulting `engine_record.json` via the admin console
(`/admin/scenarios`) or the JSON API:

```bash
curl -sS -u admin:"$ADMIN_PASSWORD" -H 'Content-Type: application/json' \
  -d @boxes/ranked-demo/artifacts-r2/engine_record.json \
  http://10.0.0.160:8080/admin/scenarios
```

## 2. Create and start a competition

Admin console: `/admin/competitions/new`.

Fields:

- **Name / slug** — slug is the public URL `/c/<slug>`.
- **Scenario** — the uploaded name/version.
- **Max players** — hard cap; joins are refused when full.
- **Run duration** — each player's clock starts at join and ends after this.
- **Workshop pool** — provisioned per competition, not chosen: at the first
  claim the engine asks the portal for a private dispenser pool cloned from
  the scenario's `pool:` block (see §3.1) and pins it. There is no pool field
  in the UI; the competition page only records that a pool was attached — the
  pool code itself is portal plumbing, kept for debugging to the audit log and
  journal. Clearing a
  pin (so the next claim provisions a fresh pool) is the only mutation:
  `POST /admin/api/competitions/<id>/pool` with an empty `pool_code`.
  `HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD` authorizes the engine's portal
  admin calls; `HUITZILOPOCHTLI_WORKSHOP_SECRET` carries the prebind codes.
- **Join instructions / accent** — optional presentation.

Start the competition from its admin page. It moves `draft → live` and opens
joins. **End** freezes all runs and the leaderboard. **Close joins** stops new
players without ending existing runs. There is no pause.

## 3. Build the ranked competition box

Honor boxes are not convertible. Build a ranked box from a clean base:

```bash
boxbuilder compile --spec box.yaml --out artifacts/ --json
boxbuilder plant   --spec box.yaml --out artifacts/ --json
boxbuilder install --spec box.yaml --out artifacts/ --competition --json
```

`--competition` skips the engine-record upload and enrollment-token mint,
installs the agent + signed manifest + authoring key, and leaves the agent
unit **disabled**. The player runs `huitz join` with the code from the join
page; that binds the box and enables/starts the unit.

For a manual/lab install, copy `agent.pyz`, `manifest.signed.json`,
`authoring_public_key.b64`, and an `agent_config.json` with
`"enrollment_token": null` into `/opt/.huitzilopochtli/`, install the unit,
then run `/usr/local/bin/huitz join --code <CODE>`.

## 3.1 The scenario's `pool:` block (per-competition provisioning)

Each competition provisions **its own private pool** at the first claim,
cloned from the ranked template named in the scenario record's `pool:` block.
The engine never selects among the portal's pre-existing pools — so a ranked
competition can never be handed an honor-mode box. Author the block in the
ranked scenario YAML (field names mirror the portal's
`POST /api/admin/provision` 1:1):

```yaml
pool:
  template_vm_id: 183
  template_vm_access_method: vnc
  template_vm_username: sysadmin
  template_vm_password: asdf
  vm_count: 2          # pre-provisioned VMs; the dispenser clones more on demand
  # optional, defaults: dispenser: true, private: true, group: Challenge,
  #                     guac_link_ttl_seconds: 7200
```

Recompile (`boxbuilder compile`) and upload the engine record to the engine
(`POST /admin/scenarios` or the box-folder import). A `pool:` block on an
**honor** scenario is a validation error — pools exist only to hand out ranked
boxes. What the engine does with it:

- On the first claim (or sweeper retry), it asks the portal to provision a
  private dispenser pool named `huitz-ranked-<competition-slug>` from that
  template, pins the new pool code on the competition (audit event
  `competition_pool`, `source: "provisioned"`), and claims from it. VM
  provisioning runs asynchronously portal-side; claims work immediately
  because the dispenser clones on demand.
- If a portal provisioning job is already running, the request is retried by
  the sweeper. If a pool with the competition's name already exists (an
  earlier attempt or engine restart), it is reused — but only if it clones
  the same template; a template mismatch is refused loudly.
- **Ending a competition** (the admin End action, or the next sweeper pass)
  releases the competition's VMs and deletes its pool. Pools this engine did
  not provision (legacy pins from before per-competition provisioning) are
  never touched — the pin is simply cleared.
- The only admin operations left are read-only visibility (the competition
  page records that a pool is attached; the code itself stays in the audit
  log/journal) and **clearing** a pinned pool so the next
  claim provisions a fresh one. A competition can never be pointed at an
  arbitrary existing pool.

The lab used template `huitz-ranked-template` (vmid 174, full clone of a
working ranked box, cleaned identity, agent disabled). Keep the template VMs'
`qemu-guest-agent` installed — the on-open join runs through it.

### 3.2 Pre-bound joins (no terminal, no code)

The player gets one link and nothing to type. The engine sends the portal the
player's one-time join code; the portal keeps it and, when the player opens the
link, re-mints a fresh Guacamole session and runs

```bash
/usr/local/bin/huitz join --code <code>
```

inside the guest via qemu-guest-agent. The box binds itself and the run clock
starts at that moment (the click, not the clone). If the join fails, the player
is shown the error, the VM link, and a link back to the competition page, where
the fallback code and "Get a new VM" live.

Both sides need the same shared secret:

```bash
# engine.env
HUITZILOPOCHTLI_WORKSHOP_SECRET=<hex>
# portal .env
HUITZ_PREBIND_SECRET=<hex>
# portal .env, when players reach the portal by a name other than the engine does
PUBLIC_URL=https://portal.example
# portal .env, only if huitz is not at /usr/local/bin/huitz
HUITZ_BIN=/usr/local/bin/huitz
```

`engine/deploy/install.sh` only writes `engine.env` on a fresh install; add
these lines to an existing `/etc/huitzilopochtli/engine.env` by hand and
restart the unit (the portal needs a restart too, to reload `.env`).

Set only the engine side and the portal rejects the prebind (403); the engine
then falls back to a plain claim, so players still get a VM and can run
`huitz join` by hand. Set only the portal side and nothing changes — claims
without prebind behave as before.

Two more deployment facts, both found the hard way:

- **The portal's Proxmox token needs `VM.GuestAgent.Unrestricted`.** The token
  used to provision pools usually has `VM.GuestAgent.Audit` only (enough to
  read the VM's IP for Guacamole). Without `Unrestricted`, the on-open join
  fails with `403 ... VM.GuestAgent.Unrestricted` and the portal returns the
  VM with `joined: false` plus the error. Grant it to the token (a small
  `HuitzAgentExec` role works) — or add the privilege to the portal's custom
  role.
- **Windows boxes have no `huitz` shim.** The portal runs
  `python C:\ProgramData\huitzilopochtli\agent.pyz join --code <code>` for
  `rdp` pools (`HUITZ_WIN_PYTHON` / `HUITZ_WIN_AGENT`), and `huitz join`
  enables and starts the `HuitzilopochtliAgent` scheduled task (ranked Windows
  templates ship it registered but disabled).

## 4. Player join flow

1. Player opens `/c/<slug>` and clicks **Join**.
2. Enters a display name; the engine reserves a slot, mints a one-time code,
   and claims a VM from the competition's pool (resolving the pool first if
   needed).
3. The page shows **Open my VM** (a stable portal link). While the VM clones,
   it says it is being prepared and updates itself. Failed claims are retried
   automatically in the background; the page also offers **Get a new VM** for
   an immediate retry.
4. Player clicks the link. The portal mints a fresh Guacamole session and runs
   `huitz join` in the guest before handing over the console.
5. The engine binds the box, starts that player's run clock, and the agent
   begins signed check-ins. The page flips to "your box is joined".
6. Player watches `/c/<slug>` or `huitz watch`.

The link is stable for the life of the claim: reopening it always mints a new
session, so an idle Guacamole token is not a dead end. If the VM is gone
(released, expired, competition ended), the portal says so and links back; use
**Get a new VM** on the competition page.

**Fallback.** `huitz join` and the code are still there: open the join page's
"Join from the terminal" section and run it yourself. An admin can reissue the
code (and rotate the portal's copy) from the roster; the fresh code is shown
once in a confirmation banner and never lingers in the page or the URL.

If the player loses the page, `/c/<slug>/me` uses a player cookie (it shows the
score, a live countdown, the last check-in age, the VM link, and the same
**Get a new VM** button).

## 5. Scored services

- Each service is a normal check plus SLA parameters, compiled under
  `svc_<id>`.
- The box agent probes its own service; the engine accrues
  `points_per_interval` while the service is UP, using the engine receipt
  clock, capped per check-in (default 3 intervals), and never back-pays an
  outage.
- Hysteresis defaults to 2/2: two consecutive failures go DOWN, two successes
  go UP.
- **Ceiling:** this is self-reported. It proves the box observed the service
  locally, not that it is reachable from another network. Use `http_uptime`,
  `tcp_port`, `service_state`, or `db_query` and document the perspective.

## 6. Admin operations

- `/admin` — competitions, status, player counts, recent audit (auto-updates
  every 30s).
- `/admin/competitions/<id>` — start/end/close joins, roster (auto-updates
  every 15s; score, service dots, check-in age, reissue code,
  disqualify/remove with confirmations), join-URL copy button, export via API.
  Join codes are never rendered; a reissue shows the fresh code once.
- `/admin/scenarios` — paste an `engine_record.json` and validate/upload.
- `/admin/audit` — admin action log with `?action=` filter chips.
- API (admin token or Basic):
  - `GET/POST /admin/api/competitions`
  - `GET /admin/api/competitions/<id>`
  - `POST /admin/api/competitions/<id>/start|end|close-join`
  - `POST /admin/api/competitions/<id>/pool` — optional automation override;
    pool picking is normally automatic
  - `POST /admin/players/<id>/reissue|retry-claim|disqualify|remove`
  - `POST /api/public/join/<player_id>/claim` (player cookie + page CSRF)

A background sweeper (`HUITZILOPOCHTLI_SWEEP_INTERVAL_S`, default 15s; runs
when `HUITZILOPOCHTLI_WORKSHOP_URL` is set) keeps dispensing automatic: it
retries claims that never got a VM (per-player exponential backoff up to 5
minutes, refreshing an expired join code first), advances provisioning
tickets left behind by closed join pages, and rotates the portal's join code
on claimed VMs before it expires.

CSRF tokens are required for session-authenticated form posts; header-auth API
calls are exempt.

### Web UI design notes

The engine UI (public + admin + display board) is server-rendered from
`engine/web.py` in a cream editorial style — hard 1px espresso frames, sharp
corners, serif headings, small uppercase sans labels, flat surfaces. Two
themes share one token set: cream (default; follows `prefers-color-scheme`,
overridable via the header toggle, persisted in `huitz-theme` localStorage)
and a warm dark roast. Per-competition accents (set at creation) color links,
the leader's rank edge, and the big-screen score; unreadable accents are
clamped to the default. Live pages poll in place via fetch + section swap
(leaderboard/display 5s, roster 15s, /me 15s, dashboard 30s) with a
`<noscript>` meta-refresh fallback and ticking countdowns.

## 7. Engine VM operations

```bash
# status / health
systemctl status huitzilopochtli-engine
curl -sS http://127.0.0.1:8080/health

# logs
journalctl -u huitzilopochtli-engine -f

# backup now
systemctl start huitzilopochtli-backup.service
ls -l /var/backups/huitzilopochtli/

# restart
systemctl restart huitzilopochtli-engine
```

Engine code is deployed from a tarball built on the dev host:

```bash
python3 packaging/build_engine_bundle.py dist/huitzilopochtli-engine.tar.gz
```

On the VM, extract and copy `common/` + `engine/` into
`/opt/huitzilopochtli/engine/`, then restart the unit. The engine database and
`engine.env` survive redeploys.

**Backup/restore:** stop the engine, copy a backup over
`/var/lib/huitzilopochtli/engine.db`, fix ownership (`huitz:huitz`, `0600`),
start the engine. Restore the matching `HUITZILOPOCHTLI_SERVER_SECRET` from
`engine.env`; rotating it re-schedules every box's adversary events.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Join page says "no VM" / shows a red claim error | The roster shows the exact portal error; failed claims retry automatically every sweep. Check `HUITZILOPOCHTLI_WORKSHOP_URL` / `HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD` and the portal's `/api/admin/pools`; use **Retry VM** or **Get a new VM** to force an immediate attempt |
| VM opens but never joins | Portal log for `Prebind ... failed`; check `HUITZ_PREBIND_SECRET` matches on both sides, `HUITZ_BIN`, and `huitz join --code <code>` by hand in the guest |
| `huitz join` 403 | code expired/used; reissue from roster; check server clock |
| Box checks in but score 0 | signed manifest scenario/version matches the competition; `journalctl -u huitzilopochtli-agent` |
| Service always DOWN | check `collect` URL/port from **inside** the box; evidence reason on `/c/<slug>` or `huitz score` |
| Admin page 401 | `HUITZILOPOCHTLI_ADMIN_PASSWORD`; credentials file on VM |
| Engine won't start | `journalctl`; `python3 -m engine.server` manually from `/opt/huitzilopochtli/engine` |
| Disk filling | backups/retention; DB size; `df -h` |
