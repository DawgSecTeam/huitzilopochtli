# boxbuilder

A practice-box factory that pairs **nakon**-planted vulnerabilities with
**huitzilopochtli** hardening scoring, automating the four-step workflow for
creating CyberPatriot / eCitadel-style boxes and competitions.

boxbuilder is **author/build-machine tooling** (like `authoring/` and
`packaging/`) — it is excluded from the agent zipapp and may use third-party
deps (PyYAML, paramiko). It is invoked via `python3 -m boxbuilder ...`.

## The workflow

```
  ┌─ you author ──────────────────────────────┐    ┌─ boxbuilder runs ───────────────────────────┐
  │  box spec YAML   (scenario + nakon config)│    │                                              │
  │  scenario YAML   (huitz checks)           │ ─► │  1. compile   scenario+key ─► manifest,     │
  │  nakon config    (which vulns to plant)   │    │                            rubric, agent.pyz│
  └───────────────────────────────────────────┘    │                            + nakon bundle    │
                                                   │  2. plant     nakon deploy ─► vulns on box   │
                                                   │  3. install   agent.pyz+manifest ─► on box   │
                                                   │                            (+engine if ranked)│
                                                   │  4. package   export box image for distro    │
                                                   └──────────────────────────────────────────────┘
```

The key idea: **nakon plants a vulnerability; huitzilopochtli scores whether a
team hardened it.** You author *both* halves — the vuln selection (nakon config)
and the checks that verify the hardening (scenario YAML). boxbuilder does **not**
know the vuln→check mapping; it orchestrates. This keeps the vulndb
consumer-agnostic and avoids a mirrored registry of an unfinished catalog.

## Quick start

```bash
# 1. Browse the vulndb catalog and pick vulns (agent-facing, read-only):
nakon catalog list --json
nakon catalog check --select nginx,ssh-root-login,suid-find --json

# 2. Author a nakon config (which vulns) + a huitz scenario (which checks).
#    See boxes/chocolate-factory/ for a worked pairing.

# 3. Author a box spec tying them together:
#    boxes/chocolate-factory/box.yaml

# 4. Build the box (all four steps, resumable):
python3 -m boxbuilder build \
  --spec boxes/chocolate-factory/box.yaml \
  --image-out /tmp/chocolate-factory.ova --json
```

Each box lives in its own directory (`boxes/<name>/box.yaml`,
`scenario.yaml`, `nakon.json`, plus `assets/`). The worked example is the
**Cocoa Falls Chocolate Works** scenario:
`boxes/chocolate-factory/box.yaml` pairs with `scenario.yaml` and `nakon.json`
in the same directory.
It targets an Ubuntu/Xubuntu XFCE VM in honor mode and pairs ordinary cyPAT-style
access-control findings (root SSH login, passwordless sudo, unauthorized users,
unwanted admin membership, and loose permissions) with cron, malicious media,
autostart, and system-service persistence findings. Its bundled planting seeds
are ensured into vulndb idempotently when selected; point `VULNDB_UI_URL` at the
shared catalog before compiling.

Each step is also runnable on its own (see CLI below) so you can pause/verify
between steps.

### VNC desktop caveats (xubuntu-vnc-derived templates)

If a VNC-viewed box (like chocolate-factory) shows a solid-black screen with
no desktop -- theme shortcuts (e.g. the "Scoring Report" icon) included --
this is very unlikely to be a boxbuilder/theme/agent bug even though it
looks like one from the shortcut's perspective. It's a live-cursor-but-black
X session underneath, and boxbuilder has no visibility into or control over
VNC/X11/lightdm at all (that setup lives entirely on the box's own template
image, outside this repo). Three independent, compounding causes were found
by direct `xwd`-based capture of a real X display (bypassing VNC/Guacamole
entirely -- a moving cursor is NOT proof the session is rendering; x11vnc
tracks/draws the pointer separately from the framebuffer capture):

1. **No real lightdm autologin.** A template built by manually typing a
   password into the greeter once (so it "stays logged in" as long as the
   VM is never rebooted) breaks on the first reboot or `systemctl restart
   lightdm` -- it drops back to a real login greeter nobody has credentials
   for, which sits there indefinitely with a dark background and a live
   cursor. This was the actual root cause the one time this was chased down
   in full (2026-09-05); the other two below are real but secondary.
2. **DPMS screen blanking** after an idle timeout, independently
   re-asserted by `xfce4-power-manager` regardless of raw `xset` settings.
3. **`xfce4-screensaver`'s own idle-activation** (separate from DPMS)
   painting a fullscreen black lock/blank window.

`boxes/shared/fix-xubuntu-vnc-display.sh` fixes all three (plus
a related machine-id/DHCP-collision issue -- see the script's own header) on
a booted (not yet re-templated) clone -- see its header comment for the full
incident writeup, exact commands, and the `xwdtopnm`-not-ImageMagick
diagnostic note. Run it once against any new xubuntu-vnc-derived template
before re-sealing with `qm template`.

**Updating an already-sealed Proxmox template**: `qm template` on LVM/LVM-thin
storage doesn't just flip a config flag -- it converts the backing volume
itself to a read-only "base" LV. Setting `template: 0` back via the config
API looks like it works (the flag flips) but the disk stays read-only and
the VM fails to start ("device is not writable"). There is no supported way
to edit a template in place: full-clone it to a fresh vmid, boot and edit
the clone, shut it down, and re-seal *that* (`qm template`) as the new
template, retiring the old vmid.

### Desktop shortcut/report caveats (any theme-enabled, snap-browser image)

Unlike the black-screen issue above, these three showed up even with the
display itself rendering correctly -- shortcuts that just quietly do the
wrong thing when clicked. Found the same way: live SSH diagnosis against a
booted clone, not a code read, since none of them are visible from
boxbuilder's side of the fence.

1. **Content-addressed filenames must never reach a Desktop icon.**
   `vulndb.ensure_attachment()`'s `<sha256[:16]>-<basename>` naming exists so
   identical attachment bytes are reused across builds -- it's an internal
   vulndb storage convention. `theme-readme.json` used to `cp` the
   attachment to each user's Desktop *under that same name*, so the icon
   read as e.g. `158f3cbb4e51da58-chocolate-factory-README.md` instead of
   `README.html`, and any shortcut assuming the clean name (like a scenario's
   own `desktop_shortcuts` entry pointing at `~/Desktop/README.html`) never
   resolved. Fixed by always copying out under a fixed `README.html` (authored
   Markdown is rendered to that themed page at build time by
   `boxbuilder/mdhtml.py`).
2. **A bare `~`/`$HOME` in a `.desktop` `Exec=` line is not guaranteed to be
   shell-expanded.** GLib's desktop-entry launcher does quote-removal, not
   tilde/variable expansion, so `Exec=xdg-open ~/Desktop/README.html` can
   silently fail to resolve regardless of whether the target file exists.
   Wrap any such Exec in `sh -c '...'` (e.g. `sh -c 'xdg-open
   $HOME/Desktop/README.html'`) so the shell -- not the launcher -- does the
   expansion.
3. **A strictly-confined snap browser (Ubuntu's default Firefox) can't see
   `/opt`.** `snap connections firefox` shows only the `home` interface
   connected -- no access outside `$HOME`. The auto-appended "Scoring
   Report" shortcut used to point straight at
   `/opt/huitzilopochtli/report.html`; Firefox would actually launch (so
   this doesn't look like caveat #2) but show "File not found", because the
   file is genuinely invisible to the sandboxed process, not because it's
   missing. Fixed by `packaging/sync-report.sh` (run via
   `huitzilopochtli-agent.service`'s `ExecStartPost`, which is why that
   unit's `ProtectHome` is `false` rather than `read-only`) mirroring
   `report.html` into each real user's `$HOME/Desktop`, and pointing the
   shortcut there instead. Honor mode's re-grade timer keeps that copy
   fresh; a ranked-mode box's single long-running process only gets the
   very first snapshot synced (`ExecStartPost` fires once, at service
   start) -- a known, currently-unaddressed limitation for that mode.

## The two inputs you author

### 1. nakon config (which vulns to plant)

A nakon machine list. Each entry's `configurations` names vulndb catalog entries
that, when deployed, make the box insecure in specific ways. Browse with
`nakon catalog list --json`; validate a selection with
`nakon catalog check --config <file> --json`. See
`boxes/chocolate-factory/nakon.json`.

The `ip`/`user`/`password` are **placeholders** — at deploy time boxbuilder
overwrites them with the provider's address (so the box spec is the single source
of truth for where the box is). v1 is single-box; the first machine is targeted.

### 2. huitz scenario (which checks score the hardening)

A standard huitzilopochtli scenario YAML (same shape `authoring/compile.py`
consumes). Each check awards points for correctly hardening what a planted vuln
broke. Mode (`honor`/`ranked`) and `engine_url` live here. See
`boxes/chocolate-factory/scenario.yaml` and `architecture.md` §8.

### The box spec (ties them together)

```yaml
scenario: ./scenario.yaml
nakon_config: ./nakon.json
provider: {name: ssh, host: 192.168.50.10, user: ubuntu, password: ubuntu}
authoring_key: ./authoring.key     # optional; auto-generated+persisted (0600) if absent
```

Mode is read from the scenario, not duplicated here.

## Modes

boxbuilder supports both huitzilopochtli modes in v1:

| | **honor** (take-home) | **ranked** (live) |
|---|---|---|
| Step 3 places | agent.pyz + manifest + **rubric.json** (on-box scoring) | agent.pyz + manifest (rubric stays off-box) |
| Engine needed? | No | **Yes** — a running engine the box checks in to |
| Step 3 also | — | uploads the scenario record + mints an enrollment token |
| `agent_config.json` | mode=honor, rubric set | mode=ranked, identity_path + checkin_interval_s + enrollment_token set |

For ranked mode, set `HUITZILOPOCHTLI_ADMIN_TOKEN` (the engine's admin token)
or pass `--admin-token`; boxbuilder uses the engine's `/admin/scenarios` and
`/admin/tokens` endpoints (engine/server.py).

> **Note:** what lands *on the box* is the **agent** (`.pyz`) + manifest in both
> modes. The **engine** (server) only exists in ranked mode and runs on a
> *separate* host — there is no engine on a practice box. (architecture.md §5.2)

## CLI

Every subcommand supports `--json`: the **result is a single JSON line on
stdout** (parseable like nakon's `--json`); progress/logs go to **stderr**, so
`boxbuilder <cmd> --json | jq` works.

```
boxbuilder compile --spec box.yaml [--out artifacts/] [--json]
    Compile scenario + build agent.pyz + build nakon bundle. (Needs vulndb.)

boxbuilder plant   --spec box.yaml [--out artifacts/] [--bundle DIR] [--json]
    Deploy the vulns onto the box via nakon. (Needs only paramiko.)

boxbuilder install --spec box.yaml [--out artifacts/] [--init systemd|openrc|none]
                   [--admin-token T] [--checkin-interval N] [--json]
    Place agent + manifest (+ rubric for honor) on the box and enable the init
    unit. Ranked also uploads the engine record + mints an enrollment token.

boxbuilder package --spec box.yaml --image-out box.ova [--format ova|qcow2|raw] [--json]
    Export the box image for distribution.

boxbuilder build   --spec box.yaml [--from-step compile|plant|install|package]
                   [--image-out box.ova] [--json]
    Run all four steps with resumability. compile writes artifacts/build-state.json;
    later steps read it, so you can resume after a failure with --from-step.
```

You can pass the two inputs directly instead of `--spec`:
`--scenario X.yaml --nakon-config Y.json --provider ssh --provider-host ...`.

## Providers

The provider is how boxbuilder reaches and packages the box. Pluggable; v1 ships:

- **`ssh`** — box already running, reached over SSH (paramiko). `export()` returns
  `mode: "manual"` with instructions (a remote box can't snapshot itself; you
  export from its hypervisor).

Future providers (drop-ins, no boxbuilder changes needed):
- **`qemu`** — boots a cloud-init qcow2, deploys, exports the qcow2/ova.
- **`proxmox`** — clones a template, deploys via jump host, exports (mirrors
  tezcatlipoca's model).

Address reconciliation: the provider handle is the single source of truth for
the box's address. At deploy time, boxbuilder rewrites the nakon deploy config
to use the provider's address (vulns still come from your nakon config).

## nakon integration

boxbuilder treats nakon as a **CLI dependency** (never imports it as a library),
consistent with tezcatlipoca and nakon's documented CLI contract
(`vendor/nakon/README.md`). It shells out:

- `nakon build --json` (cwd = `$NAKON_DIR`, so nakon can read its `.env`/vulndb)
  → parses `{bundle_id, path, cached, plans, machines}` from the final stdout line.
- `nakon deploy --json` → parses `{ok, failures, machines[].steps}`.

Set `--nakon-dir` or `$NAKON_DIR` (default: the `vendor/nakon` submodule, falling back to a
sibling `../nakon` checkout). Catalog theming goes through the `vendor/vulndb-cli` submodule
(`$VULNDB_CLI_DIR`), not raw HTTP.

## How vulns and checks relate (important)

boxbuilder does **not** pair them for you. When you author a box, you must ensure
each planted vuln has a corresponding check that verifies the hardening — e.g.
`ssh-root-login` (plants `PermitRootLogin yes`) pairs with a `file_regex` check
expecting `PermitRootLogin no`. The worked example in `boxes/chocolate-factory/`
shows several concrete pairings. An agent authoring a box
should:

1. `nakon catalog show <vuln> --json` — read exactly what each vuln plants.
2. Write a check that awards points for the *opposite* (hardened) state.
3. `nakon catalog check` the selection before building.

## Theming

An optional top-level `theme:` block in the scenario YAML (sibling of `scenario`/
`checks`/`adversary`) decorates the box the way a CyberPatriot/CCDC image is themed —
wallpaper, a desktop README, an MOTD/login banner, and desktop launchers — on top of
whatever vulns get planted:

```yaml
theme:
  title: "Operation Featherstorm"        # report masthead + shortcut label fallback
  organization: "DawgSec"                 # report subtitle
  accent: "#c8102e"                       # report accent color (#rrggbb)
  logo: ./assets/logo.png                 # embedded in report.html as base64 (size-capped)
  wallpaper: ./assets/wallpaper.png       # file path, resolved relative to the scenario file
  readme: ./assets/README.md              # authored as Markdown; rendered to a themed
                                          # README.html on every user's Desktop
                                          # (.html passes through unrendered)
  motd: "Authorized use only."            # -> /etc/motd (+ /etc/issue if `issue` absent)
  desktop_shortcuts: [{name: "Wiki", exec: "xdg-open https://..."}]

# Scored forensics questions (CyberPatriot-style) -- see "Forensics questions" below.
forensics:
  - id: fq-mail-port
    question: "What port is the mail server listening on?"
    answer: "587"
    points: 10
```

`title`/`organization`/`accent`/`logo` are small and cosmetic — they're compiled straight
into the **signed manifest** (`authoring/compile.py::_build_manifest_theme`) and read by
the agent to brand `report.html` (`agent/reporter.py`). Everything else — the actual
on-box decoration — is **entirely vulndb-catalog-driven, with zero nakon source
changes**: `boxbuilder/theme.py` turns it into extra entries appended to every machine's
`configurations` list, referencing four small, generic, reusable catalog configurations
(`theme-wallpaper`, `theme-motd`, `theme-readme`, `theme-shortcuts` — static definitions
in `boxbuilder/vulndb_theme_configs/`) that `boxbuilder/vulndb.py` auto-creates
idempotently the first time they're needed. Free text (motd/issue/
shortcut name+exec) rides as ordinary nakon `vars`; the wallpaper/README files go through
one content-addressed attachment per distinct file — uploaded once, reused by every
scenario that references identical bytes, using nakon's own existing MinIO-backed
attachment fetcher unmodified.

This means a **themed** `compile` needs vulndb-ui reachable (`--vulndb-url` or
`$VULNDB_UI_URL`, default `http://127.0.0.1:3000` — same env var and default
`vulndb-cli` uses) *in addition to* the usual nakon/vulndb reachability `nakon build`
already needs; a scenario with **no theme block and no locally-seeded vulns**
never touches vulndb-ui at all. (Note: `compile` also ensures any *selected*
vuln that has a bundled seed in `boxbuilder/vulndb_vuln_configs/` exists in the
catalog — create-if-missing — so scenarios selecting seeded vulns reach
vulndb-ui even when untheme'd.) See
`boxes/chocolate-factory/{scenario,box}.yaml` for a worked,
themed example.

## Forensics questions (scored)

Forensics questions work like CyberPatriot's: each carries points, teams type answers
on the box, and correct answers earn the points (wrong/blank answers never deduct).
They live in a top-level `forensics:` block (sibling of `scenario:`/`checks:`):

```yaml
forensics:
  - id: fq-hidden-cron            # must not collide with a check id
    question: "What is the filename of the hidden cron job?"
    answer: "cocoa-hidden-sync"   # exact key; `answers: [...]` adds alternates
    points: 10                    # positive integer
    # path: /home/user/Desktop/Forensics-Questions.txt   # optional; default = Desktop
```

How it works end to end:

- **Compile** turns each question into a `forensics_answer` check (question text +
  answers-file path in the signed manifest) plus a rubric entry holding the answer key.
  The key never ships in the manifest — engine-side rubric in ranked mode, on-box
  `rubric.json` in honor mode, same as every other check.
- **On the box**, the agent writes `Forensics-Questions.txt` (with blank `Answer: ____
  ` lines) to the primary desktop user's Desktop on first boot — if the file already
  exists it is never overwritten, so team answers survive reboots/re-grades.
- **Scoring**: teams replace the `____` blanks; the agent's collector reads the file
  each re-grade/check-in pass and the shared evaluator compares answers (case-
  insensitive, whitespace-collapsed, punctuation-tolerant). A correct answer earns the
  question's points; the report shows a Forensics card with per-question status.

Because questions are scored, **pair them with planted vulnerabilities** like checks:
each answer should be discoverable from the box's evidence (see "How vulns and checks
relate" above). The chocolate-factory example shows four question/vuln pairings.

## Artifacts

`compile` writes to `artifacts/` (gitignored — contains the authoring key, rubric,
and agent zipapp):

```
artifacts/
  build-state.json         # resumability checkpoint (paths + bundle id; no secrets)
  authoring.key            # Ed25519 seed, mode 0600 (auto-generated if not supplied)
  manifest.signed.json     # signed manifest (compiled)
  rubric.json              # honor mode only
  engine_record.json       # ranked upload target
  authoring_public_key.b64 # verifies manifest signature on-box
  agent.pyz                # the agent artifact
  nakon-config.json        # the build input (captured)
  nakon-deploy-config.json # derived (address-reconciled) deploy config
  agent_config.json        # generated per-mode (placed on-box)
```

## Tests

```
pytest tests/unit/test_boxbuilder_*.py tests/integration/boxbuilder/
```

Unit tests cover spec parsing, key handling, nakon wrappers, per-mode artifact
generation, the provider registry, and theming (`vulndb.py` against a fake
`http.server`, `theme.py` with `vulndb.ensure_*` monkeypatched). Integration tests drive
`plant`/`install`/`package`/`build` end-to-end with a FakeProvider + a fake nakon (no
real VM, no real vulndb), and exercise `engine.py` against the **real** engine server.

## Out of scope

- **No vuln→check registry** (by design — agents author both halves).
- **Engine co-location** — ranked boxes need a separate running engine. A
  self-contained "engine-on-box" ranked variant is a future mode.
- **Multi-box / multi-team competitions** — boxbuilder targets single practice
  boxes. tezcatlipoca covers multi-team ranges; boxbuilder is complementary.
- **SshProvider self-export** — returns `manual`; a qemu/proxmox provider will
  make export fully automatic.
