# boxbuilder

A practice-box factory: it pairs **nakon**-planted vulnerabilities with
**huitzilopochtli** hardening scoring, turning one authored scenario and one
nakon config into a buildable box in four steps.

It is **author/build-machine tooling** (like `authoring/` and `packaging/`) —
not part of the agent zipapp, free to use PyYAML/paramiko, invoked as
`python3 -m boxbuilder …` — and never touches a box directly: every remote step
goes through a provider (v1: `ssh`).

## The four-step workflow

```
   you author                          boxbuilder runs
   boxes/<box>/scenario.yaml  ──►  1. compile   scenario → signed manifest,
   boxes/<box>/nakon.json                         rubric, engine record,
   boxes/<box>/box.yaml                           agent.pyz, nakon bundle
                                   2. plant     nakon deploy → vulns on the box
                                   3. install   agent + manifest (+ rubric in honor)
                                   4. package   export the box image
```

The key idea: **nakon plants a vulnerability; huitzilopochtli scores whether a
team hardened it.** You author both halves — the vuln selection (nakon config)
and the checks that verify the hardening (scenario). boxbuilder does not know
the vuln→check mapping; it orchestrates. That keeps the vulndb consumer-agnostic
and avoids a mirrored registry of an unfinished catalog.

Each step is also runnable alone; `build --from-step` resumes, refusing when the
scenario or nakon config changed since `compile` (the `build-state.json`
fingerprint).

### Quick start

```bash
# Browse and validate vulns (read-only, agent-safe):
nakon catalog list --json
nakon catalog show ssh-root-login --json
nakon catalog check --select nginx,ssh-root-login --json

# Author the two inputs (see the worked example below), cross-check them, then
# build (build ends at package, so --image-out is required):
python3 -m boxbuilder lint --all
python3 -m boxbuilder build --spec boxes/<box>/box.yaml --image-out <path>.ova --json
```

### The `--json` contract

Every subcommand takes `--json`. With it, **the result is exactly one JSON line
on stdout** (parseable like nakon's `--json`), so `… --json | jq` works and an
orchestrator can take `stdout.splitlines()[-1]`. Everything else — progress,
`[boxbuilder] …` log lines, warnings, and the human summary printed without
`--json` — goes to **stderr**. A failed `--json` call still prints one line
(`{"ok": false, "error": …}`) and exits non-zero.

## The inputs you author

```
boxes/<box>/
  scenario.yaml     # scenario + checks; also the ranked: block when applicable
  nakon.json        # which vulns to plant
  box.yaml          # the spec tying the two together
  assets/           # theme files (wallpaper, logo, handbook)
```

Worked example: [`boxes/chocolate-factory/`](../boxes/chocolate-factory/) —
[box.yaml](../boxes/chocolate-factory/box.yaml),
[scenario.yaml](../boxes/chocolate-factory/scenario.yaml),
[nakon.json](../boxes/chocolate-factory/nakon.json) side by side.

### 1. nakon config — which vulns to plant

A nakon machine list. Each machine's `configurations` names vulndb catalog
entries (with `vars`) that, once deployed, make the box insecure in specific
ways. Browse with `nakon catalog list --json`; validate a selection with
`nakon catalog check --config <file> --json`. Three rules:

- Exactly **one machine** per config (v1 targets a single box), and it must set
  `os`.
- `ip` / `user` / `password` are **placeholders**: at deploy time boxbuilder
  rewrites them from the provider handle, so this file is never the source of
  truth for where the box is.
- Plain JSON only — no comments, no `_comment` field.

### 2. scenario — which checks score the hardening

One standard huitzilopochtli scenario YAML, authored to the same shape
`authoring/compile.py` consumes — and the same file serves both build targets:

```yaml
scenario:
  name: "Example"
  version: 1
  mode: honor            # default build target; 'ranked' means ranked-only
  hosts: ["localhost"]

ranked:                  # optional; only read by a ranked build
  engine_url: "http://127.0.0.1:8080"   # loopback placeholder; override at build time
  checks: [...]          # ranked-only extra checks, appended
  services: [...]        # scored services (self-reported uptime)
  adversary: {...}       # engine-side red-team schedule
  pool: {...}            # workshop pool provisioning (env-placeholder friendly)

checks: [...]
theme: {...}
forensics: [...]
```

`scenario.mode` names the default target. `honor` means the file can build
either target; `ranked` means it is ranked-only, and an honor build is an error.
An honor build never reads the `ranked:` block, so ranked-only content cannot
leak into an honor manifest or rubric — structurally.

- `ranked.engine_url` is a **loopback placeholder** meaning "not configured
  yet"; the real address comes from `--engine-url` or
  `$HUITZILOPOCHTLI_ENGINE_URL` (see *Build targets*).
- `ranked.pool` fields may be `${VAR}` strings, expanded only on a ranked build:
  `${HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID}`, `..._TEMPLATE_USER`,
  `..._TEMPLATE_PASSWORD`. An unset variable is an error, so a committed
  scenario names no deployment specifics.
- `services` / `adversary` / `pool` belong under `ranked:`; a ranked-only file
  (`scenario.mode: ranked`) may also carry them at top level.

### The spec that ties them

```yaml
scenario: scenario.yaml
nakon_config: nakon.json
provider:
  name: ssh
  user: sysadmin
```

That is the whole committed spec; paths resolve relative to it. It carries **no
deployment facts** — no host, no password (a cloned box's DHCP address changes
every rebuild); deployment supplies those at invoke time. An optional
`authoring_key: ./authoring.key` and `provider.known_hosts` are read from the
spec when you want them pinned.

## Build targets and modes

The target is `--mode honor|ranked` (default: `scenario.mode`). There are no
separate ranked scenario or spec files: `--mode ranked` merges the same file's
`ranked:` block, and `--mode honor` ignores it.

| | **honor** | **ranked** | **ranked competition** |
|---|---|---|---|
| engine needed | no | yes — a running engine on its own host | yes — at join time |
| rubric | on the box (`.score.dat`, obfuscated) | engine-side only | engine-side only |
| step 3 also | — | seeds the engine's scenario cache (upload), mints an enrollment token | nothing; the engine reads `boxes/` itself — create the competition in the admin console |
| enrollment | — | token in `agent_config.json`, consumed on first boot | player runs `huitz join` with the one-time code |
| `ranked:` block read | no | yes | yes |

Step 3 places the **agent** (`agent.pyz`) plus the signed manifest and public
key, `agent_config.json`, the motd fragment (POSIX) and an init unit in every
mode; honor adds the obfuscated rubric and (on systemd) a re-grade timer. Ranked
adds `identity_path` / `checkin_interval_s`, the agent creates `identity.json` on
first boot, and any inherited honor timer is removed; the engine never lives on a
practice box.

- **Ranked** needs the engine's admin token: `--admin-token` or, preferably,
  `$HUITZILOPOCHTLI_ADMIN_TOKEN` (the flag shows up in process lists and shell
  history). boxbuilder posts the engine record to `/admin/scenarios` (a cache
  seed — the admin picker lists the engine's own `boxes/` folder, which the
  engine parses itself) and mints a token from `/admin/tokens`; `--enrollment-ttl` (default 86400 s) bounds its
  life and `--checkin-interval` (default 60 s) sets the check-in cadence.
- **Ranked competition** (`install`/`build --competition`): no upload and no
  token. The box cannot check in until the player runs `huitz join` with the code
  from the competition page, which binds the box and starts the agent.
  Competition boxes are a separate lineage — an honor build cannot be turned
  into one by flipping a flag, and each competition provisions its own pool.

### Where the addresses come from

- **Engine:** `--engine-url` > `$HUITZILOPOCHTLI_ENGINE_URL` >
  `ranked.engine_url` (then a legacy `scenario.engine_url`). A ranked install
  warns when the value is still the loopback placeholder. Plain-HTTP admin calls
  to a non-loopback engine are refused unless
  `HUITZILOPOCHTLI_ALLOW_INSECURE_ENGINE=1`; prefer `https://`.
- **Provider:** `--provider-host` / `-user` / `-password` / `-port`, or
  `$HUITZILOPOCHTLI_PROVIDER_{HOST,USER,PASSWORD,PORT}`, all overriding the spec.
  A missing `user` defaults to `root`; a missing password prompts (only for
  `plant`/`install`, which log in). Prefer the env var over `--provider-password`
  for the same process-list reason.
- **Host keys:** the ssh provider refuses to connect without a pinned host key —
  `provider.known_hosts` in the spec or `$HUITZILOPOCHTLI_KNOWN_HOSTS`;
  `HUITZILOPOCHTLI_INSECURE_HOST_KEYS=1` is a loud, lab-only opt-out.

## CLI reference

Run everything as `python3 -m boxbuilder <subcommand>`.

Common to `compile`, `plant`, `install`, `package` and `build`:

```
--spec FILE | --scenario FILE   exactly one; --scenario also needs --nakon-config
--nakon-config FILE             nakon machine list (direct-flag path)
--mode honor|ranked             build target (default: scenario.mode)
--engine-url URL                ranked engine (default: $HUITZILOPOCHTLI_ENGINE_URL,
                                then ranked.engine_url)
--authoring-key FILE            32-byte Ed25519 seed (default: artifacts/authoring.key)
--nakon-dir DIR                 nakon checkout (default: $NAKON_DIR, vendor/nakon,
                                then ../nakon)
--vulndb-url URL                vulndb-ui (default: $VULNDB_UI_URL, then
                                http://127.0.0.1:3000)
--provider ssh                  box provider (v1: ssh only)
--provider-host HOST            box address (default: $HUITZILOPOCHTLI_PROVIDER_HOST)
--provider-user USER            default: $HUITZILOPOCHTLI_PROVIDER_USER, then the spec
--provider-password PASS        default: $HUITZILOPOCHTLI_PROVIDER_PASSWORD, else prompt
--provider-port PORT            default: $HUITZILOPOCHTLI_PROVIDER_PORT, then 22
--out DIR                       artifacts directory (default: ./artifacts)
--json                          one JSON line on stdout
```

Each subcommand, with its extra flags:

```
compile    [common] --no-bundle
    Compile the scenario, build agent.pyz, build the nakon bundle (needs nakon
    plus its catalog access; themes or bundled seeds also need vulndb-ui).
    --no-bundle skips nakon and vulndb entirely: install-only artifacts, for a
    ranked template that installs over an already-planted honor seal.

plant      [common] --bundle PATH
    Deploy the vulns via `nakon deploy`. Needs the bundle (from --bundle or
    build-state.json) and the ssh provider, but not vulndb.

install    [common] --init systemd|openrc|none --admin-token TOKEN
           --checkin-interval SECS --enrollment-ttl SECS --competition
    Place the agent + manifest (+ rubric for honor), write the motd fragment,
    install and enable the init unit; ranked also wires the engine.

package    [common] --image-out PATH --format ova|qcow2|raw
    Export the box image through the provider. --image-out is required.

build      [common] --image-out PATH --from-step compile|plant|install|package
           --init … --admin-token … --checkin-interval … --enrollment-ttl …
           --competition --no-bundle --format …
    Run the four steps with resumability: later steps refuse a build-state.json
    whose input fingerprint no longer matches the scenario/nakon config, and a
    reinstall clears the install dir so no old rubric, identity or report
    survives a mode or scenario change.

verify     [common] [--competition] [--expect-total N] [--for-seal]
    Check a live box against the build: install completeness, manifest/key
    lineage, agent config, init state, journal, report, theme artifacts and
    (optionally) seal hygiene. Exit 1 on any failure; `skip` means "not
    measurable here". See "Verify and seal" below.

seal-prepare [common] [--competition] [--expect-total N] [--for-seal]
           [--skip-verify] --yes
    Stop and disable the agent, remove identity/enrollment/report state and
    per-user mirrors, truncate /etc/machine-id, and print the lineage hashes.
    Aborts unless `verify` passes. Idempotent; --yes is required.

lint       --all | --spec FILE | --scenario FILE --nakon-config FILE
           [--boxes-dir DIR] [--mode honor|ranked] [--engine-url URL]
           [--catalog] [--nakon-dir DIR] [--json]
    Cross-check each planted vuln against the scored checks. --all walks
    ./boxes (or --boxes-dir) for */box.yaml. --catalog additionally validates
    the selection with `nakon catalog check` (needs the nakon checkout and
    catalog access); without it lint never touches the network.

answer-key --scenario FILE [--out PATH] [--html] [--json]
    Render authored `solution:` walkthroughs into a post-event handout.
```

`lint` writes one status line per box to stderr; with `--json`, stdout carries
one line: `{"ok": bool, "reports": [...]}`. Exit code is 1 if any box fails and
2 if `--all` found no boxes.

## nakon integration

boxbuilder treats nakon as a **CLI dependency** — it shells out with
`cwd = <nakon-dir>` (so nakon can read its own `.env`) and never imports it:

- `nakon build --json` → `{bundle_id, path, plans, machines}`. Bundles are
  content-addressed under `<nakon-dir>/bundles/`, with the path recorded in
  `build-state.json` for `plant`.
- `nakon deploy --json` → `{bundle_id, machines, failures, ok, log_dir}`.

**`bundle_id` / `request_key`.** A bundle is a map from request key to plan, and
nakon looks plans up by `request_key` — platform plus the *ordered* configuration
list — never by machine name. Anything that changes that list changes the key.

**Address reconciliation.** `plant` takes the vuln list for the target machine
from your config but rewrites `ip` / `user` / `password` / `port` from the
provider handle, the single source of truth for where the box is. That derived
deploy config is a 0600 temp file inside `artifacts/`, deleted in a `finally`
right after deploy because it holds the SSH password.

**Themes are appended at compile time.** `theme:` is resolved into extra
`configurations` entries and appended to every machine's list *before* the bundle
is built, so the bundle's `request_key` covers them. That is why `plant` reads
the compiled `artifacts/nakon-config.json` rather than the file you authored:
deploying the raw config would omit the theme entries and ask nakon for a request
key the bundle does not contain (falling back to the raw config only when no
compiled copy exists).

Set `--nakon-dir` or `$NAKON_DIR`; the default is the `vendor/nakon` submodule,
then a sibling `../nakon` checkout. Catalog theming goes through the
`vendor/vulndb-cli` submodule (`$VULNDB_CLI_DIR`), not raw HTTP.

## How vulns and checks relate

boxbuilder does **not** pair them for you. Each planted vuln needs a check that
awards points for the **opposite, hardened state** — a vuln that plants
`PermitRootLogin yes` pairs with a `file_regex` check expecting
`PermitRootLogin no`. The rule: read what the vuln plants
(`nakon catalog show <vuln> --json`), write a check that scores that artefact's
hardened state, then `nakon catalog check` the selection and `boxbuilder lint`.

`python3 -m boxbuilder lint --all [--json]` is the mechanical half of that
discipline, and warnings do not fail it — they are the review list. For each box:

- **errors** when the build inputs do not validate for either target, when a
  configuration's primary planted artefact (its `FILE_PATH`, `DIR`,
  `TARGET_FILE` or `LIB_PATH` var) is named by no check, when a theme asset
  (`wallpaper` / `readme` / `logo`) is missing, or when a scenario has no checks
  or duplicate check ids;
- **warns** for pairings it cannot prove mechanically — a configuration that
  plants identifying values none of the checks names, a check that scores a path
  under a writable data root that nothing plants, and configurations that exist
  only in the remote catalog (no bundled seed).

## Theming

An optional top-level `theme:` block (a sibling of `scenario` / `checks` /
`forensics`) decorates the box like a CyberPatriot/CCDC image:

```yaml
theme:
  title: "Example Range"           # report masthead + shortcut label fallback
  organization: "Example Org"      # report subtitle
  accent: "#c8102e"                # report accent (#rrggbb)
  logo: assets/logo.png            # embedded in the signed manifest (size-capped)
  wallpaper: assets/wallpaper.png  # resolved relative to the scenario file
  readme: assets/README.md         # authored Markdown → themed README.html on the box
  motd: "Authorized use only."     # -> /etc/motd (+ /etc/issue if `issue` absent)
  desktop_shortcuts:
    - {name: "Wiki", exec: "xdg-open https://example.invalid"}
```

`theme` keys split by destination:

- **Signed manifest:** `title`, `organization`, `accent`, the base64 `logo`, and
  the handbook text itself (`readme_text`) — read by the agent to brand
  `report.html`, and by `huitz readme` to render the handbook from the report
  snapshot in both modes. The logo is size-capped and fails the compile if over.
- **vulndb attachments:** the on-box decoration — wallpaper, motd/issue text, the
  rendered `README.html`, and desktop shortcuts (a "Scoring Report" launcher is
  appended unless `theme.include_report_shortcut: false`). `theme.py` turns these
  into extra catalog configurations (`theme-wallpaper`, `theme-motd`,
  `theme-readme`, `theme-shortcuts`, with `-win` variants) that `vulndb.py`
  creates idempotently; free text rides as nakon `vars`, and files go through one
  content-addressed attachment per distinct byte sequence.

The handbook is the assignment, not the answer key — write it to the bar in
[HANDBOOK_GUIDE.md](../HANDBOOK_GUIDE.md). Compile enforces the mechanical half
(`authoring/readme_lint.py`): a forensics answer verbatim in the handbook **fails
the compile**, while lesser leaks (copied walkthrough lines, mutation commands,
planted paths) surface as `readme_warnings` and `[boxbuilder] WARNING:` log
lines. `theme.readme_lint_allow` lists answer aliases the lint may ignore.

A **themed** compile therefore needs vulndb-ui reachable (`--vulndb-url` or
`$VULNDB_UI_URL`, default `http://127.0.0.1:3000`) on top of the catalog nakon
itself needs; `compile --no-bundle` touches neither, so it builds install-only
artifacts.

## Forensics questions and answer keys

Forensics questions are scored like checks, in a top-level `forensics:` block:
an id, the question, an `answer` (plus optional `answers` aliases), `points`, and
an optional `path` for the answers file.

```yaml
forensics:
  - id: fq-hidden-cron             # must not collide with a check id
    question: "What is the filename of the hidden cron job?"
    answer: "example-hidden-sync"
    points: 10
```

- **Compile** turns each question into a `forensics_answer` check (question text
  and answers-file path in the manifest) plus a rubric entry holding the answer
  key, so the key never ships in the manifest.
- **On the box**, the agent writes `Forensics-Questions.txt` with blank answer
  lines to the primary desktop user's Desktop on first boot and never overwrites
  it, so answers survive reboots and re-grades. Players record them with
  `huitz forensics <n> "<text>"`; answers match case-insensitively, collapsing
  whitespace and ignoring surrounding punctuation.
- Pair questions with planted evidence, like checks — otherwise it is a guessing
  game.

**Answer-key handouts.** Any check or forensics entry may carry a `solution:`
(a string or list of strings) in post-event walkthrough voice — authoring-side
only, never copied into the manifest or rubric. Render it with:

```bash
python3 -m boxbuilder answer-key --scenario boxes/<box>/scenario.yaml [--out PATH] [--html]
```

Output defaults to `artifacts/answer-keys/<scenario-slug>.md` (gitignored, 0600);
`--html` adds a themed page. Items without a `solution:` render a placeholder and
are reported as gaps, so backfill is trackable.

## Artifacts and secrets

`compile` writes into the artifacts directory (`--out`, default `./artifacts`):

```
artifacts/
  authoring.key             Ed25519 seed, 0600 (generated if not supplied)
  manifest.signed.json      signed manifest (public)
  rubric.json               honor only
  engine_record.json        ranked cache-seed upload (the engine also parses
                            boxes/ sources itself)
  authoring_public_key.b64  ships on the box to verify the manifest signature
  agent.pyz                 the agent artifact
  nakon-config.json         theme-expanded build input (absent with --no-bundle)
  build-state.json          resumability, input fingerprint, and the
                            manifest/key hashes `verify` checks lineage against
```

The bundle lives under `<nakon-dir>/bundles/`, recorded by path in
`build-state.json`; `install` also stages `agent_config.json`, `.score.dat`
(honor: the obfuscated rubric) and `huitzilopochtli-motd.sh` here first.

**Secrets.** `artifacts/` is gitignored and holds the authoring key, which signs
manifests for any box trusting the matching public key. The directory is `0700`;
the key, rubric, engine record and generated agent config are `0600`; the
transient deploy config is deleted after `plant`. Never commit it, never copy it
to shared media, and treat generated answer keys the same way.

## Verify and seal

The two steps between "installed" and "shipped" are mechanical, so they are
subcommands rather than prose:

```bash
python3 -m boxbuilder verify --spec boxes/<box>/box.yaml --mode ranked \
  --provider-host <box> --competition --for-seal
python3 -m boxbuilder seal-prepare --spec boxes/<box>/box.yaml --mode ranked \
  --provider-host <box> --competition --yes
```

`verify` compares the box against the build: the files the install placed, the
manifest and authoring-key hashes `compile` recorded, `agent_config.json`
against the target, unit/timer state (stopped for a competition template),
recent journal crashes, the report snapshot and expected total, the theme
artifacts for a real user, and — where `xwd` is available — a framebuffer
capture that proves the desktop paints. `--for-seal` adds seal hygiene (no
per-player identity, no legacy install dir, a non-empty machine-id to wipe).

`skip` results are not failures: they mean the target cannot answer that
question (Windows has no journald or `/etc/machine-id`; a headless image has no
X display). `warn` is advisory. Only `fail` exits non-zero.

`seal-prepare` runs `verify` first and refuses on failure (`--skip-verify`
overrides), then does the destructive cleanup and prints the manifest/key
hashes to record with the template. The remaining steps — delete the snapshot,
clean shutdown, convert to a template, rename — are hypervisor operations; see
`DEPLOY.md`.

## Deployment

`boxbuilder` plants and installs over ssh — the only provider in v1 (a running
box reached over SSH with paramiko). Its `export()` is deliberately manual: a
remote box cannot snapshot itself, so `package` returns `mode: "manual"` plus
hypervisor instructions for exporting it.

Promoting a built box to a reusable template (clone → snapshot → deploy →
verify → seal) is a separate manual loop, documented once in
[DEPLOY.md](DEPLOY.md). Deployment supplies every environment-specific value at
invoke time — provider host, provider password, engine URL — via the flags or
`HUITZILOPOCHTLI_*` variables above; never commit a host, password, VMID, bridge
or engine address, and never put one in `box.yaml`.

## Tests

```bash
pytest tests/unit/test_boxbuilder_*.py tests/integration/boxbuilder/
```

Unit tests cover spec parsing, keys, nakon wrappers, per-mode artifacts,
theming, the provider registry, answer keys and per-box compile; integration
tests drive `plant` / `install` / `package` / `build` with a fake provider and
nakon, and exercise the ranked engine client against the real engine server.

## Out of scope

- **No vuln→check registry** — you author both halves; `lint` only proves they
  still agree.
- **Engine co-location** — ranked boxes need a separate running engine; an
  "engine-on-box" ranked variant is not supported.
- **Multi-box / multi-team ranges** and **self-exporting ssh** — boxbuilder
  targets single practice boxes, packaged manually from the hypervisor.
