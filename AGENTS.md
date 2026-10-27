# AGENTS.md

Guidance for agents (LLM or otherwise) working in this repo.

## What this repo is

**huitzilopochtli** is a security-hardening **scoring engine**. Teams *harden*
target systems; the engine collects evidence and produces a scored report. It
scores **correct hardening** — it does *not* deploy vulnerabilities. Two modes:
**honor** (offline, box scores itself) and **ranked** (a central engine
aggregates signed check-ins; rubric stays off-box). See `architecture.md` (the
source of truth) and `README.md`.

The thing that *deploys* vulnerabilities is **nakon**; the vulnerability catalog is
**vulndb-ui** (edited via the **vulndb-cli** client). Both are vendored as **git submodules**
under `vendor/` (`vendor/nakon`, `vendor/vulndb-cli`, pinned to a release). huitzilopochtli's
**boxbuilder** pairs with nakon to create practice boxes, and uses vulndb-cli — not raw HTTP —
to ensure its theme configurations + attachments exist in the catalog. Set them up with
`git submodule update --init --recursive` after clone.

Submodule init only brings tracked files, though — `vendor/nakon/.env` (vulndb DB creds +
`VULNDB_UI_URL`, same shape as `vendor/nakon/.env.example`) is gitignored and must be created
by hand on every machine that runs boxbuilder (boxbuilder runs nakon with `cwd=vendor/nakon`
specifically so it can read this file). `vendor/vulndb-cli` needs no on-disk config, but does
need `VULNDB_UI_URL` exported as a real environment variable (or passed via `--url`) in the
shell running boxbuilder — it otherwise silently falls back to `http://127.0.0.1:3000`.

## Invariants (do not break)

- **Collect/evaluate split.** Checks emit `Evidence` (structured `raw` facts + a
  human `reason`), never verdicts — scoring is a pure function of
  `(evidence, rubric, clock)` (`architecture.md` §2.1, §10).
- **The box never holds the answer key in ranked mode.** `collect_params` and the
  manifest carry what to collect, never expected values (§2.4, §6.1); the rubric
  stays engine-side (§3).
- **The engine serves exactly what `boxes/` holds.** The admin scenario picker
  lists the committed box folder only — the engine parses each
  `boxes/<box>/scenario.yaml` itself (no `engine_record.json` required) and
  keeps one current version per scenario name; creating, starting, or rerunning
  a competition against any other version is refused (competitions migrate
  forward when a version is released, never back-compatible), and versions are
  never rendered in any UI.
- **The box clock is diagnostic-only.** All timed scoring uses the engine's
  receipt clock; never score from box-claimed time (§2.3, §11.3).
- **The adversary is a closed allowlist with no network egress.** No scenario
  can author a callback, structurally — there is no code path for one (§2.7, §12).
- **Ranked competition boxes are a separate lineage.** Honor boxes cannot be
  converted: a competition box is built from a ranked scenario with scored
  services and red-team exposure, carries no rubric/token, and is bound to a
  player by `huitz join`. Do not add an honor→ranked shortcut.
- **Each ranked competition provisions its own workshop pool.** The pool is
  cloned from the ranked template named in the scenario record's `pool:` block
  (`RANKED_COMPETITION.md` §3.1); the engine never picks among the portal's
  pre-existing pools, so a ranked competition can never hand out an honor box.
- **Competition run clocks are per-player** (start at join, fixed duration, no
  pause) and all scoring timestamps remain engine receipt time. Self-reported
  service checks are explicitly not independent uptime verification.

## Building a practice box (the boxbuilder workflow)

`boxbuilder/` automates the four-step workflow: **(1) author** huitz checks +
nakon vuln selection → **(2) plant** vulns via nakon → **(3) install** the
huitz agent + manifest on the box → **(4) package** the box image.

Each box is one directory `boxes/<box>/` with exactly one authored
`scenario.yaml` (the honor base plus an optional top-level `ranked:` block),
its `nakon.json`, and a minimal `box.yaml`. Build it with `--mode ranked` for
the ranked target; an honor build never reads the `ranked:` block, so ranked
content cannot leak into an honor manifest or rubric. `box.yaml` must not carry
a host, password or mode — deployment supplies those. The field list is
canonical in `boxbuilder/README.md`; do not restate it here.

You author **both** halves: the nakon config (which vulns to plant) and the
huitz scenario (which checks verify the hardening). boxbuilder does **not** know
the vuln→check mapping — you must ensure each planted vuln has a check that
awards points for the opposite (hardened) state. `python3 -m boxbuilder lint
--all` is the mechanical half of that discipline: it walks every box and fails
when a build input does not validate, when a check id it needs is missing or
duplicated, when a primary planted artefact path is read by no check (or its
directory, or a forensics question), and when a theme asset is missing. It
warns on the softer cases — a pairing it cannot prove mechanically, a scored
path nothing plants, a configuration that exists only in the remote catalog —
so run it before every deploy and read the warnings. `--catalog` additionally
validates the selection through `nakon catalog check` (needs the nakon checkout
and catalog access).

The handbook (`theme.readme`) is the assignment, not the answer key — write it
to the bar in `HANDBOOK_GUIDE.md`. Compile runs a spoiler lint
(`authoring/readme_lint.py`): forensics answers in the handbook block the
compile, lesser leaks surface as `readme_warnings`.

```bash
# Browse + validate vulns (read-only, agent-safe):
nakon catalog list --json
nakon catalog show ssh-root-login --json      # read exactly what it plants
nakon catalog check --select nginx,ssh-root-login --json

# Author the two files (see boxes/chocolate-factory/ for a worked pairing), then:
python3 -m boxbuilder lint --all              # plant<->check cross-check, every box
python3 -m boxbuilder build --spec box.yaml --image-out box.ova --json
```

Each step is also runnable alone (`compile`/`plant`/`install`/`package`) so you
can verify between steps. `--mode ranked` selects the ranked target of the same
`scenario.yaml`; `compile --no-bundle` builds only the install artifacts, which
is what an install-only ranked template needs when it installs over a box that
is already planted. See `boxbuilder/README.md`.

## Deploying a built box

`boxbuilder` plants + installs over ssh; promoting a build to a reusable
template is a separate manual loop, documented end to end in
`boxbuilder/DEPLOY.md` (clone → snapshot → deploy → verify → seal — the same
moves map onto any hypervisor that can full-clone and snapshot; the doc
assumes no particular vmid, name, address, or account). Clone + snapshot before
deploying, wipe `/etc/machine-id` before sealing, and keep the previous
template until the new one is confirmed in the field.

Deployment supplies every environment-specific value at invoke time, never in
the committed box:

```bash
python3 -m boxbuilder install --spec boxes/<box>/box.yaml --mode ranked \
  --provider-host <box-address> --provider-password '<password>' \
  --engine-url <engine-base-url>
```

`--provider-host` / `--provider-password` fall back to
`$HUITZILOPOCHTLI_PROVIDER_HOST` / `$HUITZILOPOCHTLI_PROVIDER_PASSWORD`
(`..._PROVIDER_USER` / `..._PROVIDER_PORT` too); the ranked engine URL falls
back to `$HUITZILOPOCHTLI_ENGINE_URL`, then to the scenario's `ranked:`
`engine_url`, which is only a loopback placeholder. Never commit a host,
password, VMID, bridge, or engine address — and never put one in `box.yaml`.

## Working in this repo

- **Python 3.10+** (built/tested on 3.14). No `pyproject.toml`; development
  and test dependencies live in `requirements-dev.txt`
  (`pip install -r requirements-dev.txt`). The shipped code stays stdlib-only
  (see the boundary bullet below).
- **Dependency boundaries (hard).** `agent/` + `common/` are stdlib-only
  (vendored Ed25519 is the sole exception); `engine/` adds only stdlib
  `sqlite3` plus PyYAML (the distro `python3-yaml` package on the engine VM) —
  the engine parses `boxes/*/scenario.yaml` itself. `common/` stays stdlib-only
  because the zipapp bundles `agent/` + `common/` and nothing else — a
  third-party import there silently ships breakage to every box. PyYAML is
  also used by `authoring/` + `boxbuilder/` (`paramiko` for the ssh provider,
  `proxmoxer` in `tests/` only).
- **No src-layout.** conftest.py puts the repo root on `sys.path`, so
  `import agent`, `import common`, `import boxbuilder` work everywhere.
- **Layout:** `common/` (shared schema + evaluator + crypto), `agent/` (on-box
  collector, ships as `.pyz`), `engine/` (ranked-mode server), `authoring/`
  (scenario compile + sign), `packaging/` (zipapp build + init units + re-arm),
  `boxbuilder/` (the practice-box factory).
- **Tests:** `pytest` runs unit + integration (Proxmox tier is deselected by
  default; opt in with `pytest -m proxmox` — it is a live tier whose targets
  and credentials come from the gitignored `tests/proxmox/.env`, never from
  committed code or docs). The ranked suites take ~3min — that's the vendored
  Ed25519 (~seconds per sign/verify), not a hang.
  boxbuilder tests: `tests/unit/test_boxbuilder_*.py` and
  `tests/integration/boxbuilder/`. Hands-on walkthrough: `TESTING_GUIDE.md`;
  ranked-mode coverage matrix (what is covered, known defects, backlog):
  `RANKED_TESTING.md`; tier details: `tests/README.md`;
  install layout: `packaging/README.md`.
- **`artifacts/` is gitignored and holds secrets** (authoring key, rubric) —
  never commit it, never copy it onto shared media.
- **nakon discipline:** `catalog list/show/check --json` are read-only and
  agent-safe; `build`/`deploy` mutate. boxbuilder shells out to nakon and
  `vulndb-cli`, never imports them. Scenario extras (`theme:`, `forensics:`,
  `solution:` walkthroughs for the `answer-key` handout generator) and the
  `--json` stdout/stderr contract are documented in `boxbuilder/README.md` —
  link, don't duplicate.
- **`architecture.md` is authoritative.** Where it and intuition disagree,
  follow the doc or raise the conflict.
