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
#    See boxbuilder/examples/ for a worked pairing.

# 3. Author a box spec tying them together:
#    boxbuilder/examples/linux-fundamentals.box.yaml

# 4. Build the box (all four steps, resumable):
python3 -m boxbuilder build \
  --spec boxbuilder/examples/linux-fundamentals.box.yaml \
  --image-out /tmp/linux-fundamentals.ova --json
```

Each step is also runnable on its own (see CLI below) so you can pause/verify
between steps.

## The two inputs you author

### 1. nakon config (which vulns to plant)

A nakon machine list. Each entry's `configurations` names vulndb catalog entries
that, when deployed, make the box insecure in specific ways. Browse with
`nakon catalog list --json`; validate a selection with
`nakon catalog check --config <file> --json`. See `boxbuilder/examples/nakon-config.json`.

The `ip`/`user`/`password` are **placeholders** — at deploy time boxbuilder
overwrites them with the provider's address (so the box spec is the single source
of truth for where the box is). v1 is single-box; the first machine is targeted.

### 2. huitz scenario (which checks score the hardening)

A standard huitzilopochtli scenario YAML (same shape `authoring/compile.py`
consumes). Each check awards points for correctly hardening what a planted vuln
broke. Mode (`honor`/`ranked`) and `engine_url` live here. See
`boxbuilder/examples/linux-fundamentals.scenario.yaml` and `architecture.md` §8.

### The box spec (ties them together)

```yaml
scenario: ./linux-fundamentals.scenario.yaml
nakon_config: ./nakon-config.json
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
consistent with tezcatlipoca and nakon's documented embed contract
(nakon/README.md §"Embedding"). It shells out:

- `nakon build --json` (cwd = `$NAKON_DIR`, so nakon can read its `.env`/vulndb)
  → parses `{bundle_id, path, cached, plans, machines}` from the final stdout line.
- `nakon deploy --json` → parses `{ok, failures, machines[].steps}`.

Set `--nakon-dir` or `$NAKON_DIR` (default: `../nakon`).

## How vulns and checks relate (important)

boxbuilder does **not** pair them for you. When you author a box, you must ensure
each planted vuln has a corresponding check that verifies the hardening — e.g.
`ssh-root-login` (plants `PermitRootLogin yes`) pairs with a `file_regex` check
expecting `PermitRootLogin no`. The worked example in `boxbuilder/examples/`
shows one concrete pairing. An agent authoring a box should:

1. `nakon catalog show <vuln> --json` — read exactly what each vuln plants.
2. Write a check that awards points for the *opposite* (hardened) state.
3. `nakon catalog check` the selection before building.

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
generation, and the provider registry. Integration tests drive `plant`/`install`/
`package`/`build` end-to-end with a FakeProvider + a fake nakon (no real VM,
no real vulndb), and exercise `engine.py` against the **real** engine server.

## Out of scope

- **No vuln→check registry** (by design — agents author both halves).
- **Engine co-location** — ranked boxes need a separate running engine. A
  self-contained "engine-on-box" ranked variant is a future mode.
- **Multi-box / multi-team competitions** — boxbuilder targets single practice
  boxes. tezcatlipoca covers multi-team ranges; boxbuilder is complementary.
- **SshProvider self-export** — returns `manual`; a qemu/proxmox provider will
  make export fully automatic.
