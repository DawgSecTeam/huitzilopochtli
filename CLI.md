# CLI reference

Two command surfaces: `huitz`, the on-box terminal console, and `boxbuilder`, the author/build tooling.

## `huitz`

`huitz` renders the same grade as the Desktop `report.html` from the same `report.json` snapshot. Nothing in `score`, `watch`, `readme`, or `forensics` re-scores the box; only `grade` does (honor mode, as root).

| Command | What it does |
|---|---|
| `huitz score` | One-shot scorecard. `--json` prints the raw snapshot. Pages through `$PAGER` (then `less -R`, then `more`) only when the board is taller than the terminal; `--no-pager` forbids it. |
| `huitz watch` | Live frame: 1 s countdown tick, redraw on each new grade, terminal bell plus a session change-log on score changes seen while watching; `q` quits. `--once` renders one frame. A re-grade/check-in more than ~2 minutes late is called overdue instead of waiting silently. |
| `huitz readme` | The scenario handbook embedded in the signed manifest, typeset to the terminal width and paged by default; errors when the scenario ships none. `--raw` prints the markdown flat; `--no-pager` disables the pager. |
| `huitz forensics` | List the scenario's questions, your recorded answers, and last-grade verdicts. |
| `huitz forensics N` | Answer question N interactively (Enter keeps, `-` clears). |
| `huitz forensics N "text"` | Answer question N directly. |
| `huitz grade` | Re-grade now, then show the scorecard. Privileged, honor only; ranked boxes refuse and point at the engine. `--config PATH` selects a non-default `agent_config.json`; `--quiet` prints one summary line. |
| `huitz join` | Ranked competition only: sign a `/join` with the box key and bind this box to a player slot. `--code CODE` for scripted joins, `--no-start` to enroll without starting the agent unit, `--config PATH` for a non-default config. |
| `huitz help` | Usage (also `-h`, `--help`). |

Flags shared by reading commands: `--report PATH` (or `$HUITZ_REPORT`) pins a snapshot; `--color auto|always|never` overrides detection (`NO_COLOR` is always honored). `--answers PATH` (forensics) overrides the answers file the snapshot names. Paging never engages on a non-interactive stream, so piped output is byte-identical to a plain print. `--config PATH` (or `$HUITZ_CONFIG`) pins a config for `grade`/`join`.

### Snapshot discovery

`huitz` reads the first snapshot it finds:

1. `--report PATH` or `$HUITZ_REPORT` — authoritative, no fallback. A directory selects `report.json`; an `.html` path selects its sibling.
2. This box's install-dir `report.json`, resolved through `agent_config.json` (root reaches the sealed dir directly).
3. Your own `Documents/huitzilopochtli/report.json`, then the legacy `Desktop/report.json`; on Windows the Public profile is searched first.
4. Another real user's mirror (uid 1000–59999 and a login shell), so an SSH session as root sees the same grade the desktop user sees.

A missing snapshot says how to produce one; a corrupt or newer-version snapshot is reported verbatim, never misrendered.

### Presentation

- **Honor** is positive-only: fixed vulnerabilities, incurred penalties, and forensics state are named; failed checks stay anonymous (a count only). The snapshot carries no per-check results list, so `cat`/`jq` on the Desktop copy spoils exactly as little as the HTML.
- **Ranked** is the engine's diagnostic view: per-check results, SLA state, live rank, and the "engine's authoritative score" label. Check reasons are the box's own evidence reasons — the rubric never shipped here. Before the first engine response, `score`/`watch` say *submitted — awaiting engine*.

`agent/board.py` derives the board once; the HTML report, `report.json`, and the terminal all render from it. `agent/snapshot.py` owns the versioned snapshot format (`snapshot_version` 1, newer majors refused).

### Forensics answers

`huitz forensics N "text"` edits only the targeted `Answer:` line of the answers file, preserving ownership and permissions and recreating a missing template without clobbering existing answers. The next timer tick picks the change up; no restart is needed.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | runtime failure (no snapshot, unreadable manifest, …) |
| `2` | usage error (unknown command/flag, missing value) |
| `130` | interrupted (`Ctrl-C`) |
| `141` | output pipe closed (`huitz score | head`) |

### Installation

boxbuilder's install step copies the zipapp to `/usr/local/bin/huitz` (`install -m 755`; a copy, not a symlink, because the install dir is sealed `0700`) and plants a first-login banner under `/etc/update-motd.d/`. If the copy is skipped, the box still grades; add the shim by hand:

```bash
sudo install -m 755 /opt/.huitzilopochtli/agent.pyz /usr/local/bin/huitz
```

Windows boxes have no shim; run the zipapp directly (`py C:\ProgramData\huitzilopochtli\agent.pyz score`). The zipapp enables VT processing and reads the Public Documents snapshot the scheduled task mirrors.

## `boxbuilder`

`python3 -m boxbuilder <command>`. Every command accepts `--json`: one JSON line on stdout, progress/logs on stderr. See [`boxbuilder/README.md`](boxbuilder/README.md) for authoring detail and [`boxbuilder/DEPLOY.md`](boxbuilder/DEPLOY.md) for the deploy/template loop.

| Command | Purpose and flags |
|---|---|
| `compile` | Compile the scenario, build `agent.pyz`, and build the nakon bundle. `--no-bundle` skips nakon/vulndb for install-only builds. |
| `plant` | Deploy the authored vulns over ssh. `--bundle PATH` overrides the bundle recorded by compile. |
| `install` | Place the agent + manifest (+ honor rubric) and enable the init unit; ranked also uploads the engine record and mints a one-time enrollment token. `--init systemd\|openrc\|none`, `--admin-token`, `--checkin-interval`, `--enrollment-ttl`, `--competition` (no enrollment token; the player binds with `huitz join`). |
| `package` | Export the box image. `--image-out PATH` (required), `--format ova\|qcow2\|raw`. |
| `build` | All four steps with resumability. `--from-step compile\|plant\|install\|package`, `--image-out`, `--format`, plus the `compile`/`install` flags above. |
| `lint` | Cross-check every planted finding against the scored checks (and theme assets). `--all` walks `boxes/*/box.yaml`; or give `--spec` / `--scenario` + `--nakon-config`. `--boxes-dir`, `--mode`. Errors: build inputs that do not validate for either target, missing/duplicate check ids, a primary planted artefact path no check or forensics question reads, a missing theme asset. Warnings: pairings it cannot prove, scored paths under writable data roots that nothing plants, catalog-only configs. |
| `answer-key` | Render authored `solution:` walkthroughs into a post-event handout. `--scenario`, `--out`, `--html`. |

Shared inputs: `--spec FILE`, or `--scenario FILE` with `--nakon-config FILE`. Build target: `--mode honor\|ranked` (default: the scenario's `scenario.mode`). `--engine-url` overrides the env and the scenario for a ranked build. Provider: `--provider ssh`; `--provider-host`, `--provider-port`, `--provider-user`, `--provider-password` fall back to `$HUITZILOPOCHTLI_PROVIDER_{HOST,PORT,USER,PASSWORD}`. Committed specs carry no host or password, and the password is prompted for `plant`/`install` when absent.

Also accepted by the build steps: `--out DIR` (artifacts, default `./artifacts`), `--authoring-key PATH`, `--nakon-dir DIR`, `--vulndb-url URL`. `lint` never invokes nakon.
