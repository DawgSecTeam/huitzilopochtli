# Promoting a built box to a VM template

How to take a box that `boxbuilder` has built and promote it into a reusable
hypervisor template, in five moves: full clone → boot → snapshot →
compile/plant/install → verify → seal.

The commands below use Proxmox VE (`qm`); the same moves map to any hypervisor
that can full-clone a template and snapshot it (see the last section). Nothing
here assumes a particular vmid, name, address, or account — substitute every
`<placeholder>`.

Clone first because the template you clone from must stay untouched and
bootable: deploy damage lands on the clone, and the snapshot turns a bad
plant/install into a rollback instead of another full clone.

## Preconditions

- **`VULNDB_UI_URL` is exported** in the shell that runs `boxbuilder`. Themed
  scenarios and bundled vuln seeds reach vulndb-ui during `compile`; without it
  they fall back to a localhost default and fail or hit the wrong catalog.
- **`vendor/nakon/.env` exists.** It holds the DB credentials and
  `VULNDB_UI_URL`; it is gitignored and must be created by hand from
  `vendor/nakon/.env.example` (`boxbuilder` runs nakon with `cwd=vendor/nakon`
  so nakon can read it). Run `git submodule update --init --recursive` first.
- **The box's tests and cross-checks are green:**
  `python3 -m pytest tests/unit/test_boxbuilder_<box>.py -q && python3 -m boxbuilder lint --all`.
- **You know exactly what is uncommitted, and the clone is reachable.**
  Uncommitted scenario/theme/nakon changes *are* the deploy — `boxbuilder`
  reads the working tree, not `HEAD`. Check `git status` and
  `git diff boxes/<box>/`; confirm every change is intended (no debug check, no
  disabled check, no stray asset). Don't stash them, but be able to recreate
  them. The clone needs the guest agent and an admin account the ssh provider
  can use.

## Step 1 — Clone and snapshot before deploying

Full clone, not linked: a linked clone pins its parent, and a promoted template
must stand on its own. Boot it, wait for the guest agent, find its address.

```bash
qm clone <template-vmid> <new-vmid> --name <clone-name> --full && qm start <new-vmid>

# Wait for the guest agent, then read the clone's address:
until qm guest cmd <new-vmid> ping >/dev/null 2>&1; do sleep 5; done
qm guest cmd <new-vmid> network-get-interfaces
```

Take the snapshot **before any deploy**, from a clean guest state:

```bash
qm shutdown <new-vmid>          # wait for "stopped"
qm snapshot <new-vmid> pre-deploy-clean --description "clean clone before deploy"
qm start <new-vmid>
```

`pre-deploy-clean` is the rollback point for the whole deploy cycle: if `plant`
or `install` goes wrong, `qm rollback <new-vmid> pre-deploy-clean` and retry
instead of cloning again. Re-wait for the agent and address after the restart —
DHCP may hand out another.

A fresh clone's address comes from DHCP and **changes per clone**: never bake it
into a committed spec — pass it with `--provider-host` or
`$HUITZILOPOCHTLI_PROVIDER_HOST`, or an uncommitted temp spec.

## Step 2 — Deploy

Compile from the real spec, then plant and install against the clone's address.
Keep the password in the environment so it stays out of process lists and
shell history.

```bash
export VULNDB_UI_URL=<vulndb-url>
export HUITZILOPOCHTLI_PROVIDER_PASSWORD=<provider-password>

python3 -m boxbuilder compile --spec boxes/<box>/box.yaml \
  --out /tmp/<box>-build --json

python3 -m boxbuilder plant --spec boxes/<box>/box.yaml \
  --out /tmp/<box>-build --provider-host <clone-ip> --json

python3 -m boxbuilder install --spec boxes/<box>/box.yaml \
  --out /tmp/<box>-build --provider-host <clone-ip> --json
```

- **Compile from the box's own spec path**: theme assets (wallpaper, README,
  logo) resolve relative to the spec's directory, so a `/tmp` copy breaks them.
- **`plant` is idempotent.** Re-run it after fixing a catalog configuration or
  planting script — no rollback needed, except for damage a re-run cannot heal.
- **`install` replaces the on-box install dir unconditionally**, so no rubric,
  identity, enrollment marker, or report from an earlier build survives.
- **Compile fingerprints its inputs**; `plant`/`install` refuse a state file
  from different inputs, so after editing the scenario or nakon config re-run
  `compile`, not just the later steps.
- **Provider flags** override the spec (`--provider-host`, `--provider-user`,
  `--provider-port`, `--provider-password`); without one, boxbuilder prompts.

Ranked and competition templates: compile and install with the same
`--mode ranked --engine-url <engine-url>` — mode and engine URL are part of the
state fingerprint, so a ranked `install` against an honor `compile` is refused.
Prefer `$HUITZILOPOCHTLI_ADMIN_TOKEN` over `--admin-token` (the flag is visible
in process lists and shell history); `--competition` skips the enrollment token
and leaves the unit disabled until the player runs `huitz join`.

```bash
export HUITZILOPOCHTLI_ADMIN_TOKEN=<admin-token>
python3 -m boxbuilder compile --spec boxes/<box>/box.yaml \
  --out /tmp/<box>-build --mode ranked --engine-url <engine-url> --json
python3 -m boxbuilder install --spec boxes/<box>/box.yaml \
  --out /tmp/<box>-build --mode ranked --engine-url <engine-url> \
  --provider-host <clone-ip> --json          # add --competition for a pool template
```

Install-only builds: if the base image already carries the planted
vulnerabilities (a ranked template installed over an already-planted honor
seal), compile with `--no-bundle` — no nakon bundle, no nakon/vulndb, and only
`install` runs against the clone.

## Step 3 — Verify

Everything must hold **before** sealing, or the defect ships to every clone.
`boxbuilder verify` runs the checklist against the live box and exits non-zero
on a failure:

```bash
python3 -m boxbuilder verify --spec boxes/<box>/box.yaml --mode <honor|ranked> \
  --provider-host <clone-ip> --for-seal --json
# a ranked competition template:
python3 -m boxbuilder verify --spec boxes/<box>/box.yaml --mode ranked \
  --provider-host <clone-ip> --competition --for-seal
```

It checks, in one pass:

| Check | Meaning |
|---|---|
| `install.files` / `install.rubric` | the install is complete; honor carries `.score.dat`, ranked carries no rubric at all |
| `lineage.manifest` / `lineage.key` | the on-box manifest and authoring public key hash to what `compile` recorded in `build-state.json` — the box is running the build you tested |
| `config.mode` / `config.engine` / `config.token` | `agent_config.json` matches the target; a competition box has no enrollment token |
| `init.state` / `init.timer` | the unit is active (honor/ranked) or installed-but-stopped (competition); honor has its re-grade timer, ranked has none |
| `agent.journal` | no traceback or unhandled exception in the last 200 lines |
| `report.state` / `report.mirror` | a valid snapshot with the expected total (`--expect-total`, default 0 for honor), and the Documents mirror exists |
| `theme.wallpaper` / `theme.readme` / `theme.shortcuts` | the scenario's theme actually landed for a real user |
| `desktop.renders` | `xwd` capture of the live X root window is non-trivial (see below) |
| `seal.machine-id` / `seal.identity` / `seal.legacy-dir` | `--for-seal` hygiene |

`skip` means "not measurable on this box" (no `xwd`, no journal, Windows without
the POSIX probes) and does not fail the run; `warn` does not either. Fix every
`fail` before sealing.

**Cross-checks worth understanding, because they are the ones a green-tick
can miss:**

- **The desktop actually renders.** `xwd` capture bypasses the VNC/console
  layer: a live cursor over a black framebuffer still produces a tiny, uniform
  image. If `desktop.renders` is skipped, run the capture by hand and look for
  a multi-megabyte file with many distinct byte values.
- **Launchers are trusted and resolve.** Open one from the desktop: a
  "Untrusted application launcher" dialog or a `$HOME` that did not expand is a
  theme failure even though the file exists.
- **The report is the pre-hardening baseline.** Score 0 (honor) and a total
  equal to the scenario's full point count; forensics card present if authored.

## Step 4 — Seal

```bash
# 1. Purge per-player state and neutralize the box (runs verify first).
python3 -m boxbuilder seal-prepare --spec boxes/<box>/box.yaml --mode <honor|ranked> \
  --provider-host <clone-ip> --competition --yes

# 2. Drop the snapshot: conversion refuses a VM that still has snapshots.
qm snapshot <new-vmid> pre-deploy-clean --del

# 3. Clean shutdown, then convert and rename.
qm shutdown <new-vmid>          # wait for "stopped"
qm template <new-vmid>
qm set <new-vmid> --name <template-name>
```

`seal-prepare` stops and disables the unit (or the Windows scheduled task),
removes `identity.json`, enrollment markers, report snapshots and per-user
mirrors, deletes a legacy `/opt/huitzilopochtli`, truncates `/etc/machine-id`
to 0 bytes, and prints the lineage hashes to record with the template. It is
idempotent and refuses to run unless verification passes (`--skip-verify`
overrides that, deliberately). Windows skips the machine-id step and disables
the scheduled task instead.

- **Delete the snapshot first.** Templates cannot carry snapshots, and rolling
  back after a green verify would throw away the good state.
- **Empty `/etc/machine-id` on purpose.** A sealed non-empty ID is copied into
  every clone, so they share one identity and collide on DHCP. `seal-prepare`
  wipes it and reports the resulting size; confirm 0 before shutdown.
- **Conversion is near-irreversible.** `qm template` turns the backing disk
  into a read-only base; clearing the template flag afterwards looks like it
  works but leaves the disk read-only and the VM will not start. There is no
  supported in-place edit: full-clone the template, edit the clone, re-seal it.
- **Keep the previous template until the new one is field-confirmed.** Boot a
  fresh clone of the new template and run Step 3; only then does the old
  template stop being the fallback. Destroy it after the last clone or claim
  referencing it is gone.
- **Record the lineage.** The template's manifest is signed by one authoring
  key. `seal-prepare` prints that key's hash (and the manifest hash); store
  them with the template so a later rebuild can prove which key it descends
  from, and back the private key up — `artifacts/` is gitignored, and without
  it the lineage can be verified but never re-signed.

## Windows differences

- **`verify` covers less on Windows**: the guest has no journald, no
  `/etc/machine-id` and no X root window, so those checks report `skip`. The
  install, lineage, config and scheduled-task state are still checked.
- **Guest agent exec** is convenient but not guaranteed: some Windows images
  cannot `guest-exec`. Keep an out-of-band bootstrap (set an admin password via
  the agent, bring up OpenSSH, stage the Python installer), then prefer SSH.
  Bake OpenSSH, Python, and the guest agent into the template during prep —
  they cannot be installed per-clone.
- **Scheduled task, not systemd.** The agent runs from a SYSTEM task at startup
  and on a repeating interval; check with `schtasks /query /tn <task-name> /v`
  that the last result is 0 and the next run advances. The task's repetition
  interval *is* the re-grade cadence — change one only with the other.
- **Install dir under `C:\ProgramData`**, ACL-sealed to SYSTEM and
  Administrators. The player-facing answers file lives on the Public Desktop
  and must stay writable by Users; re-check both ACLs on the clone.
- **Sealing**: no machine-id to wipe. Delete the snapshot, shut down cleanly
  (`shutdown /s` — a hard stop sets the dirty bit and shows every clone the
  Shutdown Event Tracker modal), then convert and rename. Strip build-only
  shared folders and grants; whatever ACLs and shares remain are baked in.
- **Domain controllers**: authentication can fail or reset for the first
  minutes after boot while AD initialises. Wait with bounded, spaced retries
  and make checks fail closed during the window; never loop credentials. Shut
  a DC down before cloning it — a live clone rolls AD back to its checkpoint.

## If you are not on Proxmox

The same sequence maps onto a qcow2/libvirt workflow:

```bash
qemu-img convert -O qcow2 <base>.qcow2 <clone>.qcow2   # full copy, not a backing-file overlay
qemu-img snapshot -c pre-deploy-clean <clone>.qcow2
# boot, deploy with --provider-host <clone-ip>, run the Step 3 checks
qemu-img snapshot -d pre-deploy-clean <clone>.qcow2
virt-sysprep -a <clone>.qcow2        # empties /etc/machine-id, host keys, logs, udev rules
```

Rules that carry over: promote a full copy (an overlay pins its base); snapshot
and seal a shut-down image, not a running one; delete the snapshot before
publishing; run `virt-sysprep` with the image unused; and keep the previous
base until a clone of the new one passes the checklist. `virt-sysprep
--list-operations` shows what the seal removes — review it, don't assume.
