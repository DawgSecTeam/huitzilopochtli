# Template prep (Windows Server registry-persistence box)

Cinder Ridge Credit Union is a Windows honor box: 20 hardening checks across
the registry/logon persistence surface, plus 6 forensics questions. What
TEMPLATE PREP bakes in before any nakon plant (see `boxbuilder/DEPLOY.md` for
the full build loop) is the clean Windows Server base plus one standard user
whose hive the HKCU findings live in.

Everything environment-specific stays out of this directory. The box's address
and the provider login are supplied at deploy time as `--provider-host` /
`--provider-password` (or `$HUITZILOPOCHTLI_PROVIDER_*`); they are never
committed here.

## Base image

The workshop's Windows Server base template — the same lineage
`pinecrest-hospital` and `harborline-transit` clone from. Clone it, prep the
clone, snapshot only when prep is complete, then full-clone the snapshot for
each re-seal so a bad build never costs the prep round.

## Prep round (as Administrator on the clone)

1. **Python 3.12** — the python.org bootstrapper wedges on this image, so
   install the embeddable build at `C:\Python312` and drop a
   `C:\Windows\System32\python.cmd` shim. agent checks that shell out to
   `python` depend on it.
2. **SSH** — install OpenSSH Server, keep password auth on, and start the
   service; boxbuilder plants and installs over ssh.
3. **Local admin** — `New-LocalUser sysadmin` rather than `net user`, which
   prompts past 14 characters; then `net user sysadmin /passwordreq:yes`.
   Use a throwaway password for the build clone and pass the same value to
   `--provider-password`; `HUITZILOPOCHTLI_INSECURE_HOST_KEYS=1` is expected
   here because these clones are disposable.
4. **RDP/NLA on** — the box is handed out over RDP.
5. **`teller1`** — create the standard (non-admin) user, log in once so its
   profile and `NTUSER.DAT` exist, log off, and leave the account enabled.
   The HKCU Run/RunOnce findings are planted there, so the hive must exist
   before planting.
6. **Network** — move `net0` to the workshop bridge with `firewall=1` and set
   `balloon=2048`; the box is untrusted and reaches nothing.
7. **Snapshot** — only after every step above, and before planting.

## Re-seal order (planted-clean baseline)

Plant, install (honor), reset the forensics answer file to its blank template,
verify 0, snapshot, harden to full marks, roll back, verify 0 again, then drop
the snapshots and seal. Keep the previous template until the new one is
confirmed in the field.

## HKCU hive handling (why the collectors copy)

The first seal ran the HKCU checks in parallel, all against the same
`HKU\HuitzCheck` mount. One check could unload the hive while another was
reading it (false pass), and a leaked mount locked `NTUSER.DAT` so a later
check errored. Each HKCU check now loads a **unique per-run copy** of its hive
and reads it with native `reg.exe query`, so scoring never locks the original
file; the scripts also take a global hive-access mutex.

Ordering that matters elsewhere in the check set: Defender policy-before-
preference, and shell-quoting of the `reg` values (an earlier round mangled
quotes and scored a planted value as absent).

## Planting (`nakon.json`) — order and name discipline

`os: windows-server` puts nakon on its PowerShell deploy path (SSH transport,
Windows OpenSSH, `run.ps1` per step); elevation comes from the SSH principal,
which is why `sysadmin` must be a local admin.

Order is load-bearing. `defender-off-win` runs **first** so the staging
directory is excluded and the engine stays quiet while the later payload files
are written; the run-key and service-key families follow; the logon/loader
seeds and the remaining baseline misconfigurations come last.

Every `SERVICE_NAME` / `VALUE_NAME` / `PAYLOAD_PATH` / `GUID` in `nakon.json`
must match its paired check's `collect` params in `scenario.yaml`
**byte-for-byte** — nothing cross-validates them, and `boxbuilder lint` only
catches the primary path keys.

HKCU targets: the two `registry-run-key-win` steps with `USERNAME=teller1` load
that user's `NTUSER.DAT`, so prep must create `teller1`, log in once, and leave
the account enabled. The HKCU steps without `USERNAME` target the SSH
principal's own hive (`sysadmin`), which is also the player's RDP account.

The `service-key-persistence-win` modes `imagepath` and `unquoted` need
`LEGIT_PATH` to exist; the seed copies `svchost.exe` there if it does not. The
seed creates DEMAND-START services only — nothing runs at boot, so the box
stays stable and the finding is the registry key. AppInit registers a **text**
placeholder rather than a PE on purpose: the registration is the finding and
the loader silently fails.

Re-grading runs as SYSTEM via the `HuitzilopochtliAgent` scheduled task every
five minutes.

## Validation on the sealed template

- Planted baseline: 0 / 20 checks + 0 / 6 forensics, repeated three times.
- Scripted harden: 300 / 300 (20 of 20 + 6 of 6).
- Rollback re-verified at 0.
