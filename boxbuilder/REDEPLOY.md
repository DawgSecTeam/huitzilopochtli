# Chocolate-factory redeploy procedure (used for vmid 121, 2026-09-06;
# vmid 108, 2026-09-06 -- a full clone straight from xubuntu-vnc/119
# instead of the current template, see "Gotchas hit on the 108 round"
# below)

How to roll a new `chocolate-factory-template` from the current one.
No `qm`/`pvesh` on the dev host — all Proxmox ops go through the
`proxmoxer` API using `tests/proxmox/.env` (same convention as
`tests/proxmox/proxmox_helper.py`). SSH to the box
works from here
(`ubuntu`/`ubuntu` once that account exists -- see the 108-round gotchas if
cloning straight from xubuntu-vnc/119, which has no `ubuntu` account at
all); only the Proxmox API port + guest agent are assumed. Where SSH isn't
usable yet (no `ubuntu` account, or password auth denied for another
reason), the QEMU guest agent's own exec/file-write/file-read API works
identically and needs no login credentials -- see
`tests/proxmox/proxmox_helper.py`'s `guest_exec`/`guest_file_write`.
This loop is Linux/xubuntu-shaped; for the Windows round's differences
(cloning 903, qemu-ga limits, the VNC-console traps, schtasks/ProgramData
layout, Windows seal notes) see the "Windows round" section at the bottom.

## 0. Preflight

```bash
export VULNDB_UI_URL=http://10.0.0.119:3000   # NOT set by default; boxbuilder needs it (VM115 "vulndb"; was 10.0.0.118 until the IP drifted Sept 2026 -- confirm before assuming)
# vendor/nakon/.env must exist (gitignored, vulndb DB creds + VULNDB_UI_URL)
git status          # note uncommitted scenario changes — they ARE the deploy
python3 -m pytest tests/unit/test_boxbuilder_chocolate_factory.py -q
```

## 1. Full-clone the current template, boot, snapshot BEFORE deploy

```python
# nextid = px.cluster.nextid.get()   # 121 for this round
px.nodes(n).qemu(134).clone.post(newid=121, name='chocolate-factory-candidate', full=1)
# full clone of 15G takes ~15-20 min; poll the task UPID to completion
px.nodes(n).qemu(121).status.start.post()
wait_for_agent(px, 121); ip = wait_for_ip(px, 121)   # DHCP; WILL differ per clone
ssh ubuntu@<ip> 'cat /etc/machine-id'                # must be non-empty + unique per clone
px.nodes(n).qemu(121).status.shutdown.post()         # wait for stopped
px.nodes(n).qemu(121).snapshot.post(snapname='pre-deploy-clean',
    description='clean full-clone of 134 before boxbuilder build')
px.nodes(n).qemu(121).status.start.post()            # re-wait agent + IP
```

The snapshot protects the *deploy cycle*: a bad `plant`/`install` is
`shutdown → rollback → start` instead of another 20-min full clone.
`qm template` refuses VMs with snapshots (and rolling back after a green
verify would nuke the good state), so **delete the snapshot before sealing**.

## 2. Deploy

Compile with the REAL spec (theme wallpaper/readme resolve relative to the
spec's dir — a `/tmp` spec copy breaks with "theme.wallpaper ... not found"):

```bash
python3 -m boxbuilder compile --spec boxes/chocolate-factory/box.yaml \
  --out /tmp/choc --rebuild-bundle --json        # --rebuild-bundle after any catalog change
# plant/install need provider.host = the clone's CURRENT DHCP IP; use a temp
# spec with absolute scenario/nakon_config paths + host overridden (do NOT
# commit the DHCP IP into the example spec):
python3 -m boxbuilder plant   --spec /tmp/choc.box.yaml --out /tmp/choc --json
python3 -m boxbuilder install --spec /tmp/choc.box.yaml --out /tmp/choc --json
```

`plant` is idempotent — safe to re-run after a catalog/script fix without
rolling back (done twice for 121: once for the initial deploy, once after
the theme-readme catalog fix below).

Re-deploying a box installed by a pre-2026-09-09 boxbuilder? The install
now targets `/opt/.huitzilopochtli` (hidden, sealed 0700, rubric encoded
as `.score.dat`); the old plain `/opt/huitzilopochtli` dir is left
orphaned but inert — the re-installed systemd units point at the new dir.
`rm -rf /opt/huitzilopochtli` on the candidate before sealing so the
template ships without the stale answer key lying around in plaintext.

## 3. Verify (all must hold; reference: 121 @ 10.0.0.217)

- `xfce4-desktop.xml` (sysadmin): `screen0` ×1, `monitorVirtual-1` present,
  `workspace0..3`, wallpaper `<sha>-…-wallpaper.png`
- `/usr/local/share/huitzilopochtli-theme/*.png` ~13K
- `report.html`: `Total: 0`, `0 of 20`, Forensics card; `~/Desktop/report.html` synced
- Desktops contain exactly: `Forensics-Questions.txt`, 2 `nakon-theme-*.desktop`,
  `README.html`, `report.html` (+ planted `vault-code.txt` on sysadmin)
- Handbook `Exec=sh -c 'xdg-open $HOME/Desktop/README.html'` resolves
- `huitzilopochtli-agent.timer` active; journal shows `Started → Deactivated
  successfully` every minute with no Traceback since deploy
- `DISPLAY=:0 xwd -root` ~4.0M; `/etc/machine-id` unique (template stays empty)

## 4. Seal

```python
px.nodes(n).qemu(121).snapshot('pre-deploy-clean').delete()  # required: template + snapshots conflict
# Wipe machine-id so the template carries it EMPTY (systemd generates a fresh
# ID per clone at first boot — sealing with a fixed ID bakes one ID into every
# future clone and reproduces the DHCP-collision bug; vmid 121 shipped this
# defect, fixed from 125 on). Safe on the running box: only affects next boot.
# Run over SSH BEFORE shutdown:
#   sudo sh -c 'rm -f /etc/machine-id && touch /etc/machine-id'; wc -c /etc/machine-id  # expect 0
px.nodes(n).qemu(121).status.shutdown.post()                 # wait stopped
px.nodes(n).qemu(121).template.post()                        # converts disk to read-only base
px.nodes(n).qemu(121).config.put(name='chocolate-factory-template')
```

Then update the header comment in
`boxes/chocolate-factory/box.yaml` (new vmid supersedes old;
keep the previous template as fallback until the new one is confirmed).
`package` via the ssh provider returns `manual` — expected; sealing IS the export.

## Gotchas hit on the 121 round (do not re-learn)

1. **Box is Python 3.12, dev is 3.14.** `agent/collector.py`'s
   `_DaemonThreadPoolExecutor` mirrored 3.14's `_adjust_thread_count`
   (`_create_worker_context` — an *instance* attr since 3.14) and crashed
   every agent run on the box. Fixed version-tolerant (`hasattr` probe,
   3.12 fallback passes `(ref, queue, initializer, initargs)`).
2. **Catalog configs are create-if-missing.** `theme-readme` (id 119) still
   held the pre-`59fd4f9` script (writes `README.md`, cosmetic forensics)
   while the repo seed writes `README.html` — deploy silently produced a
   stale `README.md` (HTML bytes, wrong name) and a broken Handbook shortcut.
   Fixed with `vulndb-cli update --yes --file
   boxbuilder/vulndb_theme_configs/theme-readme.json 119` (attachments
   preserved), then `compile --rebuild-bundle` (scripts bake into the bundle
   at build time) + re-`plant`. Same pattern as the earlier id-118 wallpaper fix.
3. Stale `README.md` duplicates were deleted from both Desktops before sealing.

## Gotchas hit on the 108 round (do not re-learn)

This round cloned straight from `xubuntu-vnc` (119) instead of the current
template, because 121 and 125 were both already sealed templates with their
`pre-deploy-clean` snapshot already deleted (`qm template` requires that) --
there was nothing left to revert/redeploy in place on either, so both were
destroyed and 108 was cloned fresh from 119. If a template chain is still
mid-cycle (candidate VM exists, snapshot intact), reverting that snapshot
and redeploying on it directly is cheaper than a fresh full clone --
check `snapshot.get()` on the current template's vmid before assuming a
fresh clone is needed.

1. **119 has no `ubuntu` account.** Only `sysadmin` (the exercise/VNC login)
   exists on a fresh xubuntu-vnc clone. boxbuilder's ssh provider needs a
   separate account with a password that works for both SSH login and
   `sudo -S` (see `boxbuilder/providers/ssh.py`) -- created by hand before
   `plant`/`install`:
   ```
   useradd -m -s /bin/bash ubuntu && echo 'ubuntu:ubuntu' | chpasswd && usermod -aG sudo ubuntu
   ```
   run over the guest agent (`guest_exec`), since SSH itself isn't usable
   yet without this account.
2. **`fix-xubuntu-vnc-display.sh`'s belt 2/3 xfconf writes silently never
   applied when lightdm autologin had already started a real session by the
   time the script ran** (the normal case -- autologin fires immediately at
   boot, well before the guest agent is even reachable to push/run this
   script). The script used `dbus-launch --exit-with-session` to fabricate
   a throwaway D-Bus bus per write; that bus is unrelated to the already-
   running session's real bus at `/run/user/<uid>/bus`, so the write went
   to a disposable xfconfd instance the live session never saw, and
   `2>/dev/null || true` swallowed the failure. Net effect: reproduced the
   exact "solid black screen" bug the script exists to fix -- confirmed by
   sampling the raw `xwd -root` framebuffer (every pixel byte was `0`) and
   by `xwininfo -root -tree` showing `xfce4-screensaver`'s window at the
   full screen size (`1280x800+0+0`) instead of the normal 10x10 tray-icon
   placeholder. Fixed by preferring the real per-user bus
   (`/run/user/<uid>/bus`, present whenever that user actually has a
   session) and only falling back to `dbus-launch` when no session has
   started yet; also added an explicit `xfce4-screensaver-command
   --deactivate` since disabling idle-activation only stops *future*
   triggers; it doesn't dismiss a screensaver that already painted itself
   in before the script ran. Verified by re-running the fixed script, then
   a full reboot from cold, then re-sampling the framebuffer (256 distinct
   byte values, real desktop content) before sealing.
3. Within one VM, `/etc/machine-id` regenerates to the *same* value every
   time it's wiped and rebooted (Proxmox/qemu's SMBIOS UUID is a
   deterministic seed for systemd's fallback generator when no other
   entropy source is available at early boot) -- expected, not a sign the
   wipe-before-seal step failed. The uniqueness this whole exercise
   protects only shows up *across clones* (different SMBIOS UUIDs), which
   single-VM testing can't exercise; trust the wipe, don't expect the
   in-VM value to change on its own reboot.
4. The seal step's Proxmox calls (`shutdown` + snapshot `delete` + `qemu
   .template.post()` + rename, bundled together) got blocked by the
   session's auto-mode safety classifier even after in-conversation
   approval -- expected, this is a harness-level gate independent of chat
   approval for a bundle this destructive/irreversible. Worked around by
   having the user run the same script directly (`!python3 <script>`)
   instead of Claude executing it.

## Windows round (pinecrest-hospital, 2026-09-12/13) -- procedure differences + gotchas

The first Windows round deploys a box from the team's windows templates.
Template 903 (`workshop-template-windows`, Windows 10 Pro for Workstations
22H2) was tried first and ABANDONED for headless builds: its clones have no
SSH out of the box and the guest agent can't exec (gotcha 2), so there was no
way in. The round actually sealed from `windows-server-fix` (vmid 953), which
ships OpenSSH Server already -- bootstrap is just `agent/set-user-password`
over the API, then SSH. The Proxmox `ostype` field says `win11`, which is
only a hint. Everything in sections 0/2-4 above still applies (compile/plant/
install are OS-agnostic once SSH exists); the differences are clone bring-up,
prep, and the agent's on-box shape (schtasks instead of systemd,
`C:\ProgramData\huitzilopochtli` instead of `/opt/.huitzilopochtli`, Public
Desktop instead of `$HOME/Desktop`). Check types: `registry_value` +
`powershell_json` are Windows-first; `user_group`/`process_state`/
`service_state`/`file_regex`/`permission` all work with Windows collect
params. Sealed 2026-09-13 as vmid 1111 `pinecrest-hospital-template`
(0 -> 360 -> 0 validated on the sealing VM before `qm template`).

1. **Clone + rebridge.** Full-clone 903 like any template, then put the
   clone on vmbr0 (903 ships on `untrustedbr,firewall=1`). Two API traps:
   the `net0=virtio=BC:24:...` shorthand PUTs fail ("duplicate key ... model")
   or silently drop the bridge when set on a RUNNING vm -- stop the VM, PUT
   `net0=model=virtio,bridge=vmbr0,firewall=0`, verify the config reads back
   with the bridge, then start. Task polling: read `status` ("running") and
   `exitstatus` ("OK") from the task endpoint -- there is no `running` bool.
   Also, `POST .../qemu/<vmid>/start` 404s on this PVE build; the route is
   `POST .../qemu/<vmid>/status/start`. A 32G full clone takes ~35 min.
2. **qemu-ga on Windows: what works and what's broken.** `set-user-password`
   and `network-get-interfaces` work over the API and are the reliable
   bootstrap (set `sysadmin`'s password with the former; get the DHCP IP with
   the latter). **`guest-exec` is broken on this lineage**: every spawn
   returns "Failed to execute child process (Invalid argument)" -- bare
   `cmd`, absolute paths, forward slashes, after clean reboots, always. The
   Linux habit of bootstrapping via `guest_exec` (see the 108-round gotcha)
   does NOT transfer; don't burn an hour rediscovering this. If a Windows
   clone ever needs headless exec again, the fix is host-side (`qm guest
   exec` was proven on this very template per nakon's PROGRESS.md, so suspect
   the API path + old virtio-win agent; upgrading qemu-ga in the template
   would be the real fix). Note the agent process itself can die mid-session
   -- after a failed exec storm it stopped answering until a full VM reboot.
3. **PVE VNC console over the API is nearly unusable for automation; plan
   around it.** `vncproxy` + `vncwebsocket` works (auth: the per-session
   `password` from vncproxy answers the VNC challenge -- DES with each key
   byte's bits REVERSED; the ws needs subprotocol `binary`), but the proxy
   closes the session ~2-4s after the guest screen starts producing real
   update volume (any logon-screen activity), and the console display blanks
   itself after ~60s idle so screenshots read black. What works: input-only
   "burst" connections (send keystrokes, close within ~0.7s, before the kill
   lands -- the keys still reach the guest), and screenshots via
   hextile-only encodings at 16bpp RGB565 in ~200-row band requests on fresh
   connections (each response stays under the ~1.1MB where the proxy chokes;
   raw 32bpp full-screen frames always die). The throwaway tooling lives in
   `/home/hna/huitz-backups/2026-09-12-windows-box/` (`vnc.py`, `bridge.py`,
   `gexec.py` -- not repo material). Lesson: don't build the round on console
   automation; get SSH first.
4. **OpenSSH bring-up (the prep step that must happen before boxbuilder).**
   Once SSH exists, everything else is standard:
   `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Set-Service
   sshd -StartupType Automatic; Start-Service sshd; New-NetFirewallRule -Name
   sshdin -Enabled True -Direction Inbound -Protocol TCP -Action Allow
   -LocalPort 22`. The firewall rule matters beyond prep: the box SCORES
   "firewall enabled on all profiles", so after hardening the firewall comes
   back on and the sshd rule is what keeps the build reachable. SSH sessions
   for a local admin land elevated (no UAC filtering over sshd) -- the
   elevated-token assumption boxbuilder's Windows provider path relies on.
5. **Python on the box.** The ssh provider requires `python` on PATH and
   cannot install it remotely (no apt on Windows). SFTP the python.org
   installer and run it silently: `python-installer.exe /quiet
   InstallAllUsers=1 PrependPath=1` (installer pre-staged in the backup dir).
   Do this during template prep so clones inherit it -- NOT per-clone.
6. **boxbuilder on a Windows target.** `provider:` is the same ssh provider
   (no `os` key needed -- the provider detects Windows via `echo %OS%` over
   the session); `nakon.json`'s machine needs `"os": "windows-*"` (any value
   containing "win" routes nakon to its PowerShell deploy path and boxbuilder
   to the `-win` theme seeds). plant runs nakon's Windows path (run.ps1,
   per-step scripts, elevation from the SSH principal). install places the
   agent in `C:\ProgramData\huitzilopochtli` (icacls-sealed to
   SYSTEM+Administrators) and registers the `HuitzilopochtliAgent` scheduled
   task (SYSTEM, at startup + every 5 min) -- that task IS the honor-mode
   re-grade timer, the analog of the systemd timer pairing. Forensics: the
   agent resolves the answers file to `C:\Users\Public\Desktop\
   Forensics-Questions.txt` on Windows automatically (`_primary_desktop_dir`
   has a win32 branch); an explicit `path:` in scenario.yaml still wins if
   you prefer it spelled out.
7. **Windows seal notes.** No `/etc/machine-id` equivalent to wipe (Windows
   clones don't collide the way systemd boxes do); snapshot-delete before
   `qm template` applies unchanged. The seed catalog ids for this round are
   140-156 (`*-win` configs on vulndb 10.0.0.119); `nakon catalog check
   --config boxes/pinecrest-hospital/nakon.json --json` must stay green, and
   remember seeds are create-if-missing -- editing a repo seed does NOT
   update the catalog row (same trap as gotcha #2 on the 121 round).
8. **Never put a raw `powershell -Command "..."` one-liner over the ssh
   provider.** Windows OpenSSH execs commands through cmd.exe, which strips
   the inner double quotes -- the pipeline's very first Windows install
   attempt died with `'Out-Null' is not recognized as an internal or
   external command`. Everything PowerShell now routes through
   `SshHandle.run_ps` (`-EncodedCommand`, base64 UTF-16LE -- nothing for
   cmd to mangle, and errors promoted to exit 1 + stderr). If you add a
   remote PowerShell step, use run_ps; never concatenate a quoted
   `-Command` string.
9. **The nakon PowerShell rc trailer bites twice over.** The trailer
   (render_step_ps1) treats a non-empty `$Error` as failure even when the
   step's real work succeeded: `Get-Service -ErrorAction SilentlyContinue`
   on a not-yet-existing service records an error, and a plant step that
   then creates that service fine still reports rc=1 (malicious-service-win
   failed five rounds on exactly this). Use `-ErrorAction Ignore`, never
   `SilentlyContinue`, in any `-win` seed script.
10. **The 953 image's account APIs are inconsistent; know which one to
   trust.** `Get-LocalUser`'s `.PasswordNeverExpires` reads NULL for every
   account (a check keyed on it passes vacuously in ANY state) -- read
   `Win32_UserAccount.PasswordExpires` over CIM instead (false = never
   expires). `.PasswordRequired` is real but is NOT flipped by
   `Set-LocalUser -Password`: on this image the fix path for the
   blank-password vuln is `net user <u> /passwordreq:yes` (setting a
   password alone leaves the flag false). And `net accounts` here prints
   `Minimum password length:` WITHOUT the `(chars)` suffix other builds
   use -- check regexes must tolerate both forms.
11. **QEMU wedge recovery (no host shell needed).** Mid-round the sealing
   VM went dark on the network while PVE still said "running"; QMP and qga
   were both dead. `POST .../status/stop` still worked (~60s), the first
   `status/start` failed with "timeout waiting on systemd", and the retry
   started instantly with no disk-state loss. Don't reach for host SSH on
   the first wedge -- stop/start through the API, and if start fails once,
   just fire it again.
12. **The plant does not restore image-default state on revert.** After the
   harden->revert loop the Print Spooler stayed stopped+disabled (my
   hardening did that; no seed plants it) and silently awarded 2 checks in
   the "0" state. Whatever the scenario scores, the revert pass must
   restore by hand if no seed sets it -- for this box: `Set-Service Spooler
   -StartupType Automatic; Start-Service Spooler`, and re-run `plant` after
   deleting any account a seed must recreate EXACTLY (audit_svc's
   blank-password state required Remove-LocalUser + re-plant, since the
   seed's update path never removes a password).
13. **A Windows box with assets but no `theme:` block ships with an empty
   Desktop.** The first seal had assets/ (README.md, wallpaper, logo)
   authored but no `theme:` block in scenario.yaml -- resolve_theme_configurations
   returned [], so no theme steps ran and players got no README, wallpaper,
   or Scoring Report shortcut (only the task-mirrored report.html). The
   theme block goes in scenario.yaml (spec.theme reads the SCENARIO, not
   box.yaml); for a Windows target it needs title/accent/logo/wallpaper/
   readme and boxbuilder resolves the -win seeds automatically. Also
   remember a /tmp spec copy breaks theme asset resolution (gotcha in
   section 2) -- compile from the real box.yaml.
14. **The Windows re-grade cadence and the report countdown are coupled.**
   The schtask fires every 5 minutes and `agent/__main__.py::
   _honor_interval_s()` anchors the report countdown to 300s on win32
   (Task Scheduler repetition granularity bottoms out at 1 minute, so the
   POSIX 70s cadence is unexpressible). With the old 70s anchor the report
   read "00:00 -- checking..." for ~4 of every 5 minutes, which players
   read as "the scoring engine isn't updating" even though the task was
   firing. If you ever change the task's /ri or RepetitionInterval, change
   _honor_interval_s to match.
15. **Re-seal loop (2026-09-14) proved the schtask survives cloning.** A
   raw linked clone of the sealed template, booted and left untouched,
   fires the inherited task on its 5-minute cadence (LastRunTime advances,
   report.html rewrites, LastTaskResult 0) -- no reinstall needed. The
   re-seal procedure: fix-forward on a linked clone (plant + install with
   the updated bundle), full-clone THAT to the template vmid, boot-verify
   (Desktop README + shortcut present, report countdown ~5:00, task
   LastRunTime advancing untouched), then shutdown -> qm template -> rename.
   Template RAM raised to 6144 MB in the same pass (2 cores / 4 GB made
   the agent's CIM sweeps crawl during play).
16. **Rogue accounts are scored DISABLED, not deleted (Hamza, 2026-09-14).**
   `mharding`/`jweaver` award points only when the account exists AND
   `Win32_UserAccount.Disabled` is true -- deleting the account scores
   nothing for those checks (deleted evidence is what the forensics
   questions need). The GROUP checks still scrub memberships either way
   (deleting a rogue user legitimately empties their group entries), so a
   deleting team earns group points but loses the account points; the
   README tells players to disable + scrub groups. Restoring the planted
   state after a deletion test is re-plant (seed create path) + a manual
   `net user mharding /active:yes` -- the seed's update path never touches
   the Enabled flag.

## AD round (meridian-hq, 2026-09-21) -- promoting a base template to a DC

17. **953's local admin is `Administrator`, not `sysadmin`.** The pinecrest
   prep created `sysadmin` in ITS sealed template (1111), never in 953 -- so
   `agent/set-user-password` for sysadmin fails with "The user name could not
   be found". Set Administrator's password instead. Also: the proxmoxer
   default timeout is 5s and `set-user-password` routinely takes longer on a
   busy first boot -- build the client with `timeout=90` or the call times out
   client-side while still running guest-side, and each wedged call takes the
   qga channel down with it ("QEMU guest agent is not running" until the
   service recovers). First boot after the full clone still took ~35 min
   before the agent answered at all.
18. **953 does NOT ship Python on PATH.** The pinecrest round's
   `python-installer.exe /quiet InstallAllUsers=1 PrependPath=1` went into
   their sealed template, not 953. Base-template prep for any 953 clone must
   SFTP the installer (pre-staged in the 2026-09-12 backup dir) and run it
   before boxbuilder will connect (`connect()` gates on `python --version`).
19. **Promoting to a DC erases the local SAM -- plan the way back in.** After
   `Install-ADDSForest` there are no local accounts, so SSH as the old local
   admin dies. The meridian flow registers a SYSTEM scheduled task
   (`MeridianDomainPrep`, `ONSTART`) BEFORE promoting; it waits for ADWS,
   then creates the domain `sysadmin` (Domain Admins), three staff users in
   an OU, sets NIC DNS to 127.0.0.1, and unregisters itself. Belt and
   suspenders: the new forest's built-in `Administrator` password IS the
   DSRM password, so `administrator` + DSRM also gets in.
20. **New-ADUser creates the account DISABLED when the password violates
   complexity -- and display-name tokens count.** `MeridianBuild2026!` for a
   user with display name `Meridian IT` fails: "Meridian" is a display-name
   token longer than two characters, so the password is rejected, the account
   lands disabled, and everything downstream (SSH auth resets mid-handshake!)
   mysteriously breaks. Fix: keep tokens like the org name out of passwords,
   or change the display name (`IT Operations`), then
   `Set-ADAccountPassword -Reset` + `Enable-ADAccount`. Watch for this in any
   seed that sets a password containing a name fragment.
21. **Sealing a DC base template.** RDP ships disabled on this Server image
   (`fDenyTSConnections=1`): set it to 0 + NLA (`UserAuthentication=1`) and
   enable the `RemoteDesktop-UserMode-In-*` firewall rules during prep, or
   players get no RDP once the scored firewall state comes back on. The
   sealed template (vmid 112 `meridian-dc-base-template`) carries Python
   3.12, OpenSSH, RDP/NLA, DNS@127.0.0.1, sysadmin + staff, firewall all-on,
   LDAP signing default. Concurrent clones re-animate the same DC identity
   (same machine SID/krbtgt) -- fine in this isolated lab because every
   clone is a self-contained single-DC forest with no replication partners
   and its own DNS; document but don't fight it.

22. **AD scoring flake #1 -- the DC's auth path rejects VALID credentials
   for the first minutes after boot** (observed on fresh clones: an LDAP
   bind with the correct planted password fails with auth-flavored errors
   until AD finishes starting, so any "old password must stop working"
   check fake-passes at first boot and the clone scores 20/390 for a few
   minutes). Fix: gate credential-validation checks on
   `Win32_OperatingSystem.LastBootUpTime` (meridian-hq uses >= 8 minutes)
   and use `System.DirectoryServices.AccountManagement.PrincipalContext.
   ValidateCredentials` for the bind -- the raw
   `DirectoryEntry.Properties[...]` path throws
   "Cannot index into a null array" once the DC hardens LDAP signing.
   The check must fail closed when the DC isn't up; the 5-minute task
   cadence re-scores, so early-boot noise never sticks.
23. **AD scoring flake #2 -- secedit snapshots re-assert themselves.**
   `weak-password-policy-win` round-trips secedit (export -> edit ->
   configure); on a DC that writes a LOCAL policy store snapshot, and
   background security-policy processing re-asserts it later -- silently
   reverting bare `reg add` hardening of values captured in that snapshot
   (LDAPServerIntegrity flipped 2 -> 1 twice during the same session). Any
   hardening that must survive the workshop has to go through the policy
   store (secpol.msc / secedit with the same INF line -- note the INF
   value form is `LDAPServerIntegrity=4,<value>`; a partial replace leaves
   a dangling `,1` that secedit silently ignores) or the GPO. Solution
   texts steer students the same way.
24. **Never live-clone a domain controller.** A running DC keeps AD
   transactions in memory/EDB logs; a clone taken while the source runs
   rolls NTDS.dit back to the last checkpoint -- the seal clone silently
   lost an `Enable-ADAccount` from 7 minutes before cloning (phantom +5
   stale-computer score) even though the source verified 0. Shut the
   source down gracefully FIRST, clone, then boot. (Also explains
   "it reverted!" mysteries around any clone of a busy Windows box.)
25. **A template sealed after a hard stop makes every clone pop a modal
   at logon.** The clone's first logon raises the **Shutdown Event
   Tracker** ("Why did the computer shut down unexpectedly?" -- comment
   REQUIRED). It is a modal: Start menu, search, everything appears dead
   while it is up (this is exactly the "Start menu doesn't open" report
   from the live round -- the shell was fine). Seal with a guest-side
   `shutdown /s /d p:4:1` (clean disk, no dirty bit), and belt-and-braces
   disable the tracker:
   `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability\ShutdownReasonOn=0`
   (+ `ShutdownReasonUI=0`). Server Manager also auto-opens at logon and
   carries a Windows Admin Center promo popup; `DoNotOpenAtLogon=1` under
   `HKCU\Software\Microsoft\ServerManager` set over an SSH session did
   NOT survive sealing (ssh HKCU writes are unreliable for this) -- set
   it in `C:\Users\Default\NTUSER.DAT` (reg load/unload) next seal.
26. **The python MSI self-repair dialog is a scoring-killer trap.** The
   python.org install's Start-menu shortcuts are advertised MSI entry
   points; on these clones opening the Start menu can fire MSI
   self-repair, which pops "Another program called 'C:\Program' ... Would
   you like to rename it?" -- because the quote-mangled install root IS
   `C:\Program`. Clicking **Rename** renames the python home away; the
   agent's PATH and the py-launcher registry then point at nothing and
   scoring silently dies (the task script exits 0 regardless -- a frozen
   report that looks fine). Two boxes died this way on 2026-09-21. Fix in
   the sealed template: `msiexec /faus <product-code> /qn` for every
   Python product, then delete
   `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12`.
   Defense in depth: the win task script now falls back to
   `C:\Program\python.exe` / `C:\Program1\python.exe` when PATH is dead.
   Recovery for an affected box: repoint machine PATH + the
   `HKLM\SOFTWARE\Python\PythonCore\3.12\InstallPath` registry value at
   wherever python.exe actually lives, restart the task.
27. **pmx full-clones may land on the wrong bridge.** The 2026-09-22
   meridian re-seal's full clone came up on `untrustedbr` (firewall=1)
   while the source template is on vmbr0 -- check `net0` after cloning
   and `pmx rebridge <vmid> --bridge vmbr0 --yes` before installing.
   (The student-portal dispenser uses untrustedbr on purpose for claim
   isolation; a BUILD box on it is unreachable for the provider.)
28. **Forensics answers must be student-writable on Windows.** The agent
   runs as SYSTEM; `os.chmod` cannot express NTFS ACLs, so the answers
   file shipped with only inherited INTERACTIVE:ReadAndExecute -- and a
   UAC-filtered RDP logon of the admin account has no Administrators
   ACE, so students literally could not save answers. The agent now
   grants `BUILTIN\Users:M` via icacls on write (agent/__main__.py), and
   `packaging/huitz-agent-task.ps1` re-grants it every cycle (heals
   already-sealed boxes too). The README names the real path
   (`C:\Users\Public\Desktop\Forensics-Questions.txt`) because students
   look in their own profile folder first.
29. **Template replacement with live claims = rename + pool cutover.**
   Linked claim clones pin the old template, so you cannot destroy and
   re-create it in place. Full-clone -> fix -> `pmx template` the NEW
   vmid -> rename old to `*-template-old` -> rename new to the canonical
   name -> flip `template_vm_id` in the portal's configs.json (sed; one
   occurrence; validate JSON after; no restart needed) -> destroy the
   old template only when its last claim dies.
