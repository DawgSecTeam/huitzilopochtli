# Chocolate-factory redeploy procedure (used for vmid 121, 2026-09-06;
# vmid 108, 2026-09-06 -- a full clone straight from xubuntu-vnc/119
# instead of the current template, see "Gotchas hit on the 108 round"
# below)

How to roll a new `chocolate-factory-template` from the current one.
No `qm`/`pvesh` on the dev host — all Proxmox ops go through the
`proxmoxer` API using `tests/proxmox/.env` (same convention as
`tests/proxmox/proxmox_helper.py`). SSH to the box works from here
(`ubuntu`/`ubuntu` once that account exists -- see the 108-round gotchas if
cloning straight from xubuntu-vnc/119, which has no `ubuntu` account at
all); only the Proxmox API port + guest agent are assumed. Where SSH isn't
usable yet (no `ubuntu` account, or password auth denied for another
reason), the QEMU guest agent's own exec/file-write/file-read API works
identically and needs no login credentials -- see
`tests/proxmox/proxmox_helper.py`'s `guest_exec`/`guest_file_write`.

## 0. Preflight

```bash
export VULNDB_UI_URL=http://10.0.0.118:3000   # NOT set by default; boxbuilder needs it
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
python3 -m boxbuilder compile --spec boxbuilder/examples/chocolate-factory.box.yaml \
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
`boxbuilder/examples/chocolate-factory.box.yaml` (new vmid supersedes old;
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
