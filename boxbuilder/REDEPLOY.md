# Chocolate-factory redeploy procedure (used for vmid 121, 2026-09-06)

How to roll a new `chocolate-factory-template` from the current one.
No `qm`/`pvesh` on the dev host — all Proxmox ops go through the
`proxmoxer` API using `tests/proxmox/.env` (same convention as
`tests/proxmox/proxmox_helper.py`). SSH to the box works from here
(`ubuntu`/`ubuntu`); only the Proxmox API port + guest agent are assumed.

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
