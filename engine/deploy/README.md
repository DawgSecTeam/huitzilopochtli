# Engine deployment

Build a versioned bundle on the dev host:

```bash
python3 packaging/build_engine_bundle.py dist/huitzilopochtli-engine.tar.gz
```

On an Ubuntu/Debian engine VM, as root:

```bash
mkdir -p /tmp/huitz-bundle
tar xzf huitzilopochtli-engine.tar.gz -C /tmp/huitz-bundle
HUITZ_ADMIN_PASSWORD='...' HUITZ_PUBLIC_URL='http://10.0.0.160:8080' \
  bash /tmp/huitz-bundle/engine/deploy/install.sh
```

The installer creates:

- `/opt/huitzilopochtli/engine/{common,engine,deploy}`
- `/etc/huitzilopochtli/engine.env` (0600)
- `/var/lib/huitzilopochtli/engine.db` (0600)
- `/var/backups/huitzilopochtli/`
- `huitzilopochtli-engine.service` + `huitzilopochtli-backup.timer`

Generated admin credentials are written to
`/root/huitz-engine-credentials.txt` (0600). Change them in `engine.env` and
restart the service.

`install.sh` is idempotent for code-only upgrades: it re-copies the bundle,
keeps an existing `engine.env`, and restarts the unit.

To upgrade a running engine: build a new tarball, extract to `/tmp`, copy
`common/` and `engine/` into `/opt/huitzilopochtli/engine/`, copy
`engine/deploy/` to `/opt/huitzilopochtli/engine/deploy/`, then
`systemctl restart huitzilopochtli-engine`.

Backups run daily at 03:15 and keep 14. Run one now with
`systemctl start huitzilopochtli-backup.service`.
