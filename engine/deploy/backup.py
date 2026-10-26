#!/usr/bin/env python3
"""Consistent SQLite backup for the huitzilopochtli engine."""
import datetime
import os
import sqlite3

DB = os.environ.get("HUITZILOPOCHTLI_DB_PATH", "/var/lib/huitzilopochtli/engine.db")
OUT = os.environ.get("HUITZILOPOCHTLI_BACKUP_DIR", "/var/backups/huitzilopochtli")
KEEP = int(os.environ.get("HUITZILOPOCHTLI_BACKUP_KEEP", "14"))


def main() -> None:
    os.makedirs(OUT, mode=0o700, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(OUT, f"engine-{stamp}.db")
    src = sqlite3.connect(DB)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.chmod(dest, 0o600)
    # Verify the copy opens and has the expected core tables.
    check = sqlite3.connect(dest)
    try:
        names = {r[0] for r in check.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        check.close()
    required = {"boxes", "checkins", "scores", "competitions", "players"}
    missing = required - names
    if missing:
        raise SystemExit(f"backup verification failed: missing {sorted(missing)}")
    backups = sorted(
        (os.path.join(OUT, f) for f in os.listdir(OUT) if f.startswith("engine-")),
        key=os.path.getmtime,
    )
    for old in backups[:-KEEP]:
        try:
            os.unlink(old)
        except OSError:
            pass
    print(f"backup ok: {dest}")


if __name__ == "__main__":
    main()
