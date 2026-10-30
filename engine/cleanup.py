#!/usr/bin/env python3
"""Operator teardown for one competition's workshop pool.

    python3 -m engine.cleanup --slug broadneck-six2 [--dry-run]

This is the fallback for a competition whose End path was interrupted (an
engine redeploy between End and cleanup, a crash, or a portal restart). It
uses the same ``claims.cleanup_pool`` the sweeper uses: release claimed VMs,
destroy every pool clone by student_id/pool code, delete the pool, and clear
the pin only when a fresh listing is empty.
"""
import argparse
import json
import os
import sys

from engine import claims
from engine.store import Store

DEFAULT_DB = "/var/lib/huitzilopochtli/engine.db"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug", required=True)
    ap.add_argument("--db", default=os.environ.get(
        "HUITZILOPOCHTLI_DB_PATH", DEFAULT_DB))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    store = Store(args.db)
    comp = store.get_competition_by_slug(args.slug)
    if comp is None:
        print(json.dumps({"ok": False, "error": f"no competition {args.slug!r}"}))
        return 1
    if args.dry_run:
        print(json.dumps({
            "ok": True, "dry_run": True, "slug": comp.slug,
            "status": comp.status, "pool": comp.workshop_pool_code,
            "players": [p.display_name for p in store.list_players(comp.id)],
        }))
        return 0
    stats = claims.cleanup_pool(store, comp)
    print(json.dumps({"ok": True, "slug": comp.slug, **stats}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
