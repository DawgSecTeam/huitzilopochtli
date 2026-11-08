#!/usr/bin/env python3
"""Operator teardown for a competition's workshop pool.

    python3 -m engine.cleanup --slug broadneck-six2 [--dry-run]
    python3 -m engine.cleanup --all-ended [--dry-run]

This is the fallback for a competition whose End path was interrupted (an
engine redeploy between End and cleanup, a crash, or a portal restart). It
uses the same ``claims.cleanup_pool`` the sweeper uses: release claimed VMs,
destroy every clone belonging to *that* pool (exact pool code, or the portal's
``<pool name>-<digits>`` student id -- never a slug prefix, so ending ``demo``
cannot destroy ``demo-2``'s boxes), delete the pool, and clear the pin only
when a fresh listing is empty.

``--all-ended`` is the multi-event recovery command: it sweeps every ended
competition that still holds a pool pin, which is what a crash during a day of
back-to-back events leaves behind.
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
    ap.add_argument("--slug", help="competition slug to tear down")
    ap.add_argument("--all-ended", action="store_true",
                    help="every ended competition that still holds a pool pin")
    ap.add_argument("--db", default=os.environ.get(
        "HUITZILOPOCHTLI_DB_PATH", DEFAULT_DB))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    if not args.slug and not args.all_ended:
        ap.error("give --slug <slug> or --all-ended")

    store = Store(args.db)
    if args.slug:
        comp = store.get_competition_by_slug(args.slug)
        if comp is None:
            print(json.dumps({"ok": False,
                              "error": f"no competition {args.slug!r}"}))
            return 1
        # Single-competition shape is unchanged for existing operators/scripts.
        if args.dry_run:
            print(json.dumps({
                "ok": True, "dry_run": True, "slug": comp.slug,
                "status": comp.status, "pool": comp.workshop_pool_code,
                "pool_name": claims.pool_name_for(comp),
                "players": [p.display_name for p in store.list_players(comp.id)],
            }))
            return 0
        stats = claims.cleanup_pool(store, comp)
        print(json.dumps({"ok": True, "slug": comp.slug, **stats}))
        return 0
    targets = [c for c in store.list_competitions()
               if c.status == "ended" and c.workshop_pool_code]
    if not targets:
        print(json.dumps({"ok": True, "competitions": [],
                          "note": "nothing to clean"}))
        return 0
    if args.dry_run:
        print(json.dumps({
            "ok": True, "dry_run": True,
            "competitions": [
                {"slug": c.slug, "status": c.status,
                 "pool": c.workshop_pool_code,
                 "pool_name": claims.pool_name_for(c),
                 "players": [p.display_name for p in store.list_players(c.id)]}
                for c in targets],
        }))
        return 0
    results = []
    for comp in targets:
        stats = claims.cleanup_pool(store, comp)
        results.append({"slug": comp.slug, **stats})
    # A legacy shared pool is left untouched by design (the pin is cleared),
    # so only a still-running destroy job makes the sweep "not finished".
    ok = all(not r.get("destroy_pending") for r in results)
    print(json.dumps({"ok": ok, "competitions": results}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
