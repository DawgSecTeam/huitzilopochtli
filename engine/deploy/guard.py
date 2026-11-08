#!/usr/bin/env python3
"""Refuse an engine code deploy while a competition is live.

The six-player field showed why: an engine redeploy mid-run replaced the code
between End and pool cleanup, leaving seven clones and a pool pin behind.
install.sh pipes the local /health body through this guard before copying
anything. ``HUITZ_DEPLOY_FORCE=1`` is the explicit operator override.
"""
import json
import os
import sys


def live_count(payload) -> int:
    try:
        data = json.loads(payload) if isinstance(payload, str) else payload
        value = int((data or {}).get("live", 0))
    except (ValueError, TypeError, AttributeError):
        return 0
    return max(0, value)


def live_names(payload) -> list:
    """Names of the live competitions, when /health listed them."""
    try:
        data = json.loads(payload) if isinstance(payload, str) else payload
        rows = (data or {}).get("live_competitions") or []
        names = [r.get("name") or r.get("slug") for r in rows if isinstance(r, dict)]
        return [str(n) for n in names if n]
    except (ValueError, TypeError, AttributeError):
        return []


def _describe(names: list) -> str:
    if not names:
        return ""
    shown = ", ".join(names[:5])
    more = f" (+{len(names) - 5} more)" if len(names) > 5 else ""
    return f" ({shown}{more})"


def main(argv=None) -> int:
    raw = sys.stdin.read() if not (argv and len(argv) > 1) else argv[1]
    live = live_count(raw)
    names = _describe(live_names(raw))
    forced = os.environ.get("HUITZ_DEPLOY_FORCE", "") == "1"
    if live and not forced:
        sys.stderr.write(
            f"refusing to deploy: {live} live competition(s) are running"
            f"{names}; end them first or set HUITZ_DEPLOY_FORCE=1\n")
        return 1
    if live:
        sys.stderr.write(
            f"WARNING: deploying with {live} live competition(s){names} "
            "because HUITZ_DEPLOY_FORCE=1\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
