#!/usr/bin/env python3
"""Re-arm/reset a provisioned box. See architecture.md §17:

    "a documented reset path resets local state (seq, identity optional,
    cached score, report) so a take-home box can be replayed without a
    full redeploy."

Usage (run ON the box, as the same user/root that owns the install dir):

    python3 rearm.py [install_dir] [--config CONFIG] [--reset-identity]

    install_dir   defaults to /opt/dawgscore
    --config      path to agent_config.json, defaults to
                  <install_dir>/agent_config.json
    --reset-identity  ALSO delete the ranked-mode identity file (and its
                  transport queue file). Opt-in and off by default: an
                  identity reset generates a brand-new box_id + Ed25519
                  keypair and resets last_seq to 0 (see
                  agent/identity.py load_or_create). That is a much
                  bigger action than "let me retry this take-home
                  session" -- it effectively re-enrolls the box as a
                  new entity from the engine's point of view. Re-arming
                  for a retry within the same session/box normally
                  should NOT rotate identity, so identity reset is
                  opt-in via this flag rather than the default.

This script is stdlib-only and imports agent.config (pure stdlib) to
resolve the real report/identity paths from the box's own config
rather than hardcoding filenames -- so it stays correct even if a
scenario's config points paths somewhere nonstandard.
"""
import argparse
import os
import sys

# Allow running this script directly from packaging/ on a box where the
# repo (or at least agent/+common/) is laid out next to it, OR from an
# install dir that only has the .pyz (see README: rearm.py is a plain
# stdlib script, not itself part of the zipapp, so it needs `agent` and
# `common` importable -- easiest is to run it via the same interpreter
# with the .pyz on sys.path, or just from a repo checkout).
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import agent.config  # noqa: E402


def _maybe_remove(path: str) -> bool:
    """Remove `path` if it exists. Returns whether it was removed."""
    if path and os.path.exists(path):
        os.remove(path)
        return True
    return False


def rearm(install_dir: str, config_path: str, reset_identity: bool) -> list:
    """Perform the reset, returning a list of human-readable action strings."""
    actions = []

    config = agent.config.load_config(config_path)

    if _maybe_remove(config.report_path):
        actions.append(f"removed cached report: {config.report_path}")
    else:
        actions.append(f"no cached report to remove at: {config.report_path}")

    if reset_identity:
        if config.identity_path:
            queue_path = config.identity_path + ".queue"
            if _maybe_remove(config.identity_path):
                actions.append(f"removed identity file: {config.identity_path}")
            else:
                actions.append(
                    f"no identity file to remove at: {config.identity_path}"
                )
            if _maybe_remove(queue_path):
                actions.append(f"removed queued check-in bundles: {queue_path}")
            else:
                actions.append(f"no queued check-in bundles at: {queue_path}")
        else:
            actions.append(
                "--reset-identity given but config has no identity_path "
                "(honor mode has none); nothing to do"
            )
    else:
        if config.identity_path:
            actions.append(
                f"preserved identity/seq (not touching {config.identity_path}); "
                "pass --reset-identity to also rotate box identity"
            )

    return actions


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reset local DAWGSCORE agent state for a take-home box."
    )
    parser.add_argument(
        "install_dir",
        nargs="?",
        default="/opt/dawgscore",
        help="install directory (default: /opt/dawgscore)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="path to agent_config.json (default: <install_dir>/agent_config.json)",
    )
    parser.add_argument(
        "--reset-identity",
        action="store_true",
        help="also delete the ranked-mode identity file and its queue "
        "(generates a new box identity on next run); off by default",
    )
    args = parser.parse_args()

    config_path = args.config or os.path.join(args.install_dir, "agent_config.json")

    actions = rearm(args.install_dir, config_path, args.reset_identity)
    for action in actions:
        print(action)


if __name__ == "__main__":
    main()
