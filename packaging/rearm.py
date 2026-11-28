#!/usr/bin/env python3
"""Re-arm/reset a provisioned box (architecture.md §17): clears local state
so a take-home box replays without a redeploy. Run ON the box:
    python3 rearm.py [install_dir] [--config CONFIG] [--reset-identity]
--reset-identity is opt-in: rotating box_id/keypair/last_seq re-enrolls the
box as a NEW entity at the engine — a far bigger action than a session retry.
"""
import argparse
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import agent.config  # noqa: E402


def _enrolled_marker_path(identity_path: str) -> str:
    """Path of the .enrolled first-boot gate marker, mirroring
    agent/__main__.py's version: rearm must not import the agent runtime."""
    return identity_path + ".enrolled"


def _score_state_path(report_path: str) -> str:
    """Path of the score baseline (agent/notify.py), sibling of the cached
    report. Mirrors agent/notify.py::state_path_for -- same stdlib-only rule
    as above."""
    return os.path.join(
        os.path.dirname(os.path.abspath(report_path)), "score_state.json"
    )


def _snapshot_path(report_path: str) -> str:
    """Path of the machine-readable snapshot (agent/snapshot.py), sibling of
    the cached report. Mirrors snapshot_path_for -- stdlib-only, no agent
    runtime import."""
    return os.path.join(
        os.path.dirname(os.path.abspath(report_path)), "report.json"
    )


def _maybe_remove(path: str) -> bool:
    """Remove `path` if it exists. Returns whether it was removed."""
    if path and os.path.exists(path):
        try:
            os.remove(path)
            return True
        except OSError:
            return False


def _remove_user_mirrors() -> list:
    """Delete the per-user Documents/Desktop report mirrors: the CLI searches
    them first, so a survivor keeps showing the dead session's grade."""
    removed = []
    if os.name == "nt":
        homes = [os.environ.get("PUBLIC", r"C:\Users\Public")]
    else:
        homes = []
        try:
            import pwd
            for entry in pwd.getpwall():
                if 1000 <= entry.pw_uid < 60000:
                    shell = entry.pw_shell or ""
                    if shell.endswith(("/nologin", "/false")):
                        continue
                    homes.append(entry.pw_dir)
        except (ImportError, KeyError):
            pass
    for home in homes:
        for rel in (
            os.path.join("Documents", "huitzilopochtli", "report.html"),
            os.path.join("Documents", "huitzilopochtli", "report.json"),
            os.path.join("Desktop", "report.html"),
            os.path.join("Desktop", "report.json"),
        ):
            path = os.path.join(home, rel)
            if _maybe_remove(path):
                removed.append(path)
    return removed


def rearm(install_dir: str, config_path: str, reset_identity: bool) -> list:
    """Perform the reset, returning a list of human-readable action strings."""
    actions = []

    config = agent.config.load_config(config_path)

    if _maybe_remove(config.report_path):
        actions.append(f"removed cached report: {config.report_path}")
    else:
        actions.append(f"no cached report to remove at: {config.report_path}")

    # The score baseline must go with the report: a replayed session starts
    # silent (no baseline -> no spurious penalty alarm on the first re-grade).
    score_state = _score_state_path(config.report_path)
    if _maybe_remove(score_state):
        actions.append(f"removed score baseline: {score_state}")
    else:
        actions.append(f"no score baseline to remove at: {score_state}")

    snapshot = _snapshot_path(config.report_path)
    if _maybe_remove(snapshot):
        actions.append(f"removed report snapshot: {snapshot}")
    else:
        actions.append(f"no report snapshot to remove at: {snapshot}")

    for removed in _remove_user_mirrors():
        actions.append(f"removed user report mirror: {removed}")

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
            for suffix in (".queue.fail", ".queue.dead", ".directives",
                           ".directives.tmp"):
                path = config.identity_path + suffix
                if _maybe_remove(path):
                    actions.append(f"removed state file: {path}")
            # The .enrolled marker goes too: _ensure_enrolled short-circuits
            # on it, so a leftover would make the brand-new box_id/keypair
            # skip /enroll and be rejected 403 forever (packaging/README.md
            # §17 reset flow).
            enrolled_marker = _enrolled_marker_path(config.identity_path)
            if _maybe_remove(enrolled_marker):
                actions.append(f"removed enrollment marker: {enrolled_marker}")
            else:
                actions.append(f"no enrollment marker to remove at: {enrolled_marker}")
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
        description="Reset local Huitzilopochtli agent state for a take-home box."
    )
    parser.add_argument(
        "install_dir",
        nargs="?",
        default="/opt/.huitzilopochtli",
        help="install directory (default: /opt/.huitzilopochtli)",
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
