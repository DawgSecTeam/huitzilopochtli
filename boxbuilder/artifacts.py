"""Generate the on-box install set + agent_config.json per mode.

This module knows the exact agent/config.py::AgentConfig shape (10 fields)
and the packaging/README.md install layout. It does NOT touch the box -- it returns
a description of what to place; pipeline.install_box applies it via the provider
handle. Separation makes the per-mode file set unit-testable without a box.

Install layout (see packaging/README.md), all under INSTALL_DIR:
  agent.pyz                      both modes
  manifest.signed.json           both modes
  authoring_public_key.b64       both modes
  rubric.json                    honor only (local scoring)
  agent_config.json              both modes (shape differs per mode)
  identity.json                  ranked only, CREATED BY THE AGENT on first boot
                                 (not placed by boxbuilder -- see note below)
  report.html                    written by the agent at runtime
  score_state.json               written by the agent at runtime (previous
                                 run's total, for score-change alerts)
  sync-report.sh                 both modes; mirrors report.html into each real
                                 user's $HOME/Desktop (see packaging/sync-report.sh
                                 -- a snap-confined browser can't see /opt)

Note on identity.json: the agent generates its own Ed25519 identity on first
ranked boot (agent/identity.py), so boxbuilder never ships one. We only set
identity_path in agent_config.json so the agent knows where to create it.
"""
import os
from dataclasses import dataclass
from typing import Optional

INSTALL_DIR = "/opt/huitzilopochtli"

# packaging/ lives at <repo_root>/packaging/ -- mirrors providers/ssh.py's _PACKAGING.
_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_SYNC_REPORT_SH = os.path.join(_REPO_ROOT, "packaging", "sync-report.sh")


@dataclass
class OnBoxFile:
    """A file to place on the box. `local` is a build-machine path; `remote`
    is absolute on the box. `mode` is the chmod (None = leave default)."""
    local: str
    remote: str
    mode: Optional[int] = None


def agent_config_dict(scenario_name: str, mode: str, engine_url: Optional[str] = None,
                      checkin_interval_s: Optional[int] = None,
                      enrollment_token: Optional[str] = None) -> dict:
    """Build the agent_config.json dict for the given mode.

    Matches agent/config.py::AgentConfig exactly:
      honor:  rubric_path set, identity_path/checkin_interval_s/enrollment_token null
      ranked: rubric_path null, identity_path set, checkin_interval_s set,
              enrollment_token set (consumed once on first boot)

    `manifest_path` and `authoring_public_key_path` are always set (both modes
    verify the manifest signature; the public key is the distributable artifact).
    """
    base = INSTALL_DIR
    cfg = {
        "mode": mode,
        "manifest_path": f"{base}/manifest.signed.json",
        "authoring_public_key_path": f"{base}/authoring_public_key.b64",
        "report_path": f"{base}/report.html",
        "rubric_path": None,
        "identity_path": None,
        "checkin_interval_s": None,
        "enrollment_token": None,
        "notifications": True,
    }
    if mode == "honor":
        cfg["rubric_path"] = f"{base}/rubric.json"
    elif mode == "ranked":
        if not engine_url:
            raise ValueError("ranked mode requires engine_url")
        if not checkin_interval_s or checkin_interval_s <= 0:
            raise ValueError("ranked mode requires a positive checkin_interval_s")
        # identity.json is created by the agent on first boot; we just point at it.
        cfg["identity_path"] = f"{base}/identity.json"
        cfg["checkin_interval_s"] = checkin_interval_s
        cfg["enrollment_token"] = enrollment_token  # may be None if pre-seeded
    else:
        raise ValueError(f"unknown mode {mode!r}")
    return cfg


def on_box_files(compile_result: dict, mode: str, agent_config: dict) -> list:
    """Return the list of OnBoxFile to place, given a compile result + config.

    `compile_result` is what compile_box returned (paths under artifacts_dir).
    `agent_config` is the dict from agent_config_dict(); it's serialized to JSON
    and placed as agent_config.json.
    """
    import json

    files = [
        OnBoxFile(compile_result["agent_pyz"], f"{INSTALL_DIR}/agent.pyz"),
        OnBoxFile(compile_result["manifest"], f"{INSTALL_DIR}/manifest.signed.json"),
        OnBoxFile(compile_result["authoring_public_key"],
                  f"{INSTALL_DIR}/authoring_public_key.b64"),
        # Both modes: huitzilopochtli-agent.service's ExecStartPost runs this after
        # every agent run to mirror report.html into each real user's $HOME/Desktop
        # (a snap-confined browser can't see /opt -- see the script's own comments).
        OnBoxFile(_SYNC_REPORT_SH, f"{INSTALL_DIR}/sync-report.sh", mode=0o755),
    ]
    if mode == "honor":
        if not compile_result.get("rubric"):
            raise ValueError("honor mode requires rubric.json from compile, but it was missing")
        files.append(OnBoxFile(compile_result["rubric"], f"{INSTALL_DIR}/rubric.json"))

    # agent_config.json is synthesized (not on disk), so we write it to the
    # artifacts dir first, then treat it as a normal file to place.
    artifacts_dir = os.path.dirname(compile_result["agent_pyz"])
    cfg_path = os.path.join(artifacts_dir, "agent_config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(agent_config, f, indent=2)
    files.append(OnBoxFile(cfg_path, f"{INSTALL_DIR}/agent_config.json"))
    return files
