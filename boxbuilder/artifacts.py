"""Generate the on-box install set + agent_config.json per mode.

This module knows the exact agent/config.py::AgentConfig shape (10 fields)
and the packaging/README.md install layout. It does NOT touch the box -- it returns
a description of what to place; pipeline.install_box applies it via the provider
handle. Separation makes the per-mode file set unit-testable without a box.

Install layout (see packaging/README.md), all under the target OS's install
dir -- /opt/.huitzilopochtli (POSIX) or ``C:\\ProgramData\\huitzilopochtli``
(windows), sealed to admins-only by pipeline.install_box after placement:
  agent.pyz                      both modes
  manifest.signed.json           both modes
  authoring_public_key.b64       both modes
  .score.dat                     honor only (local scoring; the rubric,
                                 obfuscated via common/rubric_codec.py)
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

INSTALL_DIR_POSIX = "/opt/.huitzilopochtli"
INSTALL_DIR_WINDOWS = r"C:\ProgramData\huitzilopochtli"
# Default kept for existing importers; new code should use install_dir_for()
# with the target box's os_name (the BUILD machine is always POSIX, so this
# constant says nothing about where the agent will run).
INSTALL_DIR = INSTALL_DIR_POSIX
# On-box name of the honor-mode rubric: dotfile, no .json extension, so
# casual `ls` / `cat` discovery doesn't hand over the answer key. Encoded
# content (common/rubric_codec.py) -- obfuscation, not a security boundary.
RUBRIC_BASENAME = ".score.dat"


def install_dir_for(os_name: str) -> str:
    """Install dir on the TARGET box for its OS ("posix" | "windows")."""
    if os_name == "windows":
        return INSTALL_DIR_WINDOWS
    return INSTALL_DIR_POSIX


MOTD_PATH = "/etc/update-motd.d/90-huitzilopochtli"


def _sh_single_quoted(text: str) -> str:
    """Escape `text` for a single-quoted POSIX shell string (' -> '\\'')."""
    return text.replace("'", "'\\''")


def motd_script(title: str, organization: Optional[str] = None,
                mode: str = "honor") -> str:
    """The first-login banner: an /etc/update-motd.d/ fragment (POSIX).

    Ubuntu's dynamic motd executes every script in /etc/update-motd.d/ at
    each login (console + SSH), so this is what tells a player what to do
    the first time they get a shell. Guidance leads with `huitz readme`
    (the handbook carries the objective and rules) and spells out the
    forensics answer syntax — the least discoverable command. Pure text
    generation here; the pipeline places it (SFTP to /tmp, then
    `install -m 755` — the target dir is root-owned). Windows has no motd
    mechanism; the win task script's report shortcut is that box's
    equivalent pointer.
    """
    heading = f"Welcome to {_sh_single_quoted(title)}"
    if organization:
        heading += f" — {_sh_single_quoted(organization)}"
    grade_line = ("  '  sudo huitz grade           re-grade right now' \\"
                  if mode == "honor" else
                  "  '  (ranked) scores arrive from the engine at each"
                  " check-in' \\")
    # The description column starts at character 29 in every command line.
    return "\n".join([
        "#!/bin/sh",
        "# Huitzilopochtli onboarding banner (placed by boxbuilder).",
        "# Edit freely on the box — reinstalls overwrite it.",
        'printf \'%s\\n\' \\',
        f"  '{heading}' \\",
        "  '' \\",
        "  'This box is a hardening challenge: scored misconfigurations' \\",
        "  'are hiding on this system. Find them, fix them properly, and' \\",
        "  'keep them fixed. New here? Start with the handbook:' \\",
        "  '' \\",
        "  '  huitz readme               the handbook: objective, rules, login' \\",
        "  '' \\",
        "  'Then work from the terminal:' \\",
        "  '  huitz score                your current standing' \\",
        "  '  huitz watch                live board, re-grades as you work' \\",
        "  '  huitz forensics 1 \"text\"   answer forensics question 1' \\",
        grade_line,
        "  '' \\",
        "  'Fixes re-score automatically about a minute after you make' \\",
        "  'them. The Desktop has the handbook and Scoring Report' \\",
        "  'shortcuts plus Forensics-Questions.txt; the full report' \\",
        "  'lives in ~/Documents/huitzilopochtli. Good luck.'",
        "",
    ])

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
                      enrollment_token: Optional[str] = None,
                      os_name: str = "posix") -> dict:
    """Build the agent_config.json dict for the given mode.

    Matches agent/config.py::AgentConfig exactly:
      honor:  rubric_path set, identity_path/checkin_interval_s/enrollment_token null
      ranked: rubric_path null, identity_path set, checkin_interval_s set,
              enrollment_token set (consumed once on first boot)

    `manifest_path` and `authoring_public_key_path` are always set (both modes
    verify the manifest signature; the public key is the distributable artifact).
    `os_name` selects the target box's install dir ("posix" | "windows").
    """
    base = install_dir_for(os_name)
    # The BUILD machine is POSIX; path separators for the TARGET box must be
    # chosen explicitly, not via os.path.join.
    sep = "\\" if os_name == "windows" else "/"
    cfg = {
        "mode": mode,
        "manifest_path": f"{base}{sep}manifest.signed.json",
        "authoring_public_key_path": f"{base}{sep}authoring_public_key.b64",
        "report_path": f"{base}{sep}report.html",
        "rubric_path": None,
        "identity_path": None,
        "checkin_interval_s": None,
        "enrollment_token": None,
        "notifications": True,
    }
    if mode == "honor":
        cfg["rubric_path"] = f"{base}{sep}{RUBRIC_BASENAME}"
    elif mode == "ranked":
        if not engine_url:
            raise ValueError("ranked mode requires engine_url")
        if not checkin_interval_s or checkin_interval_s <= 0:
            raise ValueError("ranked mode requires a positive checkin_interval_s")
        # identity.json is created by the agent on first boot; we just point at it.
        cfg["identity_path"] = f"{base}{sep}identity.json"
        cfg["checkin_interval_s"] = checkin_interval_s
        cfg["enrollment_token"] = enrollment_token  # may be None if pre-seeded
    else:
        raise ValueError(f"unknown mode {mode!r}")
    return cfg


def on_box_files(compile_result: dict, mode: str, agent_config: dict,
                 os_name: str = "posix") -> list:
    """Return the list of OnBoxFile to place, given a compile result + config.

    `compile_result` is what compile_box returned (paths under artifacts_dir).
    `agent_config` is the dict from agent_config_dict(); it's serialized to JSON
    and placed as agent_config.json. `os_name` selects the target box layout
    ("posix" | "windows"): on windows the install dir differs and sync-report.sh
    is not placed (the scheduled-task wrapper copies the report itself).
    """
    import json

    base = install_dir_for(os_name)
    sep = "\\" if os_name == "windows" else "/"
    files = [
        OnBoxFile(compile_result["agent_pyz"], f"{base}{sep}agent.pyz"),
        OnBoxFile(compile_result["manifest"], f"{base}{sep}manifest.signed.json"),
        OnBoxFile(compile_result["authoring_public_key"],
                  f"{base}{sep}authoring_public_key.b64"),
    ]
    if os_name != "windows":
        # POSIX only: huitzilopochtli-agent.service's ExecStartPost runs this
        # after every agent run to mirror report.html into each real user's
        # $HOME/Desktop (a snap-confined browser can't see /opt). Windows gets
        # the same effect from the scheduled-task wrapper (Public Desktop copy).
        files.append(OnBoxFile(_SYNC_REPORT_SH, f"{base}/sync-report.sh",
                               mode=0o755))
    if mode == "honor":
        if not compile_result.get("rubric"):
            raise ValueError("honor mode requires rubric.json from compile, but it was missing")
        # Compile emits plain rubric.json; the on-box copy is the obfuscated
        # form, staged next to the other synthesized files (like
        # agent_config.json below) and placed 0600 into the sealed dir.
        from common import rubric_codec
        with open(compile_result["rubric"], "r", encoding="utf-8") as f:
            rubric_dict = json.load(f)
        artifacts_dir = os.path.dirname(compile_result["agent_pyz"])
        rubric_stage = os.path.join(artifacts_dir, RUBRIC_BASENAME)
        with open(rubric_stage, "wb") as f:
            f.write(rubric_codec.encode_rubric(rubric_dict))
        files.append(OnBoxFile(rubric_stage,
                               f"{base}{sep}{RUBRIC_BASENAME}", mode=0o600))

    # agent_config.json is synthesized (not on disk), so we write it to the
    # artifacts dir first, then treat it as a normal file to place.
    artifacts_dir = os.path.dirname(compile_result["agent_pyz"])
    cfg_path = os.path.join(artifacts_dir, "agent_config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(agent_config, f, indent=2)
    files.append(OnBoxFile(cfg_path, f"{base}{sep}agent_config.json"))
    return files
