"""Generate the on-box install set + agent_config.json per mode; never
touches the box — pipeline.install_box applies what this returns. Full
layout table: packaging/README.md. The honor rubric ships as .score.dat,
obfuscated so a casual `ls` doesn't hand over the answer key; identity.json
is created by the agent on first ranked boot, never shipped."""
import os

from boxbuilder.os_family import is_windows
from dataclasses import dataclass
from typing import Optional

INSTALL_DIR_POSIX = "/opt/.huitzilopochtli"
INSTALL_DIR_WINDOWS = r"C:\ProgramData\huitzilopochtli"
INSTALL_DIR = INSTALL_DIR_POSIX
RUBRIC_BASENAME = ".score.dat"


def install_dir_for(os_name: str) -> str:
    """Install dir on the TARGET box for its OS ("posix" | "windows")."""
    if is_windows(os_name):
        return INSTALL_DIR_WINDOWS
    return INSTALL_DIR_POSIX


MOTD_PATH = "/etc/update-motd.d/90-huitzilopochtli"


def _sh_single_quoted(text: str) -> str:
    """Escape `text` for a single-quoted POSIX string; control characters
    collapse to spaces because a newline would inject shell into the
    root-executed motd script."""
    text = "".join(
        ch if ord(ch) >= 0x20 and not 0x7F <= ord(ch) <= 0x9F else " "
        for ch in str(text)
    )
    return text.replace("'", "'\\''")


def motd_script(title: str, organization: Optional[str] = None,
                mode: str = "honor") -> str:
    """The first-login banner: an /etc/update-motd.d/ fragment (POSIX only;
    Windows has no motd). Pure text generation — pipeline.install_box places
    it via /tmp stage + install -m 755. Leads with `huitz readme`."""
    heading = f"Welcome to {_sh_single_quoted(title)}"
    if organization:
        heading += f" — {_sh_single_quoted(organization)}"
    grade_line = ("  '  sudo huitz grade           re-grade right now' \\"
                  if mode == "honor" else
                  "  '  (ranked) scores arrive from the engine at each"
                  " check-in' \\")
    if mode == "honor":
        intro = [
            "  'This box is a hardening challenge: scored misconfigurations' \\",
            "  'are hiding on this system. Find them, fix them properly, and' \\",
            "  'keep them fixed. New here? Start with the handbook:' \\",
            "  '' \\",
            "  '  huitz readme               the handbook: objective, rules, login' \\",
            "  '' \\",
            "  'Then work from the terminal:' \\",
        ]
    else:
        intro = [
            "  'Your box joins when you open the competition link. If it did' \\",
            "  'not, run this here with the one-time code from your page:' \\",
            "  '' \\",
            "  '  huitz join                 bind this box to your competition slot' \\",
            "  '' \\",
            "  'Then work from the terminal:' \\",
            "  '  huitz readme               the handbook: objective, rules, login' \\",
        ]
    return "\n".join([
        "#!/bin/sh",
        "# Huitzilopochtli onboarding banner (placed by boxbuilder).",
        "# Edit freely on the box — reinstalls overwrite it.",
        'printf \'%s\\n\' \\',
        f"  '{heading}' \\",
        "  '' \\",
        *intro,
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
    """Build agent_config.json per agent/config.py::AgentConfig field names.
    honor: rubric_path set, identity/checkin/token null; ranked: the mirror
    image, plus engine_url (not an AgentConfig field — the agent reads it
    from the raw JSON). `os_name` selects the install dir."""
    base = install_dir_for(os_name)
    sep = "\\" if is_windows(os_name) else "/"
    cfg = {
        "mode": mode,
        "manifest_path": f"{base}{sep}manifest.signed.json",
        "authoring_public_key_path": f"{base}{sep}authoring_public_key.b64",
        "report_path": f"{base}{sep}report.html",
        "rubric_path": None,
        "identity_path": None,
        "checkin_interval_s": None,
        "enrollment_token": None,
        "engine_url": None,
        "notifications": True,
    }
    if mode == "honor":
        cfg["rubric_path"] = f"{base}{sep}{RUBRIC_BASENAME}"
    elif mode == "ranked":
        if not engine_url:
            raise ValueError("ranked mode requires engine_url")
        cfg["engine_url"] = engine_url
        if not checkin_interval_s or checkin_interval_s <= 0:
            raise ValueError("ranked mode requires a positive checkin_interval_s")
        cfg["identity_path"] = f"{base}{sep}identity.json"
        cfg["checkin_interval_s"] = checkin_interval_s
        cfg["enrollment_token"] = enrollment_token
    else:
        raise ValueError(f"unknown mode {mode!r}")
    return cfg


def on_box_files(compile_result: dict, mode: str, agent_config: dict,
                 os_name: str = "posix") -> list:
    """The OnBoxFile list to place for a compile result + config. `os_name`
    picks the target layout; on windows sync-report.sh is not placed (the
    scheduled-task wrapper mirrors the report itself)."""
    import json

    base = install_dir_for(os_name)
    sep = "\\" if is_windows(os_name) else "/"
    files = [
        OnBoxFile(compile_result["agent_pyz"], f"{base}{sep}agent.pyz"),
        OnBoxFile(compile_result["manifest"], f"{base}{sep}manifest.signed.json"),
        OnBoxFile(compile_result["authoring_public_key"],
                  f"{base}{sep}authoring_public_key.b64"),
    ]
    if not is_windows(os_name):
        files.append(OnBoxFile(_SYNC_REPORT_SH, f"{base}/sync-report.sh",
                               mode=0o755))
    if mode == "honor":
        if not compile_result.get("rubric"):
            raise ValueError("honor mode requires rubric.json from compile, but it was missing")
        from common import rubric_codec
        with open(compile_result["rubric"], "r", encoding="utf-8") as f:
            rubric_dict = json.load(f)
        artifacts_dir = os.path.dirname(compile_result["agent_pyz"])
        rubric_stage = os.path.join(artifacts_dir, RUBRIC_BASENAME)
        with open(rubric_stage, "wb") as f:
            f.write(rubric_codec.encode_rubric(rubric_dict))
        files.append(OnBoxFile(rubric_stage,
                               f"{base}{sep}{RUBRIC_BASENAME}", mode=0o600))

    artifacts_dir = os.path.dirname(compile_result["agent_pyz"])
    cfg_path = os.path.join(artifacts_dir, "agent_config.json")
    fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(agent_config, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(cfg_path, 0o600)
    except OSError:
        pass
    # Ranked's config is world-readable so `huitz` can answer before the box
    # joined; it carries no key material. Honor keeps it 0600 in the seal.
    cfg_mode = 0o644 if mode == "ranked" else 0o600
    files.append(OnBoxFile(cfg_path, f"{base}{sep}agent_config.json", mode=cfg_mode))
    return files
