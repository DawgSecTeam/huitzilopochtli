"""Resolve a scenario's `theme` block into vulndb catalog `configurations`
entries appended to each machine — via the four generic configs
theme-wallpaper/-motd/-readme/-shortcuts (free text as `vars`, files as
content-addressed attachments), with zero nakon changes. Cosmetic fields
(title/accent/logo…) flow through the signed manifest, not here.
"""
import base64
import os
import shutil
import tempfile
from typing import Optional

from boxbuilder import mdhtml, vulndb
from boxbuilder.os_family import is_windows
from boxbuilder.spec import BoxSpec, _resolve

_MAX_LOGO_BYTES = 150 * 1024


def _readme_logo_b64(theme: dict, base_dir: str) -> Optional[str]:
    """Base64-encode theme.logo for the README page masthead, or None if absent/
    unreadable/over-cap (cosmetic only -- the manifest path fail-fasts instead)."""
    logo = theme.get("logo")
    if not logo:
        return None
    try:
        with open(_resolve(logo, base_dir), "rb") as f:
            data = f.read()
    except OSError:
        return None
    if len(data) > _MAX_LOGO_BYTES:
        return None
    return base64.b64encode(data).decode("ascii")


def _readme_upload_path(readme_abs: str, theme: dict, base_dir: str) -> str:
    """theme.readme upload target: Markdown renders to a themed HTML page in a
    temp dir (caller cleans up); an author .html passes through. The fixed
    README.html basename is what lands in the attachment name."""
    if readme_abs.lower().endswith((".html", ".htm")):
        return readme_abs
    with open(readme_abs, encoding="utf-8") as f:
        page = mdhtml.render_readme_page(
            f.read(), theme, logo_b64=_readme_logo_b64(theme, base_dir)
        )
    tmp_dir = tempfile.mkdtemp(prefix="huitz-readme-")
    path = os.path.join(tmp_dir, "README.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    return path


def _motd_vars(theme: dict) -> dict:
    motd_text = theme.get("motd") or theme.get("issue") or ""
    issue_text = theme.get("issue") or theme.get("motd") or ""
    v = {}
    if motd_text:
        v["MOTD_TEXT"] = motd_text
    if issue_text:
        v["ISSUE_TEXT"] = issue_text
    return v


# The mirror must live under plain $HOME: snap's `home` interface covers
# ~/Documents but never /opt, so a snap-confined browser can't read /opt.
MIRROR_DIR_POSIX = "Documents/huitzilopochtli"
MIRROR_DIR_WINDOWS = r"%PUBLIC%\Documents\huitzilopochtli"


def _shortcut_pairs(theme: dict, windows: bool = False) -> list:
    """Author's shortcuts plus the auto "Scoring Report" launcher (unless
    opted out), as (name, exec) pairs. The report opens via the $HOME/Public
    Documents mirror (snap can't read /opt), sh -c wrapped to expand $HOME."""
    shortcuts = list(theme.get("desktop_shortcuts") or [])
    for idx, sc in enumerate(shortcuts):
        if not isinstance(sc, dict) or not sc.get("name") or not sc.get("exec"):
            raise ValueError(
                f"theme.desktop_shortcuts[{idx}] must be an object with "
                f"'name' and 'exec' keys, got {sc!r}"
            )
    if theme.get("include_report_shortcut") is not False:
        if windows:
            shortcuts.append({
                "name": "Scoring Report",
                "exec": MIRROR_DIR_WINDOWS + r"\report.html",
            })
        else:
            shortcuts.append({
                "name": "Scoring Report",
                "exec": f"sh -c 'xdg-open $HOME/{MIRROR_DIR_POSIX}/report.html'",
            })
    return [(sc["name"], sc["exec"]) for sc in shortcuts]


def _target_is_windows(spec: BoxSpec) -> bool:
    """The box's OS comes from the first nakon machine's `os` field (the same
    value `derive_deploy_config` threads into the deploy config) -- nakon's
    own convention: any os containing "win" is a Windows target."""
    machines = spec.nakon_machines()
    return bool(machines) and is_windows(machines[0].get("os"))


def resolve_theme_configurations(spec: BoxSpec, vulndb_url: Optional[str] = None) -> list:
    """Configuration entries to append to every machine's `configurations`
    list; empty (no vulndb contact at all) without a theme block. Raises
    ValueError before any network call if a referenced file is missing."""
    theme = spec.theme
    if not theme:
        return []

    wallpaper_abs = None
    if theme.get("wallpaper"):
        wallpaper_abs = _resolve(theme["wallpaper"], spec.base_dir)
        if not os.path.isfile(wallpaper_abs):
            raise ValueError(
                f"theme.wallpaper referenced by the scenario but not found: {wallpaper_abs}"
            )
    readme_abs = None
    if theme.get("readme"):
        readme_abs = _resolve(theme["readme"], spec.base_dir)
        if not os.path.isfile(readme_abs):
            raise ValueError(
                f"theme.readme referenced by the scenario but not found: {readme_abs}"
            )

    url = vulndb.resolve_vulndb_url(vulndb_url)
    windows = _target_is_windows(spec)
    entries = []

    if wallpaper_abs:
        seed = "theme-wallpaper-win" if windows else "theme-wallpaper"
        config = vulndb.ensure_configuration(url, vulndb.load_seed_definition(seed),
                                             sync=True)
        filename = vulndb.ensure_attachment(url, config, wallpaper_abs)
        entries.append({"name": seed, "vars": {"WALLPAPER_FILENAME": filename}})

    if not windows:
        motd_vars = _motd_vars(theme)
        if motd_vars:
            vulndb.ensure_configuration(url, vulndb.load_seed_definition("theme-motd"),
                                        sync=True)
            entries.append({"name": "theme-motd", "vars": motd_vars})

    if readme_abs:
        seed = "theme-readme-win" if windows else "theme-readme"
        config = vulndb.ensure_configuration(url, vulndb.load_seed_definition(seed),
                                             sync=True)
        readme_vars = {}
        upload_path = _readme_upload_path(readme_abs, theme, spec.base_dir)
        try:
            readme_vars["README_FILENAME"] = vulndb.ensure_attachment(
                url, config, upload_path
            )
        finally:
            if upload_path != readme_abs:
                shutil.rmtree(os.path.dirname(upload_path), ignore_errors=True)
        entries.append({"name": seed, "vars": readme_vars})

    shortcut_pairs = _shortcut_pairs(theme, windows=windows)
    if shortcut_pairs:
        seed = "theme-shortcuts-win" if windows else "theme-shortcuts"
        vulndb.ensure_configuration(url, vulndb.load_seed_definition(seed), sync=True)
        for name, exec_cmd in shortcut_pairs:
            entries.append({
                "name": seed,
                "vars": {"SHORTCUT_NAME": name, "SHORTCUT_EXEC": exec_cmd},
            })

    return entries
