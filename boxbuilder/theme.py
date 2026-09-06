"""Resolve a scenario's `theme` block into vulndb catalog configuration entries to
append to each machine's `configurations` list -- box theming lives entirely in this
project (boxbuilder) and the vulndb catalog, using nakon exactly as it already works
today (its `depends_on`/`vars` mechanism and its existing MinIO-backed attachment
fetcher), with zero nakon source changes.

Four small, generic, reusable catalog configurations do the actual work on the box --
`theme-wallpaper`, `theme-motd`, `theme-readme`, `theme-shortcuts` (static definitions in
boxbuilder/vulndb_theme_configs/, auto-created idempotently the first time they're
needed via boxbuilder/vulndb.py::ensure_configuration). Free text (motd/issue/forensics
questions/shortcut name+exec) is threaded through as `vars`; files (wallpaper/readme) go
through one content-addressed attachment per distinct file, uploaded once and reused by
every scenario that references identical bytes (boxbuilder/vulndb.py::ensure_attachment).

`title`/`organization`/`accent`/`logo` are NOT handled here -- those are the small,
cosmetic subset that flows through the signed Manifest instead (see
authoring/compile.py::_build_manifest_theme); this module never touches them.
"""
import os
from typing import Optional

from boxbuilder import vulndb
from boxbuilder.spec import BoxSpec


def _resolve(path: str, base_dir: str) -> str:
    # Mirrors boxbuilder/spec.py::_resolve -- same "absolute wins, else relative to the
    # spec file's directory" rule used for scenario_path/nakon_config_path there.
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(base_dir, path))


def _motd_vars(theme: dict) -> dict:
    # `issue` falls back to `motd` and vice versa (documented author-facing behavior,
    # unchanged from before this rework) -- resolved here in Python since the catalog
    # script itself now only ever sees the two vars independently, already resolved.
    motd_text = theme.get("motd") or theme.get("issue") or ""
    issue_text = theme.get("issue") or theme.get("motd") or ""
    v = {}
    if motd_text:
        v["MOTD_TEXT"] = motd_text
    if issue_text:
        v["ISSUE_TEXT"] = issue_text
    return v


def _forensics_text(theme: dict) -> str:
    questions = theme.get("forensics_questions") or []
    if not questions:
        return ""
    lines = []
    for i, q in enumerate(questions, start=1):
        lines.append(f"Q{i}: {q}")
        lines.append("Answer: ______________________________________________")
        lines.append("")
    return "\n".join(lines)


def _shortcut_pairs(theme: dict) -> list:
    """Author's desktop_shortcuts list plus the auto-appended "Scoring Report" launcher
    (unless opted out) -- one (name, exec) pair per eventual `theme-shortcuts` entry.

    The Scoring Report opens $HOME/Desktop/report.html, not _REPORT_PATH (/opt/...)
    directly: packaging/sync-report.sh mirrors the real report there specifically
    because a snap-confined browser (e.g. Ubuntu's default Firefox) can't see /opt at
    all, and would show "File not found" for it. sh -c wrapped so $HOME actually
    expands -- a bare `~`/`$HOME` in a .desktop Exec= line isn't guaranteed to be
    shell-expanded by whatever launches it."""
    shortcuts = list(theme.get("desktop_shortcuts") or [])
    if theme.get("include_report_shortcut") is not False:
        shortcuts.append({
            "name": "Scoring Report",
            "exec": "sh -c 'xdg-open $HOME/Desktop/report.html'",
        })
    return [(sc["name"], sc["exec"]) for sc in shortcuts]


def resolve_theme_configurations(spec: BoxSpec, vulndb_url: Optional[str] = None) -> list:
    """Return the configuration entries to append to EVERY machine's `configurations`
    list in nakon's config.json -- empty list if the scenario has no theme block (fully
    backward compatible: doesn't touch vulndb at all when there's nothing themed).

    `vulndb_url` defaults via vulndb.resolve_vulndb_url() ($VULNDB_UI_URL, else
    http://127.0.0.1:3000). Raises ValueError early (before any network call) if
    wallpaper/readme reference a missing file, mirroring spec.py::load_spec's existing
    existence checks; raises vulndb.VulndbError if vulndb-ui isn't reachable/writable.
    """
    theme = spec.theme
    if not theme:
        return []

    # Fail fast on missing files before touching the network at all.
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
    entries = []

    if wallpaper_abs:
        config = vulndb.ensure_configuration(url, vulndb.load_seed_definition("theme-wallpaper"))
        filename = vulndb.ensure_attachment(url, config, wallpaper_abs)
        entries.append({"name": "theme-wallpaper", "vars": {"WALLPAPER_FILENAME": filename}})

    motd_vars = _motd_vars(theme)
    if motd_vars:
        vulndb.ensure_configuration(url, vulndb.load_seed_definition("theme-motd"))
        entries.append({"name": "theme-motd", "vars": motd_vars})

    forensics_text = _forensics_text(theme)
    if readme_abs or forensics_text:
        config = vulndb.ensure_configuration(url, vulndb.load_seed_definition("theme-readme"))
        readme_vars = {}
        if readme_abs:
            readme_vars["README_FILENAME"] = vulndb.ensure_attachment(url, config, readme_abs)
        if forensics_text:
            readme_vars["FORENSICS_TEXT"] = forensics_text
        entries.append({"name": "theme-readme", "vars": readme_vars})

    shortcut_pairs = _shortcut_pairs(theme)
    if shortcut_pairs:
        vulndb.ensure_configuration(url, vulndb.load_seed_definition("theme-shortcuts"))
        for name, exec_cmd in shortcut_pairs:
            entries.append({
                "name": "theme-shortcuts",
                "vars": {"SHORTCUT_NAME": name, "SHORTCUT_EXEC": exec_cmd},
            })

    return entries
