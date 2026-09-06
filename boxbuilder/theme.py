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
import base64
import os
import shutil
import tempfile
from typing import Optional

from boxbuilder import mdhtml, vulndb
from boxbuilder.spec import BoxSpec

# Matches authoring/compile.py's manifest logo cap; the README page skips (rather
# than fails) an over-cap/unreadable logo -- compile.py is the one that fail-fasts.
_MAX_LOGO_BYTES = 150 * 1024


def _resolve(path: str, base_dir: str) -> str:
    # Mirrors boxbuilder/spec.py::_resolve -- same "absolute wins, else relative to the
    # spec file's directory" rule used for scenario_path/nakon_config_path there.
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(base_dir, path))


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
    """Return the file to upload for theme.readme. Markdown is rendered to a themed
    HTML page (boxbuilder/mdhtml.py) in a temp dir that the caller removes after the
    upload; an author-supplied .html passes through untouched. The fixed `README.html`
    basename -- not the scenario's own filename -- is what lands in the content-
    addressed attachment name, matching the on-box script's Desktop filename."""
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
            upload_path = _readme_upload_path(readme_abs, theme, spec.base_dir)
            try:
                readme_vars["README_FILENAME"] = vulndb.ensure_attachment(
                    url, config, upload_path
                )
            finally:
                if upload_path != readme_abs:
                    shutil.rmtree(os.path.dirname(upload_path), ignore_errors=True)
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
