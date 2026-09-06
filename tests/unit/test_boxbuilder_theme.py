"""Unit tests for boxbuilder.theme.resolve_theme_configurations.

vulndb.ensure_configuration/ensure_attachment are monkeypatched so these stay fast,
network-free unit tests -- the real HTTP behavior (idempotency, content-addressing,
multipart upload) is covered against a fake http.server in test_boxbuilder_vulndb.py,
and was additionally verified live against a real vulndb-ui during development.
"""
import os

import pytest

from boxbuilder import theme as theme_mod
from boxbuilder.spec import BoxSpec

SCENARIO = {"scenario": {"name": "Demo", "version": 1, "mode": "honor", "hosts": ["localhost"]}}


def _spec(tmp_path, theme):
    return BoxSpec(
        scenario_path="/dev/null", nakon_config_path="/dev/null",
        base_dir=str(tmp_path),
        scenario={**SCENARIO, "theme": theme},
        nakon_config={"machines": []},
    )


@pytest.fixture
def fake_vulndb(monkeypatch):
    """Records every ensure_configuration/ensure_attachment call; returns a stable fake
    row/filename so callers can assert on the resulting `vars` without any network."""
    calls = []

    def _ensure_configuration(url, definition, timeout=30):
        calls.append(("ensure_configuration", definition["name"]))
        return {"id": 1, "name": definition["name"], "attachments": []}

    def _ensure_attachment(url, configuration, local_path, timeout=60):
        calls.append(("ensure_attachment", configuration["name"], local_path))
        return f"fakehash-{os.path.basename(local_path)}"

    monkeypatch.setattr(theme_mod.vulndb, "ensure_configuration", _ensure_configuration)
    monkeypatch.setattr(theme_mod.vulndb, "ensure_attachment", _ensure_attachment)
    return calls


def test_no_theme_returns_empty_list_and_touches_nothing(tmp_path, fake_vulndb):
    result = theme_mod.resolve_theme_configurations(_spec(tmp_path, {}))
    assert result == []
    assert fake_vulndb == []


def test_manifest_only_fields_excluded_but_report_shortcut_still_added(tmp_path, fake_vulndb):
    """title/organization/accent/logo never flow through here (manifest-only, see
    authoring/compile.py), but the auto "Scoring Report" shortcut is unconditional for
    any non-empty theme block."""
    result = theme_mod.resolve_theme_configurations(
        _spec(tmp_path, {"title": "Op X", "accent": "#c8102e"})
    )
    assert result == [{
        "name": "theme-shortcuts",
        "vars": {"SHORTCUT_NAME": "Scoring Report",
                 "SHORTCUT_EXEC": "sh -c 'xdg-open $HOME/Desktop/report.html'"},
    }]
    assert ("ensure_configuration", "theme-shortcuts") in fake_vulndb


def test_wallpaper_uploads_and_sets_var(tmp_path, fake_vulndb):
    wallpaper = tmp_path / "wallpaper.png"
    wallpaper.write_bytes(b"x")
    result = theme_mod.resolve_theme_configurations(
        _spec(tmp_path, {"wallpaper": "wallpaper.png", "include_report_shortcut": False})
    )
    assert result == [{
        "name": "theme-wallpaper",
        "vars": {"WALLPAPER_FILENAME": "fakehash-wallpaper.png"},
    }]
    assert ("ensure_configuration", "theme-wallpaper") in fake_vulndb
    assert ("ensure_attachment", "theme-wallpaper", str(wallpaper)) in fake_vulndb


def test_missing_wallpaper_raises_before_any_vulndb_call(tmp_path, fake_vulndb):
    with pytest.raises(ValueError, match="theme.wallpaper referenced by the scenario but not found"):
        theme_mod.resolve_theme_configurations(_spec(tmp_path, {"wallpaper": "nope.png"}))
    assert fake_vulndb == []


def test_missing_readme_raises_before_any_vulndb_call(tmp_path, fake_vulndb):
    with pytest.raises(ValueError, match="theme.readme referenced by the scenario but not found"):
        theme_mod.resolve_theme_configurations(_spec(tmp_path, {"readme": "nope.md"}))
    assert fake_vulndb == []


def test_absolute_asset_path_passed_through(tmp_path, fake_vulndb):
    wallpaper = tmp_path / "wallpaper.png"
    wallpaper.write_bytes(b"x")
    theme_mod.resolve_theme_configurations(
        _spec(tmp_path, {"wallpaper": str(wallpaper), "include_report_shortcut": False})
    )
    assert ("ensure_attachment", "theme-wallpaper", str(wallpaper)) in fake_vulndb


def test_motd_and_issue_fallback_both_directions(tmp_path, fake_vulndb):
    r1 = theme_mod.resolve_theme_configurations(
        _spec(tmp_path, {"motd": "hi", "include_report_shortcut": False})
    )
    assert r1 == [{"name": "theme-motd", "vars": {"MOTD_TEXT": "hi", "ISSUE_TEXT": "hi"}}]

    r2 = theme_mod.resolve_theme_configurations(
        _spec(tmp_path, {"issue": "console banner", "include_report_shortcut": False})
    )
    assert r2 == [{"name": "theme-motd",
                   "vars": {"MOTD_TEXT": "console banner", "ISSUE_TEXT": "console banner"}}]

    r3 = theme_mod.resolve_theme_configurations(
        _spec(tmp_path, {"motd": "m", "issue": "i", "include_report_shortcut": False})
    )
    assert r3 == [{"name": "theme-motd", "vars": {"MOTD_TEXT": "m", "ISSUE_TEXT": "i"}}]


def test_forensics_questions_without_readme_file_still_creates_readme_entry(tmp_path, fake_vulndb):
    result = theme_mod.resolve_theme_configurations(_spec(tmp_path, {
        "forensics_questions": ["What port is the mail server on?"],
        "include_report_shortcut": False,
    }))
    assert len(result) == 1
    entry = result[0]
    assert entry["name"] == "theme-readme"
    assert "README_FILENAME" not in entry["vars"]
    assert entry["vars"]["FORENSICS_TEXT"] == (
        "Q1: What port is the mail server on?\n"
        "Answer: ______________________________________________\n"
    )
    assert not any(c[0] == "ensure_attachment" for c in fake_vulndb)  # no file, no upload


def test_readme_file_and_forensics_together(tmp_path, fake_vulndb):
    readme = tmp_path / "README.md"
    readme.write_text("hi")
    result = theme_mod.resolve_theme_configurations(_spec(tmp_path, {
        "readme": "README.md", "forensics_questions": ["q1?"],
        "include_report_shortcut": False,
    }))
    [entry] = result
    assert entry["name"] == "theme-readme"
    assert entry["vars"]["README_FILENAME"] == "fakehash-README.md"
    assert "FORENSICS_TEXT" in entry["vars"]
    assert ("ensure_attachment", "theme-readme", str(readme)) in fake_vulndb


def test_multiple_shortcuts_plus_auto_report_shortcut(tmp_path, fake_vulndb):
    result = theme_mod.resolve_theme_configurations(_spec(tmp_path, {
        "desktop_shortcuts": [{"name": "Wiki", "exec": "xdg-open https://x"}],
    }))
    assert result == [
        {"name": "theme-shortcuts", "vars": {"SHORTCUT_NAME": "Wiki", "SHORTCUT_EXEC": "xdg-open https://x"}},
        {"name": "theme-shortcuts",
         "vars": {"SHORTCUT_NAME": "Scoring Report",
                  "SHORTCUT_EXEC": "sh -c 'xdg-open $HOME/Desktop/report.html'"}},
    ]
    # ensure_configuration called once for theme-shortcuts regardless of shortcut count.
    assert fake_vulndb.count(("ensure_configuration", "theme-shortcuts")) == 1


def test_include_report_shortcut_false_with_no_other_shortcuts_yields_no_shortcuts_entry(
    tmp_path, fake_vulndb,
):
    result = theme_mod.resolve_theme_configurations(
        _spec(tmp_path, {"include_report_shortcut": False})
    )
    assert result == []
    assert fake_vulndb == []


def test_full_theme_produces_all_four_entries_in_order(tmp_path, fake_vulndb):
    (tmp_path / "wallpaper.png").write_bytes(b"x")
    (tmp_path / "README.md").write_text("hi")
    result = theme_mod.resolve_theme_configurations(_spec(tmp_path, {
        "wallpaper": "wallpaper.png", "readme": "README.md", "motd": "hi",
        "forensics_questions": ["q1?"],
        "desktop_shortcuts": [{"name": "Wiki", "exec": "xdg-open https://x"}],
    }))
    names = [e["name"] for e in result]
    assert names == ["theme-wallpaper", "theme-motd", "theme-readme",
                      "theme-shortcuts", "theme-shortcuts"]
