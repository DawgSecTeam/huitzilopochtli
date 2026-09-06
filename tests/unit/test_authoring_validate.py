"""Unit tests for authoring/validate.py's `theme` block validation.

No dedicated test module existed for authoring/validate.py before this; scope here is
deliberately limited to the new `theme` structural checks (_validate_theme), not a
backfill of coverage for the pre-existing scenario/checks[] validation.
"""
from authoring.validate import validate_scenario_yaml


def _base():
    return {
        "scenario": {"name": "x", "version": 1, "mode": "honor", "hosts": ["h"]},
        "checks": [{
            "id": "c1", "type": "file_regex", "category": "vuln", "display": "d",
            "max_points": 5, "collect": {}, "expect": {"equals": "y", "points": 5},
        }],
    }


def test_no_theme_key_is_valid():
    assert validate_scenario_yaml(_base(), "x.yaml") == []


def test_empty_theme_is_valid():
    parsed = _base()
    parsed["theme"] = {}
    assert validate_scenario_yaml(parsed, "x.yaml") == []


def test_null_theme_is_valid():
    parsed = _base()
    parsed["theme"] = None
    assert validate_scenario_yaml(parsed, "x.yaml") == []


def test_full_valid_theme_passes():
    parsed = _base()
    parsed["theme"] = {
        "title": "Op Featherstorm",
        "organization": "DawgSec",
        "accent": "#c8102e",
        "logo": "assets/logo.png",
        "wallpaper": "assets/wallpaper.png",
        "readme": "assets/README.md",
        "motd": "Authorized use only.",
        "issue": "Authorized use only.",
        "desktop_shortcuts": [{"name": "Wiki", "exec": "xdg-open https://x"}],
        "include_report_shortcut": False,
    }
    parsed["forensics"] = [{
        "id": "fq1", "question": "What port is the mail server on?",
        "answer": "587", "points": 10,
    }]
    assert validate_scenario_yaml(parsed, "x.yaml") == []


def test_theme_not_a_mapping_rejected():
    parsed = _base()
    parsed["theme"] = "not a mapping"
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("'theme' must be a mapping" in e for e in errors)


def test_theme_string_keys_must_be_strings():
    parsed = _base()
    parsed["theme"] = {"wallpaper": 5, "readme": ["not", "a", "string"]}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("theme.wallpaper must be a string" in e for e in errors)
    assert any("theme.readme must be a string" in e for e in errors)


def test_theme_accent_must_be_hex_color():
    parsed = _base()
    parsed["theme"] = {"accent": "red"}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("theme.accent must match" in e for e in errors)


def test_theme_accent_valid_hex_passes():
    parsed = _base()
    parsed["theme"] = {"accent": "#ABCDEF"}
    assert validate_scenario_yaml(parsed, "x.yaml") == []


def test_theme_forensics_questions_is_rejected():
    """The cosmetic theme list was replaced by the scored forensics section."""
    parsed = _base()
    parsed["theme"] = {"forensics_questions": ["What port is the mail server on?"]}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("no longer supported" in e for e in errors)
    assert any("'forensics' section" in e for e in errors)


def test_theme_desktop_shortcuts_shape():
    parsed = _base()
    parsed["theme"] = {"desktop_shortcuts": "not a list"}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("desktop_shortcuts must be a list" in e for e in errors)

    parsed["theme"] = {"desktop_shortcuts": ["not a mapping"]}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("desktop_shortcuts[0] must be a mapping" in e for e in errors)

    parsed["theme"] = {"desktop_shortcuts": [{"name": "Wiki"}]}  # missing exec
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("desktop_shortcuts[0] missing required key 'exec'" in e for e in errors)

    parsed["theme"] = {"desktop_shortcuts": [{"name": "Wiki", "exec": 5}]}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("desktop_shortcuts[0].exec must be a string" in e for e in errors)


def test_theme_include_report_shortcut_must_be_bool():
    parsed = _base()
    parsed["theme"] = {"include_report_shortcut": "yes"}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("include_report_shortcut must be a boolean" in e for e in errors)

    parsed["theme"] = {"include_report_shortcut": False}
    assert validate_scenario_yaml(parsed, "x.yaml") == []
