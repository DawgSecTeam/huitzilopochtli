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
            "max_points": 5, "collect": {"path": "/etc/x", "extract": "x=(\\w+)"}, "expect": {"equals": "y", "points": 5},
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


def test_compile_rejects_unknown_sla_key():
    # A typo'd sla key (hysteresis_fal_n) used to be silently dropped at
    # compile time, leaving the author's intended hysteresis unapplied.
    import pytest
    from authoring.compile import _build_rubric_entry

    check = {"id": "web_sla", "category": "vuln",
             "expect": {"equals": 200, "field": "status", "points": 0,
                        "sla": {"interval_s": 60, "points_per_interval": 1,
                                "hysteresis_fal_n": 3}}}
    with pytest.raises(ValueError, match="unknown key.*hysteresis_fal_n"):
        _build_rubric_entry(check)


# --- 1.0 authoring hardening -------------------------------------------------

def _valid_check(**overrides):
    check = {
        "id": "c1", "type": "file_regex", "category": "vuln", "display": "d",
        "max_points": 5, "collect": {"path": "/etc/x", "extract": "x=(\\w+)"},
        "expect": {"equals": "y", "points": 5},
    }
    check.update(overrides)
    return check


def _scenario(check=None, **extra):
    parsed = {
        "scenario": {"name": "x", "version": 1, "mode": "honor", "hosts": ["h"]},
        "checks": [check or _valid_check()],
    }
    parsed.update(extra)
    return parsed


def test_unknown_check_type_is_rejected():
    parsed = _scenario(_valid_check(type="file_regexx"))
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("not a registered check type" in e for e in errors)


def test_unknown_check_key_is_rejected():
    parsed = _scenario(_valid_check(soluion="typo"))
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("unknown key" in e and "soluion" in e for e in errors)


def test_unknown_top_level_key_is_rejected():
    parsed = _scenario(adversrys={"events": []})
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("adversrys" in e for e in errors)


def test_missing_expect_points_is_rejected():
    check = _valid_check()
    del check["expect"]["points"]
    errors = validate_scenario_yaml(_scenario(check), "x.yaml")
    assert any("expect.points is required" in e for e in errors)


def test_zero_points_non_sla_is_rejected():
    check = _valid_check(expect={"equals": "y", "points": 0})
    errors = validate_scenario_yaml(_scenario(check), "x.yaml")
    assert any("non-zero" in e for e in errors)


def test_max_points_must_match_points():
    check = _valid_check(max_points=10)
    errors = validate_scenario_yaml(_scenario(check), "x.yaml")
    assert any("max_points" in e and "must match" in e for e in errors)


def test_penalty_max_points_uses_absolute_points():
    check = _valid_check(category="penalty", max_points=10, type="service_state",
                         collect={"service": "atd"},
                         expect={"equals": True, "field": "active", "points": -10})
    assert validate_scenario_yaml(_scenario(check), "x.yaml") == []


def test_is_sla_without_sla_is_rejected():
    check = _valid_check(is_sla=True)
    errors = validate_scenario_yaml(_scenario(check), "x.yaml")
    assert any("without expect.sla" in e for e in errors)


def test_sla_missing_interval_is_rejected_cleanly():
    check = _valid_check(expect={"equals": True, "field": "active", "points": 0,
                                 "sla": {"points_per_interval": 1}})
    errors = validate_scenario_yaml(_scenario(check), "x.yaml")
    assert any("interval_s" in e for e in errors)


def test_missing_collect_param_is_rejected():
    check = _valid_check(collect={"path": "/etc/x"})
    errors = validate_scenario_yaml(_scenario(check), "x.yaml")
    assert any("missing required key 'extract'" in e for e in errors)


def test_engine_url_must_be_http_scheme():
    parsed = _scenario()
    parsed["scenario"]["mode"] = "ranked"
    parsed["scenario"]["engine_url"] = "engine.example.org"
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("engine_url must be an http" in e for e in errors)


def test_adversary_requires_ids_finite_windows_and_known_actions():
    parsed = _scenario(adversary={"events": [
        {"action": "kill_servce", "window_s": [1, 2], "params": {"service": "atd"}},
        {"id": "ok", "action": "kill_service", "window_s": [float("nan"), 2],
         "params": {"service": "atd"}},
    ]})
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("non-empty string (stable event id)" in e for e in errors)
    assert any("must be one of" in e for e in errors)
    assert any("finite" in e for e in errors)


def test_affects_check_must_reference_an_sla_check():
    check = _valid_check()
    parsed = _scenario(check, adversary={"events": [{
        "id": "e1", "action": "kill_service", "window_s": [1, 2],
        "params": {"service": "atd"}, "affects_check": "c1",
    }]})
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("must name an SLA check" in e for e in errors)


# --- pool block (ranked-only workshop pool provisioning spec) -------------------


def _ranked_base():
    parsed = _base()
    parsed["scenario"]["mode"] = "ranked"
    parsed["scenario"]["engine_url"] = "http://engine:8080"
    return parsed


def _pool_block():
    return {"template_vm_id": 183, "template_vm_access_method": "vnc",
            "template_vm_username": "sysadmin", "template_vm_password": "asdf",
            "vm_count": 2}


def test_pool_block_on_a_ranked_scenario_is_valid():
    parsed = _ranked_base()
    parsed["pool"] = _pool_block()
    assert validate_scenario_yaml(parsed, "x.yaml") == []


def test_pool_block_on_an_honor_scenario_is_rejected():
    parsed = _base()
    parsed["pool"] = _pool_block()
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("ranked-only" in e and "'pool'" in e for e in errors)


def test_pool_block_missing_required_template_keys():
    parsed = _ranked_base()
    parsed["pool"] = {"vm_count": 2}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    for key in ("template_vm_id", "template_vm_access_method",
                "template_vm_username", "template_vm_password"):
        assert any(f"pool missing required key '{key}'" in e for e in errors)


def test_pool_block_rejects_bad_values():
    parsed = _ranked_base()
    parsed["pool"] = dict(_pool_block(), template_vm_id=0,
                          template_vm_access_method="telnet", vm_count=-1,
                          guac_link_ttl_seconds=10, dispenser="yes",
                          group="Ranked")
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("pool.template_vm_id must be a positive integer" in e for e in errors)
    assert any("pool.template_vm_access_method must be one of" in e for e in errors)
    assert any("pool.vm_count must be an integer >= 0" in e for e in errors)
    assert any("pool.guac_link_ttl_seconds must be an integer >= 60" in e
               for e in errors)
    assert any("pool.dispenser must be a boolean" in e for e in errors)
    assert any("pool.group must be one of" in e for e in errors)


def test_pool_block_rejects_unknown_keys_and_an_empty_block():
    parsed = _ranked_base()
    parsed["pool"] = dict(_pool_block(), proxmox_url="http://x")
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("pool has unknown key(s): proxmox_url" in e for e in errors)
    parsed["pool"] = {}
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("'pool' must be a non-empty mapping" in e for e in errors)
