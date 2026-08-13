"""Unit tests for agent/reporter.py::render_report -- no dedicated test module existed
before this. Focus: the new optional `theme` param doesn't disturb the untheme'd path,
and theming (title/org/logo/accent) escapes correctly and can't inject into either the
HTML body or the <style> block.
"""
from agent.reporter import render_report
from common.schema import CheckResult, Category, Mode, ScoreBreakdown, SlaStatus


def _score(**overrides):
    defaults = dict(
        scenario_name="Test Scenario", scenario_version=1, total=42,
        results=[CheckResult(check_id="c1", category=Category.VULN, awarded_points=5,
                              passed=True, reason="ok")],
        sla_status=[SlaStatus(check_id="c1", state="UP", accrued_points=3)],
        computed_at=1234.0,
    )
    defaults.update(overrides)
    return ScoreBreakdown(**defaults)


def test_no_theme_arg_and_explicit_none_are_identical():
    score = _score()
    assert render_report(score, Mode.HONOR, None) == render_report(score, Mode.HONOR, None, theme=None)


def test_no_theme_uses_scenario_name_and_has_no_accent_block():
    out = render_report(_score(), Mode.HONOR, None)
    assert "<h1>Test Scenario</h1>" in out
    assert ":root" not in out
    assert '<div class="masthead">' in out  # masthead wrapper always present


def test_theme_title_overrides_scenario_name():
    out = render_report(_score(), Mode.HONOR, None, theme={"title": "Operation X"})
    assert "<h1>Operation X</h1>" in out
    assert "Test Scenario" not in out.split("<body>")[1].split("scenario version")[0]


def test_theme_title_is_html_escaped():
    theme = {"title": "<script>alert(1)</script>"}
    out = render_report(_score(), Mode.HONOR, None, theme=theme)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


def test_theme_organization_rendered_and_escaped():
    out = render_report(_score(), Mode.HONOR, None, theme={"organization": "Dawg & Sec"})
    assert '<p class="org">Dawg &amp; Sec</p>' in out


def test_theme_organization_absent_renders_no_org_tag():
    out = render_report(_score(), Mode.HONOR, None, theme={"title": "X"})
    assert '<p class="org">' not in out


def test_theme_logo_embedded_as_data_uri():
    out = render_report(_score(), Mode.HONOR, None, theme={"logo_b64": "Zm9v"})
    assert '<img class="logo" src="data:image/png;base64,Zm9v" alt="">' in out


def test_theme_valid_accent_injects_root_variable():
    out = render_report(_score(), Mode.HONOR, None, theme={"accent": "#C8102E"})
    assert ":root { --accent: #C8102E; }" in out


def test_theme_invalid_accent_is_dropped_defensively():
    """Even though authoring/validate.py already rejects this at authoring time, the
    renderer must not trust an accent value blindly -- it's a <style> interpolation
    context where a malformed value could break out of the intended CSS rule."""
    out = render_report(_score(), Mode.HONOR, None, theme={"accent": "red; } body { color:red"})
    assert ":root" not in out
    assert "red; }" not in out


def test_pass_fail_colors_never_themed():
    """The up/down semantic colors must stay fixed regardless of accent."""
    out = render_report(_score(), Mode.HONOR, None, theme={"accent": "#000000"})
    assert ".up { color: #4caf50; font-weight: bold; }" in out
    assert ".down { color: #f44336; font-weight: bold; }" in out


def test_ranked_awaiting_engine_with_theme():
    out = render_report(_score(), Mode.RANKED, None, theme={"title": "Op X"})
    assert "awaiting engine" in out
    assert "<h1>Op X</h1>" in out


def test_ranked_confirmed_with_theme():
    out = render_report(_score(), Mode.RANKED, 1700000000.0, theme={"title": "Op X", "accent": "#c8102e"})
    assert "last confirmed by engine" in out
    assert ":root { --accent: #c8102e; }" in out
