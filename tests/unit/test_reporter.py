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
    assert ":root { --accent:" not in out
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
    assert ":root { --accent:" not in out
    assert "red; }" not in out


def test_pass_fail_colors_never_themed():
    """The up/down semantic colors must stay fixed regardless of accent."""
    out = render_report(_score(), Mode.HONOR, None, theme={"accent": "#000000"})
    # semantic colors stay fixed (light-theme green/red); see agent/report_page.py
    assert "#1a7f37" in out
    assert "#cf222e" in out
    assert ".up" in out and ".down" in out


def test_ranked_awaiting_engine_with_theme():
    out = render_report(_score(), Mode.RANKED, None, theme={"title": "Op X"})
    assert "awaiting engine" in out
    assert "<h1>Op X</h1>" in out


def test_ranked_confirmed_with_theme():
    out = render_report(_score(), Mode.RANKED, 1700000000.0, theme={"title": "Op X", "accent": "#c8102e"})
    assert "last confirmed by engine" in out
    assert ":root { --accent: #c8102e; }" in out


# --- Honor positive-only + countdown (CyberPatriot-style) -----------------

def test_honor_hides_failed_and_uses_display_title():
    from common.schema import CheckSpec, Manifest
    manifest = Manifest(
        schema_version=1, scenario_name="Test Scenario", scenario_version=1,
        mode=Mode.HONOR, engine_url=None, hosts=["localhost"], checks=[
            CheckSpec(id="c-pass", type="file_regex", category=Category.VULN,
                      host_id="localhost", collect_params={}, display_title="Fixed vuln A", display_max_points=10),
            CheckSpec(id="c-fail", type="file_regex", category=Category.VULN,
                      host_id="localhost", collect_params={}, display_title="Hidden vuln B", display_max_points=10),
        ], theme=None,
    )
    score = ScoreBreakdown(
        scenario_name="Test Scenario", scenario_version=1, total=10,
        results=[
            CheckResult(check_id="c-pass", category=Category.VULN, awarded_points=10, passed=True, reason="equals FOUND"),
            CheckResult(check_id="c-fail", category=Category.VULN, awarded_points=0, passed=False, reason="equals FOUND expected X"),
        ], sla_status=[], computed_at=1234.0,
    )
    out = render_report(score, Mode.HONOR, None, theme=None, manifest=manifest)
    assert "Fixed vuln A" in out
    assert "+10 pts" in out
    assert "Hidden vuln B" not in out
    assert "c-fail" not in out
    assert "equals FOUND" not in out  # reason must not leak
    # category value and Passed oracle must not appear in honor
    assert "<th>Category</th>" not in out
    assert "<th>Passed</th>" not in out


def test_honor_penalty_only_when_active():
    from common.schema import CheckSpec, Manifest
    manifest = Manifest(
        schema_version=1, scenario_name="Test Scenario", scenario_version=1,
        mode=Mode.HONOR, engine_url=None, hosts=["localhost"], checks=[
            CheckSpec(id="pen-ok", type="permission", category=Category.PENALTY,
                      host_id="localhost", collect_params={}, display_title="Perm ok", display_max_points=5),
            CheckSpec(id="pen-bad", type="permission", category=Category.PENALTY,
                      host_id="localhost", collect_params={}, display_title="Perm bad", display_max_points=5),
        ], theme=None,
    )
    # pen-ok intact (0 pts) should not surface; pen-bad incurred (-5) should
    score = ScoreBreakdown(
        scenario_name="Test Scenario", scenario_version=1, total=-5,
        results=[
            CheckResult(check_id="pen-ok", category=Category.PENALTY, awarded_points=0, passed=True, reason="mode ok"),
            CheckResult(check_id="pen-bad", category=Category.PENALTY, awarded_points=-5, passed=False, reason="mode 0777 looser"),
        ], sla_status=[], computed_at=1234.0,
    )
    out = render_report(score, Mode.HONOR, None, theme=None, manifest=manifest)
    assert "Perm bad" in out
    assert "-5 pts" in out
    assert "Perm ok" not in out
    assert "0777" not in out


def test_honor_countdown_and_progress_present():
    score = _score(total=5, results=[
        CheckResult(check_id="c1", category=Category.VULN, awarded_points=5, passed=True, reason="ok"),
    ], computed_at=1000.0)
    out = render_report(score, Mode.HONOR, None)
    assert 'id="countdown"' in out
    assert "Next check in" in out
    assert 'class="progress"' in out
    assert "<script>" in out
    assert "setInterval" in out
    # SLA table must be suppressed in honor (untimed)
    assert "SLA status" not in out
    assert "Honor mode" in out


def test_ranked_still_verbose():
    score = ScoreBreakdown(
        scenario_name="Test Scenario", scenario_version=1, total=5,
        results=[CheckResult(check_id="c1", category=Category.VULN, awarded_points=5, passed=True, reason="ok reason")],
        sla_status=[SlaStatus(check_id="c1", state="UP", accrued_points=3)],
        computed_at=1234.0,
    )
    out = render_report(score, Mode.RANKED, 1700000000.0)
    # Ranked keeps diagnostic table with category/check_id/reason
    assert "c1" in out
    assert "ok reason" in out
    assert "Category" in out
    assert "Reason" in out


def test_ranked_countdown_when_next_checkin_known():
    score = _score()
    out = render_report(score, Mode.RANKED, 1700000000.0, next_checkin_s=60)
    assert 'id="countdown"' in out
    assert "Next check-in in" in out


# --- Countdown embeds a render-time remainder, not an absolute target ------

def test_honor_countdown_embeds_render_time_remainder(monkeypatch):
    """The static report outlives its render instant, so the JS must count
    down from page load ("N seconds left as of render"), not tick an absolute
    epoch target against whatever clock happens to open the file."""
    monkeypatch.setattr("agent.reporter.time.time", lambda: 1030.0)
    out = render_report(_score(computed_at=1000.0), Mode.HONOR, None)
    assert "endMs=Date.now()+30*1000" in out  # 60s honor interval - 30s since scoring
    assert "targetMs" not in out


def test_ranked_countdown_embeds_render_time_remainder(monkeypatch):
    """Ranked deadlines come from the engine's clock (server_time +
    next_checkin_s); converting to a remainder at render keeps the box
    browser's clock out of the math entirely."""
    monkeypatch.setattr("agent.reporter.time.time", lambda: 1700000007.0)
    out = render_report(_score(), Mode.RANKED, 1700000000.0, next_checkin_s=123)
    assert "endMs=Date.now()+116*1000" in out  # 123s - 7s since server confirmation


def test_stale_render_reads_expired_at_load(monkeypatch):
    """A file rendered after its deadline (stale last_response on failed
    check-ins, dead re-grade timer) must read 00:00 immediately, never
    resurrect a countdown for a check-in that is already overdue."""
    monkeypatch.setattr("agent.reporter.time.time", lambda: 1700000300.0)
    out = render_report(_score(), Mode.RANKED, 1700000000.0, next_checkin_s=60)
    assert "endMs=Date.now()+0*1000" in out


# --- Score-change banner (score_delta; the visual twin of the siren/chime) --

def test_no_delta_arg_renders_no_banner():
    out = render_report(_score(), Mode.HONOR, None)
    assert 'class="delta-banner' not in out


def test_zero_delta_renders_no_banner():
    out = render_report(_score(), Mode.HONOR, None, score_delta=0)
    assert 'class="delta-banner' not in out


def test_gain_delta_banner():
    out = render_report(_score(), Mode.HONOR, None, score_delta=10)
    assert 'class="delta-banner up"' in out
    assert "+10 pts since the last grading pass" in out
    assert "delta-banner down" not in out


def test_penalty_delta_banner():
    out = render_report(_score(), Mode.HONOR, None, score_delta=-5)
    assert 'class="delta-banner down"' in out
    assert "-5 pts" in out
    assert "penalty" in out
    assert "delta-banner up" not in out


def test_delta_banner_escapes_hostile_delta_values():
    """score_delta comes from the evaluator as an int, but it flows into raw
    HTML via an f-string -- a non-int value must degrade to no banner, never
    to injected markup (defense in depth, same as every other fragment)."""
    out = render_report(_score(), Mode.HONOR, None,
                        score_delta="<script>alert(1)</script>")
    assert 'class="delta-banner' not in out
    assert "<script>alert(1)</script>" not in out


def test_delta_banner_renders_in_ranked_mode_too():
    out = render_report(_score(), Mode.RANKED, 1700000000.0,
                        next_checkin_s=60, score_delta=7)
    assert 'class="delta-banner up"' in out
    assert "+7 pts since the last grading pass" in out
