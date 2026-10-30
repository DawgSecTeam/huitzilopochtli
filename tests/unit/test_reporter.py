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


def test_ranked_is_positive_only():
    score = ScoreBreakdown(
        scenario_name="Test Scenario", scenario_version=1, total=5,
        results=[CheckResult(check_id="c1", category=Category.VULN, awarded_points=5, passed=True, reason="ok reason")],
        sla_status=[SlaStatus(check_id="c1", state="UP", accrued_points=3)],
        computed_at=1234.0,
    )
    manifest = {"checks": [
        {"id": "c1", "category": "vuln",
         "display_title": "SSH root login disabled",
         "display_max_points": 5},
    ]}
    out = render_report(score, Mode.RANKED, 1700000000.0, manifest=manifest)
    # Same positive-only contract as honor: named fixed work, no per-check
    # id/reason table (a failed id would be the answer key).
    assert "SSH root login disabled" in out
    assert "c1" not in out
    assert "ok reason" not in out
    assert "Point-in-time results" not in out
    assert "Category" not in out and "Reason" not in out
    # Ranked still gets its own two-tab shell (config + service uptime).
    assert "Configuration &amp; forensics" in out
    assert "Service uptime" in out


def test_ranked_total_shows_the_hardening_service_split():
    """A 514-pt total beside a 150-pt board read as broken aggregation.

    The engine scores total = hardening + SLA accrual; the rendered report
    must show both parts (round 6 finding 2).
    """
    score = ScoreBreakdown(
        scenario_name="Test Scenario", scenario_version=1, total=514,
        results=[CheckResult(check_id="c1", category=Category.VULN,
                             awarded_points=190, passed=True, reason="ok")],
        sla_status=[SlaStatus(check_id="svc_a", state="UP", accrued_points=200),
                    SlaStatus(check_id="svc_b", state="UP", accrued_points=124)],
        computed_at=1234.0,
    )
    out = render_report(score, Mode.RANKED, 1700000000.0)
    assert "190 pts hardening" in out
    assert "324 pts service uptime" in out
    assert 'class="total-split"' in out


def test_honor_report_has_no_total_split():
    out = render_report(_score(), Mode.HONOR, 1700000000.0)
    assert 'class="total-split"' not in out


def test_ranked_countdown_when_next_checkin_known():
    score = _score()
    out = render_report(score, Mode.RANKED, 1700000000.0, next_checkin_s=60)
    assert 'id="countdown"' in out
    assert "Next check-in in" in out


# --- Countdown embeds a render-anchored deadline, not a page-load anchor ----

def test_honor_countdown_embeds_render_anchored_deadline(monkeypatch):
    """The report is a static file re-executed on every reload/meta-refresh,
    so the deadline must be baked in at render time ("N seconds left as of
    render"); anchoring it to the page-load clock would restart the countdown
    on every reload."""
    monkeypatch.setattr("agent.reporter.time.time", lambda: 1030.0)
    out = render_report(_score(computed_at=1000.0), Mode.HONOR, None)
    assert "endMs=1030000+40*1000" in out  # render instant + (70s interval - 30s since scoring)
    assert "targetMs" not in out


def test_ranked_countdown_embeds_render_anchored_deadline(monkeypatch):
    """Ranked deadlines come from the engine's clock (server_time +
    next_checkin_s); subtracting the render-time box clock absorbs any
    engine/box skew, and the baked anchor is box-local like the browser's."""
    monkeypatch.setattr("agent.reporter.time.time", lambda: 1700000007.0)
    out = render_report(_score(), Mode.RANKED, 1700000000.0, next_checkin_s=123)
    assert "endMs=1700000007000+116*1000" in out  # 123s - 7s since server confirmation


def test_stale_render_reads_expired_at_load(monkeypatch):
    """A file rendered after its deadline (stale last_response on failed
    check-ins, dead re-grade timer) must read 00:00 immediately, never
    resurrect a countdown for a check-in that is already overdue."""
    monkeypatch.setattr("agent.reporter.time.time", lambda: 1700000300.0)
    out = render_report(_score(), Mode.RANKED, 1700000000.0, next_checkin_s=60)
    assert "endMs=1700000300000+0*1000" in out


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


# --- Ranked event bar + tabbed detail (rank / clock / uptime history) -------


def _ranked_services_score(histories, states=None, total=40):
    """Score with two SLA services, each carrying a recent tick history."""
    states = states or ["UP"] * len(histories)
    return ScoreBreakdown(
        scenario_name="Saltmarsh Exchange", scenario_version=1, total=total,
        results=[CheckResult(check_id="ssh-root", category=Category.VULN,
                             awarded_points=10, passed=True, reason="ok")],
        sla_status=[
            SlaStatus(check_id=f"svc_{i}", state=states[i], accrued_points=10,
                      history=list(hist))
            for i, hist in enumerate(histories)
        ],
        computed_at=1700000000.0,
    )


def _ranked_manifest():
    return {"checks": [
        {"id": "svc_0", "category": "vuln", "display_title": "Web service",
         "display_max_points": 0, "is_sla": True},
        {"id": "svc_1", "category": "vuln", "display_title": "DNS service",
         "display_max_points": 0, "is_sla": True},
    ], "theme": {"title": "Saltmarsh Exchange"}}


def test_ranked_event_bar_has_time_remaining_and_position():
    score = _ranked_services_score([["UP"], ["DOWN"]], states=["UP", "DOWN"])
    out = render_report(
        score, Mode.RANKED, 1700000000.0, manifest=_ranked_manifest(),
        rank=2, rank_total=6, run_ends_at=1700003725.0)
    assert 'class="event-bar"' in out
    assert "Time remaining" in out and 'id="event-countdown"' in out
    assert "Scoreboard position" in out and "2" in out and "of 6" in out
    # The event bar is the ranked report's first content after any banner.
    assert out.index('class="event-bar"') < out.index('class="score-header"')


def test_ranked_event_countdown_uses_engine_relative_remainder(monkeypatch):
    """The engine's run clock is authoritative: bake `run_ends_at - server_time`
    into the render anchor instead of trusting the (possibly skewed) box clock."""
    monkeypatch.setattr("agent.reporter.time.time", lambda: 1700000007.0)
    out = render_report(
        _score(), Mode.RANKED, 1700000000.0,
        rank=1, rank_total=3, run_ends_at=1700003725.0)
    assert "endMs=1700000007000+3725*1000" in out


def test_ranked_detail_is_two_tabs_with_uptime_history():
    score = _ranked_services_score([
        ["UP", "UP", "DOWN", "UP"],
        ["DOWN", "DOWN"],
    ], states=["UP", "DOWN"])
    out = render_report(
        score, Mode.RANKED, 1700000000.0, manifest=_ranked_manifest(),
        rank=2, rank_total=6, run_ends_at=1700003725.0)
    assert 'class="tabs" data-tabs' in out
    assert "Configuration &amp; forensics" in out
    assert "Service uptime" in out
    assert 'id="panel-config"' in out and 'id="panel-uptime"' in out
    # First tab is selected/visible; the uptime panel is hidden until clicked.
    assert 'aria-selected="true"' in out
    assert 'id="panel-uptime" role="tabpanel"' in out and "hidden" in out
    # Current status + a fixed 10-slot tick history for each service.
    assert "Degraded" in out
    assert 'class="tick up"' in out and 'class="tick down"' in out
    assert out.count('class="tick void"') == 14  # 6 + 8 unfilled leading slots
    assert "last 10" in out
    assert "Web service" in out and "DNS service" in out


def test_ranked_uptime_all_clean_shows_clean_pill():
    score = _ranked_services_score([["UP", "UP"], ["UP"]])
    out = render_report(
        score, Mode.RANKED, 1700000000.0, manifest=_ranked_manifest(),
        rank=1, rank_total=2, run_ends_at=1700003725.0)
    assert '<span class="status-pill up">Clean</span>' in out
    assert "All 2 scored services are up." in out


def test_ranked_uptime_without_services_says_so():
    score = ScoreBreakdown(
        scenario_name="S", scenario_version=1, total=10, results=[],
        sla_status=[], computed_at=1700000000.0)
    out = render_report(score, Mode.RANKED, 1700000000.0)
    assert "No scored services in this scenario." in out


def test_ranked_event_bar_omitted_when_engine_sends_no_facts():
    """Legacy engines send neither rank nor run_ends_at: no empty bar."""
    out = render_report(_score(), Mode.RANKED, 1700000000.0)
    assert 'class="event-bar"' not in out


def test_honor_report_has_no_event_bar_or_tabs():
    out = render_report(_score(), Mode.HONOR, None)
    body = out.split("</style>", 1)[-1]
    assert 'class="event-bar"' not in body
    assert "data-tabs" not in body
    assert "Service uptime" not in body
    assert "Configuration &amp; forensics" not in body
