"""Static HTML report renderer. See architecture.md §13.

Scoring logic and data-driven fragments only; the visual shell (CSS, page
document, masthead, countdown, accent guard) lives in agent/report_page.py.
The derived player-facing facts (fixed vulns, active penalties, forensics
state, progress) come from agent/board.py, shared with the huitz CLI and
the report.json snapshot.
"""
import html
import time

from agent import board as board_mod
from agent.report_page import accent_css, countdown_script, masthead_html, page_shell
from common.schema import Mode, ScoreBreakdown

# Display refresh cadence (not a scoring input). Short enough that a parked
# "00:00 — checking…" expires within one refresh of the file being rewritten.
REFRESH_SECONDS = 15

# Honor re-grade cadence — mirrors packaging/huitzilopochtli-agent.timer.
# OnUnitActiveSec is 60s, but the unit re-fires 60s after the previous
# ACTIVATION and a grade run takes ~2s plus dispatch overhead, so observed
# fires land ~70s apart. This is the countdown estimate only (display
# cadence, never a scoring input).
_HONOR_INTERVAL_S = 70


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def _render_honor_board(score: ScoreBreakdown, manifest) -> str:
    """CyberPatriot-style honor board: positive-only.

    All derived facts (fixed vulns, active penalties, forensics state,
    progress) come from agent/board.py — the same derivation the huitz CLI
    and the report.json snapshot render from.

    - Only passed vulns are listed with display_title + points.
    - Penalties / prohibited only when incurred (awarded != 0).
    - No check_id, category, reason, or awarded=0 rows ever surface.
    - Shows k of n + progress bar + remaining count.
    - Scored forensics questions get their own card and are excluded from the
      vulnerabilities-fixed accounting (they still add to score.total).
    """
    b = board_mod.build_board(score, manifest)

    def _li(title_esc: str, pts: int) -> str:
        if pts > 0:
            pts_html = f'<span class="pts pos">+{html.escape(str(pts))} pts</span>'
        elif pts < 0:
            pts_html = f'<span class="pts neg">{html.escape(str(pts))} pts</span>'
        else:
            pts_html = '<span class="pts muted">—</span>'
        return f'<li><span class="found-title">{title_esc}</span>{pts_html}</li>'

    if b.fixed:
        vuln_items = "\n".join(
            _li(html.escape(str(v.title)), v.points) for v in b.fixed
        )
    else:
        vuln_items = '<li class="muted"><em>No vulnerabilities fixed yet</em></li>'

    if b.penalties:
        pen_items = "\n".join(
            _li(html.escape(str(p.title)), p.points) for p in b.penalties
        )
        pen_header = f"Penalties &mdash; {len(b.penalties)}"
    else:
        pen_items = '<li class="muted"><em>No penalties</em></li>'
        pen_header = "Penalties &mdash; 0"

    remaining_vulns = b.remaining
    if remaining_vulns > 0:
        remaining_html = f'<p class="muted remaining">{remaining_vulns} issue(s) remain.</p>'
    elif b.all_fixed:
        remaining_html = '<p class="muted remaining">All scored issues fixed</p>'
    else:
        remaining_html = ""

    max_label = (
        f" / {b.max_possible} max"
        if b.max_possible and b.max_possible != b.vulns_fixed
        else ""
    )
    fraction_label = (
        f"{b.vulns_fixed} of {b.vulns_total} fixed"
        if b.vulns_total
        else f"{b.vulns_fixed} fixed"
    )

    forensics_card = ""
    if b.forensics:
        def _forensics_li(f) -> str:
            if f.answered:
                pts_html = (
                    '<span class="pts pos">+'
                    f'{html.escape(str(f.points))} pts</span>'
                )
                icon = '<span class="icon ok">&#10003;</span> '
            else:
                pts_html = '<span class="pts muted">0 pts</span>'
                icon = ""
            return (
                f'<li><span class="found-title">{icon}'
                f'{html.escape(str(f.question))}</span>{pts_html}</li>'
            )

        forensics_items = "\n".join(_forensics_li(f) for f in b.forensics)
        forensics_card = f"""
  <section class="card forensics">
    <h2><span class="icon warn">&#128269;</span> Forensics &mdash; {b.forensics_earned} of {len(b.forensics)} correct</h2>
    <ul>
      {forensics_items}
    </ul>
    <p class="muted remaining">Type your answers into Forensics-Questions.txt &mdash; they are re-graded automatically.</p>
  </section>"""

    return f"""
<div class="score-header">
  <div>
    <div class="total">Total: {html.escape(str(b.total))}<span class="total-suffix"> pts</span></div>
    <div class="fraction">{html.escape(fraction_label)}{html.escape(max_label)} &middot; {html.escape(str(b.total))} pts earned</div>
  </div>
  <div class="countdown-wrap">
    <div class="countdown-label">Next check in</div>
    <div id="countdown" class="countdown" aria-live="polite">--:--</div>
  </div>
</div>
<div class="progress" role="progressbar" aria-valuenow="{b.progress_pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Progress">
  <div class="fill" style="width: {b.progress_pct}%"></div>
</div>
<div class="cards">
  <section class="card">
    <h2><span class="icon ok">✓</span> Vulnerabilities Fixed — {b.vulns_fixed} of {b.vulns_total}</h2>
    <ul>
      {vuln_items}
    </ul>
    {remaining_html}
  </section>
  <section class="card penalties">
    <h2><span class="icon warn">⚠</span> {pen_header}</h2>
    <ul>
      {pen_items}
    </ul>
  </section>
{forensics_card}
</div>
<p class="stamp honor-stamp">Last checked: {html.escape(_fmt_time(score.computed_at))} &middot; Honor mode — SLA not scored (untimed)</p>
"""


def _render_results_table(results) -> str:
    rows = []
    for r in results:
        category = r.category.value if hasattr(r.category, "value") else r.category
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(category))}</td>"
            f"<td>{html.escape(str(r.check_id))}</td>"
            f"<td class=\"num\">{html.escape(str(r.awarded_points))}</td>"
            f"<td>{'yes' if r.passed else 'no'}</td>"
            f"<td>{html.escape(str(r.reason))}</td>"
            "</tr>"
        )
    body = "\n".join(rows) if rows else (
        '<tr><td colspan="5"><em>No point-in-time checks.</em></td></tr>'
    )
    return f"""
<table>
  <caption>Point-in-time results</caption>
  <thead>
    <tr><th>Category</th><th>Check ID</th><th>Awarded</th><th>Passed</th><th>Reason</th></tr>
  </thead>
  <tbody>
    {body}
  </tbody>
</table>
"""


def _render_sla_table(sla_status) -> str:
    if not sla_status:
        return "<p>No SLA checks in this scenario.</p>"
    rows = []
    for s in sla_status:
        state = html.escape(str(s.state))
        state_class = "up" if str(s.state).upper() == "UP" else "down"
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(s.check_id))}</td>"
            f"<td class=\"{state_class}\">{state}</td>"
            f"<td class=\"num\">{html.escape(str(s.accrued_points))}</td>"
            "</tr>"
        )
    body = "\n".join(rows)
    return f"""
<table>
  <caption>SLA status</caption>
  <thead>
    <tr><th>Check ID</th><th>State</th><th>Accrued Points</th></tr>
  </thead>
  <tbody>
    {body}
  </tbody>
</table>
"""


def _render_delta_banner(score_delta) -> str:
    """One-run score-change banner ("" when None/0): the visual twin of the
    sound + toast -- green chime for a gain, red alarm for a penalty. Shows
    only on the run right after the change, then disappears again."""
    try:
        # The evaluator supplies an int; coerce anything else defensively so
        # a hostile/malformed value degrades to "no banner", never to markup.
        score_delta = int(score_delta)
    except (TypeError, ValueError):
        return ""
    if not score_delta:
        return ""
    if score_delta > 0:
        return (
            f'<div class="delta-banner up" role="status">&#9650; +'
            f"{html.escape(str(score_delta))} pts since the last grading pass</div>"
        )
    return (
        '<div class="delta-banner down" role="alert">&#9660; '
        f"{html.escape(str(score_delta))} pts &mdash; penalty: a scored "
        "setting was undone or a new issue introduced</div>"
    )


def render_report(score: ScoreBreakdown, mode: Mode,
                   last_confirmed_at: float | None, theme: dict | None = None,
                   manifest=None, honor_interval_s: int | None = None,
                   next_checkin_s: int | None = None,
                   score_delta: int | None = None) -> str:
    """Render ScoreBreakdown to a self-contained HTML string.

    Dashboard: total, point-in-time results, SLA status, and in ranked mode a
    "last confirmed" stamp. Before the first engine response shows
    "submitted — awaiting engine". Optional ``theme`` re-brands the masthead
    and accent color; UP/DOWN colors stay semantic.

    Honor mode is positive-only (CyberPatriot-style): only passed vulns
    (display_title) and active penalties are listed; failed check_ids, categories,
    reasons and awarded=0 rows are never surfaced. A live JS countdown shows
    time until the next re-grade (honor_interval_s, default 60s) or next
    ranked check-in (next_checkin_s), embedded as a render-time remainder
    (seconds from page load) so a stale file reads 00:00 instead of counting
    down from a long-dead target. ``score_delta`` (this run's total minus the
    previous run's, from agent/notify.py) adds a transient up/down banner.
    """
    theme = theme or {}
    scenario_version = html.escape(str(score.scenario_version))
    mode_label = html.escape(mode.value if hasattr(mode, "value") else str(mode))

    raw_title = str(theme.get("title") or score.scenario_name)
    organization = theme.get("organization")
    logo_b64 = theme.get("logo_b64")
    accent_css_block = accent_css(theme.get("accent"))

    masthead = masthead_html(raw_title, organization, logo_b64)
    sub_html = (
        f'<p class="sub">scenario version {scenario_version}'
        f' &middot; mode: {mode_label}</p>'
    )

    is_ranked = mode == Mode.RANKED
    is_honor = not is_ranked
    awaiting_engine = is_ranked and last_confirmed_at is None

    if awaiting_engine:
        # Ranked box with no engine response yet: no score table, no total.
        body_main = (
            '<div class="pending">submitted &mdash; awaiting engine</div>'
        )
        countdown_html = ""
    else:
        if is_honor:
            body_main = _render_delta_banner(score_delta) + _render_honor_board(
                score, manifest
            )
            # Countdown target: computed_at + honor interval
            interval = honor_interval_s if honor_interval_s is not None else _HONOR_INTERVAL_S
            try:
                interval = int(interval)
                if interval <= 0:
                    interval = _HONOR_INTERVAL_S
            except Exception:
                interval = _HONOR_INTERVAL_S
            target_epoch = float(score.computed_at) + interval
            countdown_html = countdown_script(target_epoch, time.time())
        else:
            # Ranked: verbose diagnostic table (rubric off-box, so safe to show)
            results_table = _render_results_table(score.results)
            sla_table = _render_sla_table(score.sla_status)
            stamp_html = ""
            if last_confirmed_at is not None:
                stamp_html = (
                    '<p class="stamp">last confirmed by engine at '
                    f'{html.escape(_fmt_time(last_confirmed_at))} '
                    '&mdash; this is the engine\'s authoritative score.</p>'
                )
            # Ranked countdown if next_checkin_s known, otherwise no countdown
            rank_countdown_block = ""
            rank_countdown_script = ""
            if next_checkin_s is not None and last_confirmed_at is not None:
                try:
                    nci = int(next_checkin_s)
                    if nci > 0:
                        target_epoch = float(last_confirmed_at) + nci
                        rank_countdown_block = '<div class="countdown-wrap" style="margin:0.75rem 0"><div class="countdown-label">Next check-in in</div><div id="countdown" class="countdown">--:--</div></div>'
                        rank_countdown_script = countdown_script(target_epoch, time.time())
                    else:
                        target_epoch = None
                except Exception:
                    target_epoch = None
            else:
                target_epoch = None
            # countdown element goes inside header when present
            body_main = f"""
{_render_delta_banner(score_delta)}
<div class="score-header">
  <div class="total">Total: {html.escape(str(score.total))}<span class="total-suffix"> pts</span></div>
  {rank_countdown_block}
</div>
{stamp_html}
{results_table}
{sla_table}
"""
            # for footer script injection
            countdown_html = rank_countdown_script

    body_html = f"""{masthead}
{sub_html}
{body_main}"""
    head_extra = f"""<!-- Display cadence only, never a scoring input: the browser reloads this
     static page every {REFRESH_SECONDS} seconds so it looks "live". -->
<meta http-equiv="refresh" content="{REFRESH_SECONDS}">
"""
    return page_shell(
        f"HUITZILOPOCHTLI — {raw_title}",
        body_html,
        accent=accent_css_block,
        head_extra=head_extra,
        body_suffix=countdown_html if not awaiting_engine else "",
        wide=True,
    )
