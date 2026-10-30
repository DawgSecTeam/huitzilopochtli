"""Static HTML report renderer. See architecture.md §13.

Scoring logic and data-driven fragments only; the visual shell (CSS, page
document, masthead, countdown, accent guard) lives in agent/report_page.py.
The derived player-facing facts (fixed vulns, active penalties, forensics
state, progress) come from agent/board.py, shared with the huitz CLI and
the report.json snapshot.
"""
import html
import math
import time

from agent import board as board_mod
from agent.report_page import (
    accent_css, countdown_script, masthead_html, page_shell, tabs_script,
)
from common.schema import Mode, SLA_HISTORY_MAX, ScoreBreakdown

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


def _render_config_cards(b) -> str:
    """Positive-only configuration/forensics cards.

    Shared by honor and ranked: only passed vulns (display_title) and
    incurred penalties are named. A failed check id, category, reason, or
    awarded=0 row never reaches the page — in ranked mode that is the answer
    key, not a diagnostic.
    """
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

    if b.remaining > 0:
        remaining_html = f'<p class="muted remaining">{b.remaining} issue(s) remain.</p>'
    elif b.all_fixed:
        remaining_html = '<p class="muted remaining">All scored issues fixed</p>'
    else:
        remaining_html = ""

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
</div>"""


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
{_render_config_cards(b)}
<p class="stamp honor-stamp">Last checked: {html.escape(_fmt_time(score.computed_at))} &middot; Honor mode — SLA not scored (untimed)</p>
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


def _render_event_bar(rank, rank_total, run_ends_at,
                      last_confirmed_at) -> "tuple[str, str]":
    """Ranked-only top bar: event time left + live scoreboard position.

    Returns (html, countdown_script). The clock is engine-relative: the
    engine tells us how long was left when it scored this check-in, and the
    baked render anchor turns that into a browser countdown, so a skewed box
    clock cannot move the event's end. Either metric may be missing (legacy
    engine, unbound box) without leaving an empty cell.
    """
    metrics = []
    script = ""
    run_end = None
    try:
        candidate = float(run_ends_at)
        if math.isfinite(candidate):
            run_end = candidate
    except (TypeError, ValueError):
        run_end = None
    if run_end is not None:
        reference = (last_confirmed_at if last_confirmed_at is not None
                     else time.time())
        try:
            remaining_s = max(0, run_end - float(reference))
        except (TypeError, ValueError):
            remaining_s = 0
        now = time.time()
        script = countdown_script(
            now + remaining_s, now,
            element_id="event-countdown",
            done_text="0:00:00 \u2014 run over",
            show_hours=True,
        )
        metrics.append(f"""<div class="event-metric">
  <div class="event-label">Time remaining</div>
  <div id="event-countdown" class="event-value" aria-live="polite">--:--</div>
  <div class="muted small">ends {html.escape(_fmt_time(run_end))}</div>
</div>""")
    if rank is not None:
        total_html = (
            f'<span class="event-of"> of {html.escape(str(rank_total))}</span>'
            if rank_total is not None else ""
        )
        metrics.append(f"""<div class="event-metric">
  <div class="event-label">Scoreboard position</div>
  <div class="event-value">{html.escape(str(rank))}{total_html}</div>
  <div class="muted small">as of last check-in</div>
</div>""")
    if not metrics:
        return "", ""
    return (f'<section class="event-bar" aria-label="Event status">'
            f'{"".join(metrics)}</section>', script)


def _service_state_label(state: str) -> str:
    return {"UP": "Clean", "DOWN": "Down"}.get((state or "").upper(), "Pending")


def _render_service_ticks(service) -> str:
    """One block per engine-scored check-in, oldest -> newest.

    The strip is always ``SLA_HISTORY_MAX`` slots wide: a service with fewer
    observations shows hollow leading slots rather than pretending the ticks
    before it existed were UP or DOWN. The engine sends the same bounded ring
    to the portal, so both surfaces read alike.
    """
    states = list(getattr(service, "history", None) or [])[-SLA_HISTORY_MAX:]
    padded = [None] * (SLA_HISTORY_MAX - len(states)) + states
    blocks = []
    labels = []
    for state in padded:
        if state is None:
            blocks.append('<span class="tick void" title="No tick yet"></span>')
            labels.append("no tick")
            continue
        state = str(state).upper()
        label = _service_state_label(state)
        labels.append(label)
        blocks.append(
            f'<span class="tick {state.lower()}" title="{html.escape(label)}"></span>'
        )
    aria = (f"Last {SLA_HISTORY_MAX} check-ins: " + ", ".join(labels))
    return (
        f'<span class="ticks" role="img" aria-label="{html.escape(aria)}">'
        f'{"".join(blocks)}</span>'
        f'<span class="ticks-label">last {SLA_HISTORY_MAX}</span>'
    )


def _render_uptime_panel(board) -> str:
    """Current service status + recent tick history (ranked tab 2)."""
    services = list(getattr(board, "services", None) or [])
    if not services:
        return '<p class="muted">No scored services in this scenario.</p>'

    total = len(services)
    clean = board.services_clean
    if clean == total:
        pill = '<span class="status-pill up">Clean</span>'
        summary = ("The scored service is up." if total == 1
                   else f"All {total} scored services are up.")
    elif clean:
        pill = '<span class="status-pill down">Degraded</span>'
        summary = f"{clean} of {total} scored services are up."
    else:
        pill = '<span class="status-pill down">Down</span>'
        summary = ("The scored service is down." if total == 1
                   else f"All {total} scored services are down.")

    rows = []
    for service in services:
        state = (service.state or "").upper()
        state_cls = state.lower() if state in ("UP", "DOWN") else "unknown"
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(service.title))}</td>"
            f'<td><span class="state {state_cls}">'
            f"{html.escape(_service_state_label(state))}</span></td>"
            f'<td class="num">{html.escape(str(service.accrued_points))}</td>'
            f"<td>{_render_service_ticks(service)}</td>"
            "</tr>"
        )
    return f"""
<div class="uptime-summary">{pill}<span class="muted">{html.escape(summary)}</span></div>
<table class="uptime">
  <caption>Scored service uptime</caption>
  <thead>
    <tr><th>Service</th><th>Current</th><th class="num">Uptime pts</th>
        <th>Recent checks</th></tr>
  </thead>
  <tbody>
    {"".join(rows)}
  </tbody>
</table>
<p class="muted small">Each block is one engine-scored check-in &mdash;
left is oldest, right is the latest. Uptime points accrue while a service
stays up and are separate from the hardening score.</p>
"""


def _render_ranked_detail(board, config_html: str) -> str:
    """Two-tab detail: configuration/forensics (positive-only) vs uptime."""
    return f"""
<div class="tabs" data-tabs>
  <div class="tablist" role="tablist" aria-label="Ranked score detail">
    <button type="button" class="tab" role="tab" id="tab-config"
            aria-controls="panel-config" aria-selected="true" tabindex="0">
      Configuration &amp; forensics</button>
    <button type="button" class="tab" role="tab" id="tab-uptime"
            aria-controls="panel-uptime" aria-selected="false" tabindex="-1">
      Service uptime</button>
  </div>
  <section class="tabpanel" id="panel-config" role="tabpanel"
           aria-labelledby="tab-config" tabindex="0">
    {config_html}
  </section>
  <section class="tabpanel" id="panel-uptime" role="tabpanel"
           aria-labelledby="tab-uptime" tabindex="0" hidden>
    {_render_uptime_panel(board)}
  </section>
</div>
"""


def render_report(score: ScoreBreakdown, mode: Mode,
                   last_confirmed_at: float | None, theme: dict | None = None,
                   manifest=None, honor_interval_s: int | None = None,
                   next_checkin_s: int | None = None,
                   score_delta: int | None = None,
                   rank: int | None = None,
                   rank_total: int | None = None,
                   run_ends_at: float | None = None) -> str:
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

    Ranked mode additionally opens with an event bar (time left in the run +
    live scoreboard position, from the engine's check-in response) and splits
    the detail into two tabs: the positive-only configuration/forensics board
    (same spoiler contract as honor) and scored service uptime with its recent
    tick history. No per-check result table exists in either mode.
    """
    theme = theme or {}
    mode_label = html.escape(mode.value if hasattr(mode, "value") else str(mode))

    raw_title = str(theme.get("title") or score.scenario_name)
    organization = theme.get("organization")
    logo_b64 = theme.get("logo_b64")
    accent_css_block = accent_css(theme.get("accent"))

    masthead = masthead_html(raw_title, organization, logo_b64)
    sub_html = f'<p class="sub">mode: {mode_label}</p>'

    is_ranked = mode == Mode.RANKED
    is_honor = not is_ranked
    awaiting_engine = is_ranked and last_confirmed_at is None
    body_suffix_html = ""

    if awaiting_engine:
        # Ranked box with no engine response yet: no score table, no total.
        body_main = (
            '<div class="pending">submitted &mdash; awaiting engine</div>'
        )
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
            body_suffix_html = countdown_script(target_epoch, time.time())
        else:
            # Ranked is positive-only in the configuration/forensics tab,
            # exactly like honor: the engine has already filtered failed
            # zero-point checks, and the board only names fixed vulns and
            # incurred penalties. Never render the per-check result table.
            _rb = board_mod.build_board(score, manifest)
            config_html = _render_config_cards(_rb)
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
            # Ranked opens with the event clock + board position, then the
            # total, then the two-tab detail (config/forensics vs uptime).
            event_bar_html, event_countdown_script = _render_event_bar(
                rank, rank_total, run_ends_at, last_confirmed_at)
            # Total = hardening + service accrual, both derived once in
            # agent/board.py (ranked_split) — never re-split here.
            split_html = ""
            if _rb.hardening_points is not None and _rb.service_points is not None:
                split_html = (
                    '<div class="total-split">{h} pts hardening'
                    ' &middot; {s} pts service uptime</div>'.format(
                        h=html.escape(str(_rb.hardening_points)),
                        s=html.escape(str(_rb.service_points))))
            body_main = f"""
{_render_delta_banner(score_delta)}
{event_bar_html}
<div class="score-header">
  <div class="total">Total: {html.escape(str(score.total))}<span class="total-suffix"> pts</span></div>
  {split_html}
  {rank_countdown_block}
</div>
{stamp_html}
{_render_ranked_detail(_rb, config_html)}
"""
            body_suffix_html = (
                rank_countdown_script + event_countdown_script + tabs_script()
            )

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
        body_suffix=body_suffix_html if not awaiting_engine else "",
        wide=True,
    )
