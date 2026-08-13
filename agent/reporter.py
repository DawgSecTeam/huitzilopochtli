"""Static HTML report renderer. See architecture.md §13.

FROZEN signature; body is a PHASE 1 TASK. Pure function — no I/O; caller
writes the returned HTML string to report_path.
"""
import html
import re
import time

from common.schema import Mode, ScoreBreakdown

# Display refresh cadence only — this number is never a scoring input, it
# just tells the browser how often to reload the static HTML page.
REFRESH_SECONDS = 30

# Re-validated here even though authoring/validate.py already checks this shape at
# authoring time -- theme reaches this function via a signed-but-still-external
# manifest field, and this is a <style> interpolation context, not HTML text, so it gets
# its own defensive check rather than relying on html.escape (which is the wrong
# protection for a CSS value position anyway).
_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


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


_STYLE = """
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
       margin: 2rem; background: #0b0d10; color: #e6e6e6; }
.masthead { display: flex; align-items: center; gap: 0.75rem; }
.logo { height: 2.2rem; width: auto; }
h1 { margin-bottom: 0.2rem; border-bottom: 3px solid var(--accent, transparent);
     padding-bottom: 0.2rem; display: inline-block; }
.sub, .org { color: #9aa0a6; margin-top: 0; }
.total { font-size: 2.5rem; font-weight: bold; margin: 1rem 0; color: var(--accent, inherit); }
table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
caption { text-align: left; font-weight: bold; margin-bottom: 0.5rem; }
th, td { border: 1px solid #333; padding: 0.4rem 0.6rem; text-align: left; }
th { background: #1a1d21; }
.num { text-align: right; }
.up { color: #4caf50; font-weight: bold; }
.down { color: #f44336; font-weight: bold; }
.stamp { color: #9aa0a6; font-size: 0.9rem; }
.pending { font-size: 1.5rem; padding: 2rem; border: 2px dashed #666;
           text-align: center; margin: 2rem 0; }
"""


def render_report(score: ScoreBreakdown, mode: Mode,
                   last_confirmed_at: float | None, theme: dict | None = None) -> str:
    """Render ScoreBreakdown to a self-contained HTML string.

    Includes a <meta http-equiv="refresh" content="N"> tag (display cadence
    only, never a scoring input). Dashboard elements: cumulative total; table
    of point-in-time results (category, awarded, reason); SLA status table
    (state UP/DOWN, accrued); and, in ranked mode, a "last confirmed by
    engine at <last_confirmed_at>" stamp. In ranked mode before the first
    engine response, last_confirmed_at is None and the report should show
    "submitted — awaiting engine" instead of a score.

    `theme` (new, optional, trailing -- every existing call site is unaffected) is the
    small cosmetic subset Manifest.theme carries: {"title", "organization", "accent",
    "logo_b64"}, any of which may be absent/None. When given, it re-brands the masthead
    (title text, org subtitle, logo) and the accent color used for the title underline
    and the total-points figure; it never touches the pass/fail UP/DOWN colors, which
    stay semantic regardless of theme.
    """
    theme = theme or {}
    scenario_version = html.escape(str(score.scenario_version))

    display_title = html.escape(str(theme.get("title") or score.scenario_name))
    organization = theme.get("organization")
    org_html = f'<p class="org">{html.escape(str(organization))}</p>' if organization else ""
    logo_b64 = theme.get("logo_b64")
    logo_html = (
        f'<img class="logo" src="data:image/png;base64,{html.escape(str(logo_b64))}" alt="">'
        if logo_b64 else ""
    )
    accent = theme.get("accent")
    accent_css = f":root {{ --accent: {accent}; }}\n" if accent and _ACCENT_RE.match(accent) else ""

    is_ranked = mode == Mode.RANKED
    awaiting_engine = is_ranked and last_confirmed_at is None

    if awaiting_engine:
        # Ranked box with no engine response yet: no score table, no total.
        body_main = (
            '<div class="pending">submitted &mdash; awaiting engine</div>'
        )
    else:
        results_table = _render_results_table(score.results)
        sla_table = _render_sla_table(score.sla_status)
        stamp_html = ""
        if is_ranked and last_confirmed_at is not None:
            stamp_html = (
                '<p class="stamp">last confirmed by engine at '
                f'{html.escape(_fmt_time(last_confirmed_at))} '
                '&mdash; this is the engine\'s authoritative score.</p>'
            )
        body_main = f"""
<div class="total">Total: {html.escape(str(score.total))}</div>
{stamp_html}
{results_table}
{sla_table}
"""

    mode_label = html.escape(mode.value if hasattr(mode, "value") else str(mode))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<!-- Display cadence only, never a scoring input: the browser reloads this
     static page every REFRESH_SECONDS seconds so it looks "live". -->
<meta http-equiv="refresh" content="{REFRESH_SECONDS}">
<title>HUITZILOPOCHTLI &mdash; {display_title}</title>
<style>{accent_css}{_STYLE}</style>
</head>
<body>
<div class="masthead">{logo_html}<h1>{display_title}</h1></div>
{org_html}
<p class="sub">scenario version {scenario_version} &middot; mode: {mode_label}</p>
{body_main}
</body>
</html>
"""
