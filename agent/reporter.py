"""Static HTML report renderer. See architecture.md §13."""
import html
import re
import time

from common.schema import Mode, ScoreBreakdown

# Display refresh cadence (not a scoring input).
REFRESH_SECONDS = 30

# Defensive accent validation for CSS interpolation context.
_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

# Honor re-grade cadence — mirrors packaging/huitzilopochtli-agent.timer
# OnUnitActiveSec=60s (local file/service checks, no network).
_HONOR_INTERVAL_S = 60


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def _manifest_lookup(manifest) -> dict:
    """Build check_id -> {display_title, display_max_points, category} from manifest."""
    if manifest is None:
        return {}
    checks = getattr(manifest, "checks", None)
    if checks is None:
        # dict form
        checks = manifest.get("checks", []) if isinstance(manifest, dict) else []
    lookup = {}
    for c in checks:
        if isinstance(c, dict):
            cid = c.get("id")
            lookup[cid] = {
                "display_title": c.get("display_title") or cid,
                "display_max_points": c.get("display_max_points", 0),
                "category": c.get("category"),
            }
        else:
            cid = getattr(c, "id", None)
            lookup[cid] = {
                "display_title": getattr(c, "display_title", None) or cid,
                "display_max_points": getattr(c, "display_max_points", 0),
                "category": getattr(c, "category", None),
            }
    return lookup


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


def _manifest_forensics(manifest) -> list:
    """Extract manifest forensics questions as [{id, question, max_points}].

    Works for both dataclass Manifests and raw dict manifests.
    """
    if manifest is None:
        return []
    forensics = getattr(manifest, "forensics", None)
    if forensics is None and isinstance(manifest, dict):
        forensics = manifest.get("forensics")
    out = []
    for fq in forensics or []:
        if isinstance(fq, dict):
            out.append({
                "id": fq.get("id"),
                "question": fq.get("question") or fq.get("id"),
                "max_points": fq.get("max_points", 0),
            })
        else:
            out.append({
                "id": getattr(fq, "id", None),
                "question": getattr(fq, "question", None) or getattr(fq, "id", None),
                "max_points": getattr(fq, "max_points", 0),
            })
    return out


def _render_honor_board(score: ScoreBreakdown, manifest) -> str:
    """CyberPatriot-style honor board: positive-only.

    - Only passed vulns are listed with display_title + points.
    - Penalties / prohibited only when incurred (awarded != 0).
    - No check_id, category, reason, or awarded=0 rows ever surface.
    - Shows k of n + progress bar + remaining count.
    - Scored forensics questions get their own card and are excluded from the
      vulnerabilities-fixed accounting (they still add to score.total).
    """
    lookup = _manifest_lookup(manifest)
    forensics = _manifest_forensics(manifest)
    forensics_ids = {f["id"] for f in forensics}

    # Separate results by awarded/penalty semantics.
    vuln_fixed = []
    penalties_active = []
    for r in score.results:
        cat = r.category.value if hasattr(r.category, "value") else str(r.category)
        # VULN: show only when passed (positive points earned)
        if cat == "vuln":
            if r.passed and r.awarded_points != 0 and r.check_id not in forensics_ids:
                vuln_fixed.append(r)
        else:
            # penalty / prohibited: show only when incurred (negative points applied)
            if r.awarded_points != 0:
                penalties_active.append(r)

    # Progress accounting — use manifest for denominator when available.
    total_checks = len(lookup) if lookup else len(score.results)
    # Non-SLA checks only; SLA entries are never in results (evaluator skips them)
    # but use lookup to avoid counting SLA placeholders if present.
    if lookup:
        # count non-SLA checks from manifest
        non_sla_total = 0
        max_possible = 0
        for cid, info in lookup.items():
            if cid in forensics_ids:
                continue
            # is_sla check: peek manifest object
            is_sla = False
            # need to find original check object
            checks = getattr(manifest, "checks", None)
            if checks is None and isinstance(manifest, dict):
                checks = manifest.get("checks", [])
            for c in (checks or []):
                check_id = c.get("id") if isinstance(c, dict) else getattr(c, "id", None)
                if check_id == cid:
                    is_sla = c.get("is_sla") if isinstance(c, dict) else getattr(c, "is_sla", False)
                    break
            if not is_sla:
                non_sla_total += 1
                try:
                    max_possible += int(info.get("display_max_points", 0) or 0)
                except Exception:
                    pass
        if non_sla_total > 0:
            total_checks = non_sla_total

    else:
        max_possible = sum(
            max(0, r.awarded_points) for r in score.results
        )  # fallback: at least show earned

    # Max possible for progress: sum of display_max_points for non-SLA, or fallback to earned+remaining estimate
    vuln_count_total = total_checks  # for "k of n"
    vuln_fixed_count = len(vuln_fixed)
    remaining = max(0, vuln_count_total - vuln_fixed_count - len([r for r in penalties_active if r.category.value == "penalty" or str(r.category) == "penalty"]))
    # Simpler remaining: total - fixed vulns (penalties don't count toward vuln total)
    # Use vuln-specific total when manifest available
    vuln_total = 0
    if lookup:
        for cid, info in lookup.items():
            if cid in forensics_ids:
                continue
            cat = info.get("category")
            cat_s = cat.value if hasattr(cat, "value") else str(cat) if cat else "vuln"
            # lookup category is from manifest; fallback to vuln counting
            # Re-derive from checks
            checks = getattr(manifest, "checks", None)
            if checks is None and isinstance(manifest, dict):
                checks = manifest.get("checks", [])
            for c in (checks or []):
                cid2 = c.get("id") if isinstance(c, dict) else getattr(c, "id", None)
                if cid2 == cid:
                    ccat = c.get("category") if isinstance(c, dict) else getattr(c, "category", None)
                    ccat_s = ccat.value if hasattr(ccat, "value") else str(ccat) if ccat else "vuln"
                    if ccat_s == "vuln":
                        vuln_total += 1
                    break
        if vuln_total == 0:
            vuln_total = vuln_count_total
    else:
        vuln_total = sum(
            1 for r in score.results
            if (r.category.value if hasattr(r.category, "value") else str(r.category)) == "vuln"
            and r.check_id not in forensics_ids
        )

    if max_possible <= 0:
        max_possible = vuln_total * 1  # avoid div0; show count-based progress
        pct = int((vuln_fixed_count / vuln_total * 100) if vuln_total else 0)
    else:
        # progress by points if max known, otherwise by count
        earned_positive = sum(r.awarded_points for r in vuln_fixed)
        pct = int((earned_positive / max_possible * 100) if max_possible else 0)
        if pct == 0 and vuln_total:
            pct = int((vuln_fixed_count / vuln_total * 100) if vuln_total else 0)
    pct = max(0, min(100, pct))

    def _li_for_result(r) -> str:
        cid = r.check_id
        title = lookup.get(cid, {}).get("display_title") or cid
        # escape display title (human label), never check_id
        title_esc = html.escape(str(title))
        pts = r.awarded_points
        # pts display: +X pts for vuln, -X pts for penalties (already negative)
        if pts > 0:
            pts_html = f'<span class="pts pos">+{html.escape(str(pts))} pts</span>'
        elif pts < 0:
            pts_html = f'<span class="pts neg">{html.escape(str(pts))} pts</span>'
        else:
            pts_html = '<span class="pts muted">—</span>'
        return f'<li><span class="found-title">{title_esc}</span>{pts_html}</li>'

    if vuln_fixed:
        vuln_items = "\n".join(_li_for_result(r) for r in vuln_fixed)
    else:
        vuln_items = '<li class="muted"><em>No vulnerabilities fixed yet — keep hardening!</em></li>'

    if penalties_active:
        pen_items = "\n".join(_li_for_result(r) for r in penalties_active)
        pen_header = f"Penalties &amp; Prohibited — {len(penalties_active)} active"
    else:
        pen_items = '<li class="muted"><em>No penalties — good hygiene!</em></li>'
        pen_header = "Penalties &amp; Prohibited — 0 active"

    # Remaining hint: count only, no identities
    remaining_vulns = max(0, vuln_total - vuln_fixed_count)
    if remaining_vulns > 0:
        remaining_html = f'<p class="muted remaining">{remaining_vulns} issue(s) remain — keep hunting.</p>'
    else:
        if vuln_total > 0 and vuln_fixed_count == vuln_total:
            remaining_html = '<p class="muted remaining">All scored issues fixed — nice work!</p>'
        else:
            remaining_html = ""

    max_label = f" / {max_possible} max" if max_possible and max_possible != vuln_fixed_count else ""
    fraction_label = f"{vuln_fixed_count} of {vuln_total} fixed" if vuln_total else f"{vuln_fixed_count} fixed"

    forensics_card = ""
    if forensics:
        results_by_id = {r.check_id: r for r in score.results}

        def _forensics_li(f) -> str:
            r = results_by_id.get(f["id"])
            if r is not None and r.passed:
                pts_html = (
                    '<span class="pts pos">+'
                    f'{html.escape(str(r.awarded_points))} pts</span>'
                )
                icon = '<span class="icon ok">&#10003;</span> '
            else:
                pts_html = '<span class="pts muted">0 pts</span>'
                icon = ""
            return (
                f'<li><span class="found-title">{icon}'
                f'{html.escape(str(f["question"]))}</span>{pts_html}</li>'
            )

        forensics_earned = sum(
            1 for f in forensics
            if (r := results_by_id.get(f["id"])) is not None and r.passed
        )
        forensics_items = "\n".join(_forensics_li(f) for f in forensics)
        forensics_card = f"""
  <section class="card forensics">
    <h2><span class="icon warn">&#128269;</span> Forensics &mdash; {forensics_earned} of {len(forensics)} correct</h2>
    <ul>
      {forensics_items}
    </ul>
    <p class="muted remaining">Type your answers into Forensics-Questions.txt &mdash; they are re-graded automatically.</p>
  </section>"""

    return f"""
<div class="score-header">
  <div>
    <div class="total">Total: {html.escape(str(score.total))}<span class="total-suffix"> pts</span></div>
    <div class="fraction">{html.escape(fraction_label)}{html.escape(max_label)} &middot; {html.escape(str(score.total))} pts earned</div>
  </div>
  <div class="countdown-wrap">
    <div class="countdown-label">Next check in</div>
    <div id="countdown" class="countdown" aria-live="polite">--:--</div>
  </div>
</div>
<div class="progress" role="progressbar" aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Progress">
  <div class="fill" style="width: {pct}%"></div>
</div>
<div class="cards">
  <section class="card">
    <h2><span class="icon ok">✓</span> Vulnerabilities Fixed — {vuln_fixed_count} of {vuln_total}</h2>
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


_STYLE = """
:root { --card-bg: #111418; --card-border: #23282e; --muted: #9aa0a6; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
       margin: 0; background: #0b0d10; color: #e6e6e6; line-height: 1.5; }
.container { max-width: 960px; margin: 0 auto; padding: 1.25rem 1.5rem 2rem; }
.masthead { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.25rem; }
.logo { height: 2.2rem; width: auto; border-radius: 4px; }
h1 { margin: 0; font-size: 1.6rem; letter-spacing: -0.01em; border-bottom: 3px solid var(--accent, #2a2f36);
      padding-bottom: 0.2rem; display: inline-block; line-height: 1.2; }
.sub, .org { color: var(--muted); margin: 0.15rem 0 0; font-size: 0.9rem; }
.sub { margin-bottom: 0.5rem; }
.score-header { display: flex; justify-content: space-between; align-items: flex-end; gap: 1rem; flex-wrap: wrap;
                background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px;
                padding: 1rem 1.2rem; margin: 1rem 0 0.6rem; }
.total { font-size: 2.1rem; font-weight: 800; margin: 0; color: var(--accent, #e6e6e6); letter-spacing: -0.02em; }
.total-suffix { font-size: 1rem; font-weight: 600; color: var(--muted); margin-left: 0.15rem; }
.fraction { color: var(--muted); font-size: 0.9rem; margin-top: 0.15rem; }
.countdown-wrap { text-align: right; min-width: 9rem; }
.countdown-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-bottom: 0.15rem; }
.countdown { font-variant-numeric: tabular-nums; font-weight: 800; font-size: 1.35rem; letter-spacing: 0.04em;
             color: #e6e6e6; border: 1px solid #2a2f36; border-radius: 8px; padding: 0.3rem 0.7rem; background: #1a1d21; min-width: 5.5rem; display: inline-block; text-align: center; }
.progress { height: 12px; background: #1a1d21; border-radius: 999px; overflow: hidden; border: 1px solid var(--card-border); margin: 0.5rem 0 1rem; }
.progress .fill { height: 100%; background: var(--accent, #4caf50); width: 0%; transition: width 0.45s ease; border-radius: 999px; }
.cards { display: grid; grid-template-columns: 1fr; gap: 0.9rem; margin-bottom: 0.5rem; }
@media (min-width: 720px) { .cards { grid-template-columns: 1fr 1fr; } }
.card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 1rem 1.15rem; }
.card h2 { margin: 0 0 0.65rem; font-size: 0.95rem; letter-spacing: 0.02em; color: #e6e6e6; display: flex; align-items: center; gap: 0.45rem; }
.card h2 .icon.ok { color: #4caf50; }
.card h2 .icon.warn { color: #f0a500; }
.card ul { list-style: none; padding: 0; margin: 0; }
.card li { display: flex; justify-content: space-between; gap: 0.75rem; padding: 0.5rem 0; border-bottom: 1px solid #1e2328; font-size: 0.92rem; }
.card li:last-child { border-bottom: none; }
.found-title { flex: 1; overflow: hidden; text-overflow: ellipsis; }
.pts { font-variant-numeric: tabular-nums; font-weight: 700; white-space: nowrap; }
.pts.pos { color: #4caf50; }
.pts.neg { color: #f44336; }
.muted { color: var(--muted); }
.remaining { margin: 0.6rem 0 0; font-size: 0.85rem; }
.stamp { color: var(--muted); font-size: 0.85rem; margin: 0.5rem 0 0; }
.honor-stamp { margin-top: 0.75rem; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1.25rem; background: var(--card-bg); border-radius: 8px; overflow: hidden; }
caption { text-align: left; font-weight: 700; margin-bottom: 0.4rem; color: #e6e6e6; }
th, td { border: 1px solid #2a2f36; padding: 0.45rem 0.6rem; text-align: left; font-size: 0.88rem; }
th { background: #1a1d21; color: #e6e6e6; }
td { background: #111418; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.up { color: #4caf50; font-weight: 700; }
.down { color: #f44336; font-weight: 700; }
.pending { font-size: 1.25rem; padding: 2rem; border: 2px dashed #3a3f45; border-radius: 10px;
           text-align: center; margin: 1.25rem 0; background: var(--card-bg); color: var(--muted); }
"""


def _countdown_script(target_epoch: float) -> str:
    """Inline JS countdown to target_epoch (seconds since epoch). No deps."""
    # target as integer seconds to avoid float formatting issues; JS uses ms.
    target_int = int(target_epoch)
    # Defensive: ensure int, no injection — html.escape not needed for int but keep safe.
    return f"""
<script>
(function(){{
  var el=document.getElementById('countdown');
  if(!el) return;
  var targetMs={target_int}*1000;
  function pad(n){{return n<10?'0'+n:''+n;}}
  function tick(){{
    var rem=Math.max(0, Math.floor((targetMs-Date.now())/1000));
    var m=Math.floor(rem/60), s=rem%60;
    if(rem<=0){{ el.textContent='00:00 \\u2014 checking\\u2026'; return; }}
    el.textContent=pad(m)+':'+pad(s);
  }}
  tick();
  setInterval(tick,1000);
}})();
</script>
"""


def render_report(score: ScoreBreakdown, mode: Mode,
                   last_confirmed_at: float | None, theme: dict | None = None,
                   manifest=None, honor_interval_s: int | None = None,
                   next_checkin_s: int | None = None) -> str:
    """Render ScoreBreakdown to a self-contained HTML string.

    Dashboard: total, point-in-time results, SLA status, and in ranked mode a
    "last confirmed" stamp. Before the first engine response shows
    "submitted — awaiting engine". Optional ``theme`` re-brands the masthead
    and accent color; UP/DOWN colors stay semantic.

    Honor mode is positive-only (CyberPatriot-style): only passed vulns
    (display_title) and active penalties are listed; failed check_ids, categories,
    reasons and awarded=0 rows are never surfaced. A live JS countdown shows
    time until the next re-grade (honor_interval_s, default 60s) or next
    ranked check-in (next_checkin_s).
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
            body_main = _render_honor_board(score, manifest)
            # Countdown target: computed_at + honor interval
            interval = honor_interval_s if honor_interval_s is not None else _HONOR_INTERVAL_S
            try:
                interval = int(interval)
                if interval <= 0:
                    interval = _HONOR_INTERVAL_S
            except Exception:
                interval = _HONOR_INTERVAL_S
            target_epoch = float(score.computed_at) + interval
            countdown_html = _countdown_script(target_epoch)
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
                        rank_countdown_script = _countdown_script(target_epoch)
                    else:
                        target_epoch = None
                except Exception:
                    target_epoch = None
            else:
                target_epoch = None
            # countdown element goes inside header when present
            body_main = f"""
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
<div class="container">
<div class="masthead">{logo_html}<h1>{display_title}</h1></div>
{org_html}
<p class="sub">scenario version {scenario_version} &middot; mode: {mode_label}</p>
{body_main}
</div>
{countdown_html if not awaiting_engine else ''}
</body>
</html>
"""
