"""Shared presentation layer for the huitz HTML pages.

Holds everything visual that the score report (agent/reporter.py, runs on the
box) and the box README page (boxbuilder/mdhtml.py, build machine only) have
in common: the CSS, the page shell, the masthead, the accent-color guard, and
the countdown script. Both import from here instead of mirroring copies, so
the two pages cannot drift apart.

Everything lives in Python (not a .css/.html data file) on purpose: the agent
ships as a zipapp, and reading data files from inside a zipapp would need
zip-internal resource loading on the box. Plain .py modules bundle for free
(packaging/build_zipapp.py copies the whole agent/ package) and keep the
pure-stdlib invariant.

Callers pass plain-text values; `page_shell` and `masthead_html` escape them.
The body HTML is inserted verbatim -- fragments built in reporter.py escape
their own dynamic pieces.
"""
import html
import re

# Defensive accent validation: only a 6-digit hex may reach the <style> block.
ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def accent_css(accent) -> str:
    """:root override for a theme accent, or "" if absent/invalid."""
    return f":root {{ --accent: {accent}; }}\n" if accent and ACCENT_RE.match(str(accent)) else ""


def masthead_html(title: str, organization=None, logo_b64=None) -> str:
    """Logo + h1 masthead with optional organization line. Escapes inputs."""
    logo_html = (
        f'<img class="logo" src="data:image/png;base64,{html.escape(str(logo_b64))}" alt="">'
        if logo_b64 else ""
    )
    org_html = (
        f'<p class="org">{html.escape(str(organization))}</p>' if organization else ""
    )
    return (
        f'<div class="masthead">{logo_html}<h1>{html.escape(str(title))}</h1></div>\n'
        f"{org_html}"
    )


def countdown_script(target_epoch_s: float, render_epoch_s: float) -> str:
    """Inline JS counting down to target_epoch_s. No deps.

    The report is a static file that outlives its render instant: it is
    re-executed on every reload and on the meta-refresh, so the deadline must
    be baked into the file (endMs is fixed) -- anchoring it to the page-load
    clock would restart the countdown on every reload. The anchor is the
    render instant, not the raw epoch target: the box's browser and the
    render-time clock() are the same clock, so engine/box skew stays absorbed
    in (target - render) exactly as it would be in a pre-computed remainder,
    and a file rendered after its deadline simply reads 00:00 at load.
    """
    # integer seconds, clamped at 0: a render that already past its deadline
    # (stale file) must read 00:00 at load, never a negative countdown.
    remaining_int = max(0, int(target_epoch_s - render_epoch_s))
    render_ms = int(render_epoch_s * 1000)
    return f"""
<script>
(function(){{
  var el=document.getElementById('countdown');
  if(!el) return;
  var endMs={render_ms}+{remaining_int}*1000;
  function pad(n){{return n<10?'0'+n:''+n;}}
  function tick(){{
    var rem=Math.max(0, Math.floor((endMs-Date.now())/1000));
    var m=Math.floor(rem/60), s=rem%60;
    if(rem<=0){{ el.textContent='00:00 \\u2014 checking\\u2026'; return; }}
    el.textContent=pad(m)+':'+pad(s);
  }}
  tick();
  setInterval(tick,1000);
}})();
</script>
"""


def page_shell(title: str, body_html: str, accent: str = "",
               head_extra: str = "", body_suffix: str = "",
               wide: bool = False) -> str:
    """Wrap body HTML in the standalone page document.

    `title` (plain text, escaped here), `accent` is the pre-built :root block
    from accent_css(), `head_extra` adds caller-specific <head> tags (report
    meta-refresh), `body_suffix` appends scripts after the container
    (countdown), `wide` widens the container for table-heavy pages.
    """
    container_class = "container wide" if wide else "container"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{head_extra}<title>{html.escape(title)}</title>
<style>{accent}{_STYLE}</style>
</head>
<body>
<div class="{container_class}">
{body_html}
</div>
{body_suffix}
</body>
</html>
"""


# Light "paper" look shared by the score report and the README page: flat
# surfaces separated by hairline rules (no cards/shadows), one accent color,
# generous line height and a capped measure for readability.
_STYLE = """
:root { --ink: #1f2328; --muted: #6e7378; --hairline: #ececea; --rule: #d9d9d4; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
       margin: 0; background: #fbfbf9; color: var(--ink); line-height: 1.65; }
.container { max-width: 46rem; margin: 0 auto; padding: 2.5rem 1.5rem 3rem; }
.container.wide { max-width: 52rem; }
.masthead { display: flex; align-items: center; gap: 0.7rem; margin-bottom: 0.25rem; }
.logo { height: 2rem; width: auto; border-radius: 2px; }
h1 { margin: 0; font-size: 1.5rem; font-weight: 700; letter-spacing: -0.01em;
     line-height: 1.25; padding-bottom: 0.4rem; display: inline-block;
     border-bottom: 2px solid var(--accent, var(--ink)); }
.org { color: var(--muted); margin: 0.4rem 0 0; font-size: 0.9rem; }
.sub, .org { color: var(--muted); }
.sub { margin: 0.5rem 0 0; font-size: 0.85rem; }
a { color: #0b63ce; text-underline-offset: 2px; }
strong { font-weight: 700; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
       font-size: 0.88em; background: #f0f0ec; border-radius: 3px; padding: 0.1em 0.35em; }
pre { background: #f0f0ec; border: 1px solid var(--rule); border-radius: 4px;
      padding: 0.9rem 1.1rem; overflow-x: auto; margin: 1rem 0; }
pre code { background: none; padding: 0; font-size: 0.85rem; }
hr { border: none; border-top: 1px solid var(--rule); margin: 2rem 0; }

/* Score report */
.score-header { display: flex; justify-content: space-between; align-items: flex-end;
                gap: 1rem; flex-wrap: wrap; margin: 2rem 0 0.75rem; }
.total { font-size: 2.1rem; font-weight: 800; letter-spacing: -0.02em; line-height: 1.1;
         color: var(--accent, var(--ink)); }
.total-suffix { font-size: 1rem; font-weight: 600; color: var(--muted); margin-left: 0.2rem; }
.fraction { color: var(--muted); font-size: 0.9rem; margin-top: 0.3rem; }
.countdown-wrap { text-align: right; min-width: 9rem; }
.countdown-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em;
                   color: var(--muted); margin-bottom: 0.2rem; }
.countdown { font-variant-numeric: tabular-nums; font-weight: 700; font-size: 1.3rem;
             color: var(--ink); display: inline-block; min-width: 5rem; text-align: center;
             padding: 0.1rem 0.15rem; border-bottom: 2px solid var(--accent, var(--ink)); }
.progress { height: 6px; background: #e8e8e3; border-radius: 3px; overflow: hidden;
            margin: 0.25rem 0 0.5rem; }
.progress .fill { height: 100%; background: var(--accent, #1a7f37); width: 0%;
                  transition: width 0.45s ease; }
.cards { margin-top: 1.25rem; }
.card { border-top: 1px solid var(--rule); margin-top: 1.5rem; padding-top: 1rem; }
.card h2 { margin: 0 0 0.4rem; font-size: 0.78rem; font-weight: 700;
           text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink);
           display: flex; align-items: center; gap: 0.45rem; }
.card h2 .icon.ok { color: #1a7f37; }
.card h2 .icon.warn { color: #9a6700; }
.card ul { list-style: none; padding: 0; margin: 0; }
.card li { display: flex; justify-content: space-between; gap: 0.75rem; padding: 0.5rem 0;
           border-bottom: 1px solid var(--hairline); font-size: 0.95rem; }
.card li:last-child { border-bottom: none; }
.found-title { flex: 1; overflow: hidden; text-overflow: ellipsis; }
.pts { font-variant-numeric: tabular-nums; font-weight: 700; white-space: nowrap; }
.pts.pos { color: #1a7f37; }
.pts.neg { color: #cf222e; }
.muted { color: var(--muted); }
.remaining { margin: 0.75rem 0 0; font-size: 0.85rem; }
.stamp { color: var(--muted); font-size: 0.85rem; margin: 2.5rem 0 0;
         border-top: 1px solid var(--hairline); padding-top: 1rem; }
.honor-stamp { margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin: 1.5rem 0; }
caption { text-align: left; font-weight: 700; font-size: 0.78rem; text-transform: uppercase;
          letter-spacing: 0.08em; margin-bottom: 0.4rem; color: var(--ink); }
th, td { border-bottom: 1px solid var(--hairline); padding: 0.5rem 0.6rem; text-align: left;
         font-size: 0.9rem; }
th { border-bottom: 2px solid var(--ink); font-size: 0.72rem; text-transform: uppercase;
     letter-spacing: 0.06em; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.up { color: #1a7f37; font-weight: 700; }
.down { color: #cf222e; font-weight: 700; }
.delta-banner { margin: 1.25rem 0 0; padding: 0.6rem 0.9rem; font-weight: 700;
                font-size: 0.95rem; border-left: 3px solid; background: #f0f0ec; }
.delta-banner.up { color: #1a7f37; border-color: #1a7f37; }
.delta-banner.down { color: #cf222e; border-color: #cf222e; }
.pending { font-size: 1rem; padding: 3rem 2rem; border: 1px dashed #c9c9c2; text-align: center;
           margin: 2rem 0 0; color: var(--muted); }

/* README prose (Markdown-rendered body) */
.prose { margin-top: 1.75rem; }
.prose h1 { font-size: 1.35rem; margin: 1.75rem 0 0.6rem; padding-bottom: 0.3rem;
            border-bottom: 1px solid var(--rule); }
.prose h1:first-child { margin-top: 0.25rem; }
.prose h2 { font-size: 1.2rem; margin: 2rem 0 0.6rem; padding-bottom: 0.3rem;
            border-bottom: 1px solid var(--rule); }
.prose h2:first-child { margin-top: 0.25rem; }
.prose h3 { font-size: 1.02rem; margin: 1.5rem 0 0.5rem; }
.prose p { margin: 0.75rem 0; }
.prose ul, .prose ol { margin: 0.75rem 0; padding-left: 1.4rem; }
.prose li { margin: 0.35rem 0; }
"""
