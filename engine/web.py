"""Server-rendered HTML for the public competition site and admin console.

Pure stdlib: every value interpolated into HTML is escaped here. JavaScript is
progressive enhancement only -- every page works with scripts off (live pages
fall back to <noscript> meta refresh; countdowns render server-side).

Design: cream editorial "paper" -- warm ivory ground, panels framed by hard
1px espresso borders, sharp corners, serif headings against small uppercase
sans labels/buttons, flat surfaces (no shadows, no blur). Status is never a
labelled pill: it is a small colored dot beside the text it describes, and the
word lives in the dot's hover/focus tooltip (color is never the only signal).
Every button shares one 32px height -- importance is carried by the fill
color, not size -- and rests on a quiet tint that empties to an outline on
hover. Spacing runs on a 4px token scale (--s1..--s7, --pad-card, --pad-cell)
so padding and rhythm line up across pages; numeric table columns are
right-aligned with tabular figures. Theme colors come from one Python table
(_THEMES) that generates the CSS custom properties, the favicon, and the
accent-contrast anchors; two themes: ``:root`` is the dark-roast palette,
``html[data-theme=light]`` the cream one; a tiny inline script applies the
stored/system theme before first paint. Semantic ok/warn/danger keep their
meaning in both themes (see CLI.md "Terminal styling conventions" for the
shared rules). The per-competition accent ships as server-precomputed text
variants (``--accent-dk`` / ``--accent-lt``), each blended until it clears
4.5:1 on its theme's worst surface -- an espresso accent must never be link
text on dark roast -- plus whisper-fill variants (``--accent-fill-dk`` /
``--accent-fill-lt``) for the primary button's resting state.
"""
import datetime
import html
import json
import re
import time
from typing import Optional

from engine.store import AuditRecord, CompetitionRecord, PlayerRecord

_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULT_ACCENT = "#5f4a38"


def _rgba(hex_color: str, alpha: float) -> str:
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return f"rgba({r},{g},{b},{alpha})"


# Single source for every theme color: the CSS custom properties in CSS, the
# favicon, and the accent-contrast anchors all read this table, so a palette
# edit cannot desync between CSS and Python. The ok/warn/danger -bg tints are
# hand-tuned (they are not alpha blends of their -fg entries) and stored
# verbatim in _SEMANTIC_BG.
_THEMES = {
    "dark": {
        "bg": "#181410", "surface": "#211c16", "surface-2": "#2b251d",
        "header": "#181410",
        "ink": "#efe8da", "ink-2": "#ddd2bf", "muted": "#b3a58f",
        "faint": "#a1947c",
        "line": "#37301f", "line-2": "#5c5140",
        "accent": "#c99a62", "on-accent": "#211c16",
        "ok": "#7fae7a", "warn": "#c9973f", "danger": "#d96f66",
    },
    "light": {
        "bg": "#f7f1e3", "surface": "#efe8d8", "surface-2": "#e6dcc6",
        "header": "#f7f1e3",
        "ink": "#262019", "ink-2": "#50473a", "muted": "#5f5749",
        "faint": "#655c4d",
        "line": "#ddd2ba", "line-2": "#8d7f66",
        "accent": "#5f4a38", "on-accent": "#f7f1e3",
        "ok": "#3a6a41", "warn": "#7c5717", "danger": "#a03a30",
    },
}
_SEMANTIC_BG = {
    "dark": {"ok": _rgba("#7fae7a", .14), "warn": _rgba("#c9973f", .14),
             "danger": _rgba("#c9584f", .13)},
    "light": {"ok": _rgba("#4a7c50", .11), "warn": _rgba("#9a6d1f", .11),
              "danger": _rgba("#a03a30", .08)},
}


def _theme_css() -> str:
    blocks = []
    for theme in ("dark", "light"):
        selector = ":root" if theme == "dark" else "html[data-theme=light]"
        decls = [f"color-scheme:{theme}"]
        decls += [f"--{name}:{value}" for name, value in _THEMES[theme].items()]
        decls += [f"--{name}-bg:{value}"
                  for name, value in _SEMANTIC_BG[theme].items()]
        blocks.append(f"{selector}{{" + ";".join(decls) + "}")
    return "\n".join(blocks)


# Inline SVG favicon: a warm "H" monogram. A data URI avoids a server route and
# the 404 every browser otherwise logs for /favicon.ico.
_FAVICON = ("data:image/svg+xml,"
            "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
            f"%3Crect width='32' height='32' fill='{_THEMES['dark']['bg'].replace('#', '%23')}'/%3E"
            "%3Cpath d='M7 6h5v8h8V6h5v20h-5v-8h-8v8H7z' "
            f"fill='{_THEMES['dark']['accent'].replace('#', '%23')}'/%3E"
            "%3C/svg%3E")


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def sanitize_accent(value) -> str:
    """Clamp an admin-supplied accent to a valid #rrggbb or the default."""
    return value if isinstance(value, str) and _ACCENT_RE.match(value) else DEFAULT_ACCENT


def _accent(comp: Optional[CompetitionRecord]) -> str:
    if comp and comp.theme_json:
        try:
            theme = json.loads(comp.theme_json) or {}
            return sanitize_accent(theme.get("accent"))
        except (ValueError, TypeError):
            pass
    return DEFAULT_ACCENT


def _mix(hex_a: str, hex_b: str, t: float) -> str:
    """Linear hex blend (t=0 -> a, t=1 -> b); used for accent text variants."""
    a = [int(hex_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(hex_b[i:i + 2], 16) for i in (1, 3, 5)]
    mixed = [round(x * (1 - t) + y * t) for x, y in zip(a, b)]
    return "#%02x%02x%02x" % tuple(mixed)


def _rel_lum(hex_color: str) -> float:
    def channel(v):
        v /= 255.0
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _contrast_ratio(fg: str, bg: str) -> float:
    hi, lo = sorted((_rel_lum(fg), _rel_lum(bg)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _on_accent(accent_hex: str) -> str:
    """Readable text color on top of the accent (WCAG-ish relative luminance)."""
    return "#1f2328" if _rel_lum(accent_hex) > 0.45 else "#ffffff"


# The worst surface each theme paints text on (table rows hover to --surface-2),
# and this palette's ink of the matching polarity as the blend anchor.
_CANVAS = {t: _THEMES[t]["surface-2"] for t in _THEMES}
_INK_ANCHOR = {t: _THEMES[t]["ink"] for t in _THEMES}


def _readable_text(accent: str, theme: str, target: float = 4.5) -> str:
    """The accent as *text* on a theme's surfaces.

    Admins pick the accent for the public page and can pick any #rrggbb; an
    espresso accent on dark roast is 1.8:1 as link text. Blend toward the
    theme's ink until the pair clears 4.5:1, passing accents through untouched.
    """
    bg, anchor = _CANVAS[theme], _INK_ANCHOR[theme]
    if _contrast_ratio(accent, bg) >= target:
        return accent
    for i in range(1, 41):
        candidate = _mix(accent, anchor, i / 40)
        if _contrast_ratio(candidate, bg) >= target:
            return candidate
    return anchor


# --- time formatting ---------------------------------------------------------


def _fmt_clock(now: Optional[float] = None) -> str:
    return datetime.datetime.fromtimestamp(time.time() if now is None else now).strftime("%H:%M:%S")


def _fmt_ts(ts) -> str:
    if not ts:
        return "—"
    dt = datetime.datetime.fromtimestamp(float(ts))
    return f"{dt.strftime('%Y-%m-%d %H:%M')} {dt.astimezone().tzname() or ''}".strip()


def _fmt_countdown(seconds) -> str:
    """h:mm:ss (or m:ss under an hour) -- never the ambiguous 119:59 form."""
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}:{m:02d}:{sec:02d}" if h else f"{m}:{sec:02d}"


def _fmt_duration(seconds) -> str:
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, _ = divmod(rem, 60)
    if h and m:
        return f"{h}h {m}m"
    if h:
        return f"{h}h"
    return f"{m} min"


def _rel_ts(ts, now: Optional[float] = None) -> str:
    if not ts:
        return "—"
    now = time.time() if now is None else now
    age = max(0.0, now - float(ts))
    if age < 10:
        return "just now"
    if age < 60:
        return f"{int(age)}s ago"
    if age < 3600:
        return f"{int(age // 60)}m ago"
    if age < 86400:
        return f"{int(age // 3600)}h ago"
    return f"{int(age // 86400)}d ago"


# --- small shared fragments ---------------------------------------------------

_COMP_STATUS = {"live": ("Live", "ok"), "draft": ("Draft", "warn"), "ended": ("Ended", "muted")}
_PLAYER_STATUS = {"invited": ("Invited", "muted"), "running": ("Running", "ok"),
                  "finished": ("Finished", "muted"), "disqualified": ("Disqualified", "danger")}


def _status_dot(status: str, table: dict, prefix: str) -> str:
    """One colored dot; the status word rides in the hover/focus tooltip."""
    label, cls = table.get(status, ((status or "?").title(), "muted"))
    return (f'<button class="sdot {cls}" type="button" data-tip="{esc(label)}" '
            f'aria-label="{prefix} status: {esc(label)}"></button>')


def comp_badge(status: str) -> str:
    return _status_dot(status, _COMP_STATUS, "Competition")


def comp_status_label(status: str) -> str:
    return _COMP_STATUS.get(status, ((status or "?").title(), "muted"))[0]


def player_badge(status: str) -> str:
    return _status_dot(status, _PLAYER_STATUS, "Player")


def _service_dots(services: list) -> str:
    """One colored dot per service (name+state in the tooltip, never color alone)."""
    svc = services or []
    if not svc:
        return '<span class="muted">—</span>'
    dots = "".join(
        f'<i class="dot {"up" if s.get("state") == "UP" else "down" if s.get("state") == "DOWN" else "pending"}"'
        f' title="{esc(s.get("display"))} — {esc(s.get("state"))}" aria-hidden="true"></i>'
        for s in svc
    )
    up = sum(1 for s in svc if s.get("state") == "UP")
    return (f'<span class="svcs">{dots}'
            f'<span class="lbl">{up}/{len(svc)} up</span></span>')


def _copy_btn(value: str, label: str) -> str:
    return (f'<button type="button" class="btn" data-copy="{esc(value)}">'
            f'<span>{esc(label)}</span></button>')


# --- layout -------------------------------------------------------------------

THEME_INIT = (
    "(function(){try{var t=localStorage.getItem('huitz-theme');"
    "if(t!=='light'&&t!=='dark'){t=(window.matchMedia&&"
    "matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light';}"
    "document.documentElement.setAttribute('data-theme',t);}"
    "catch(e){document.documentElement.setAttribute('data-theme','light');}})();"
)

_THEME_TOGGLE = (
    '<button id="theme-toggle" class="icon-btn" type="button"'
    ' aria-label="Toggle dark or light theme" aria-pressed="false" title="Toggle theme">'
    '<svg class="ic-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle>'
    '<path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2'
    'M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>'
    '<svg class="ic-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"></path></svg>'
    '</button>'
)


def layout(title: str, body: str, *, comp: Optional[CompetitionRecord] = None,
           admin: bool = False, refresh: Optional[int] = None,
           body_class: str = "", accent: Optional[str] = None,
           chrome: bool = True, current: str = "") -> str:
    """Shared shell. ``refresh`` only feeds the <noscript> fallback; JS pages
    poll in place. ``chrome=False`` renders the projector board: no header or
    footer, theme pinned to dark. ``current`` ("home"/"admin") marks the nav
    entry for the page so the header reads the same everywhere.
    """
    accent_hex = sanitize_accent(accent or _accent(comp))
    dk = _readable_text(accent_hex, "dark")
    lt = _readable_text(accent_hex, "light")
    accent_vars = (f"--accent:{esc(accent_hex)};--on-accent:{esc(_on_accent(accent_hex))};"
                   f"--accent-dk:{dk};--accent-lt:{lt};"
                   f"--accent-fill-dk:{_rgba(dk, .16)};--accent-fill-lt:{_rgba(lt, .10)}")
    theme_init = THEME_INIT if chrome else 'document.documentElement.setAttribute("data-theme","dark");'
    theme_attr = "" if chrome else ' data-theme="dark"'
    noscript = (f'<noscript><meta http-equiv="refresh" content="{int(refresh)}"></noscript>'
                if refresh else "")
    # One nav on every page: the Admin entry is always the same element in the
    # same slot, so it never jumps between pages. Log out only exists for a
    # live admin session (the route is POST-only, hence the form).
    logout = ('<form method="post" action="/admin/logout">'
              '<button type="submit">Log out</button></form>') if admin else ""
    cur_home = ' aria-current="page"' if current == "home" else ""
    cur_admin = ' aria-current="page"' if current == "admin" else ""
    header = ""
    if chrome:
        header = (
            '<header class="top"><div class="wrap">'
            '<a class="brand" href="/">Huitzilopochtli <span>ranked</span></a>'
            f'<nav><a href="/"{cur_home}>Competitions</a><a href="/admin"{cur_admin}>Admin</a>'
            f'{logout}{_THEME_TOGGLE}</nav>'
            '</div></header>'
        )
    return f"""<!doctype html>
<html lang="en"{theme_attr}><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="{_FAVICON}">
<title>{esc(title)} · Huitzilopochtli</title>{noscript}
<script>{theme_init}</script>
<style>{CSS}</style>
</head><body class="{esc(body_class)}" style="{accent_vars}">
{header}<main class="wrap">{body}</main>
<script>{JS}</script>
</body></html>"""


def error_page(status: int, title: str, detail: str = "",
               back: Optional[str] = None, *, admin: bool = False) -> str:
    back_href = f' href="{esc(back or "/")}"' if back != "" else ""
    back_link = f'<a class="btn"{back_href}>Back</a>' if back != "" else ""
    body = f"""<section class="card narrow err-card">
<p class="err-code">{int(status)}</p>
<h1>{esc(title)}</h1>
{f'<p class="muted">{esc(detail)}</p>' if detail else ''}
{back_link}
</section>"""
    return layout(title, body, admin=admin, current="admin" if admin else "home")


# --- public pages ---------------------------------------------------------------


def _page_head(title: str, back_href: str = "/admin") -> str:
    """Page heading with the back action right-aligned on the same baseline."""
    return (f'<section class="page-head"><h1>{esc(title)}</h1>'
            f'<a class="btn" href="{esc(back_href)}">Back</a></section>')


def _comp_cards(comps: list) -> str:
    if not comps:
        return '<p class="empty">No open competitions right now. Check back soon.</p>'
    rows = []
    for c in comps:
        join = ""
        if c.status == "live" and c.join_open:
            join = f'<a class="btn primary" href="/c/{esc(c.slug)}/join">Join</a>'
        if c.status == "ended":
            meta = "final scores posted"
        else:
            meta = f"{_fmt_duration(c.duration_s)} runs · up to {esc(c.max_players)} players"
        rows.append(f"""<article class="card comp-row"><div class="comp-main">
<div class="comp-title-line"><h2><a href="/c/{esc(c.slug)}">{esc(c.name)}</a></h2>{comp_badge(c.status)}</div>
<p class="comp-meta">{meta}</p></div>
<div class="comp-actions"><a class="btn" href="/c/{esc(c.slug)}">Leaderboard</a>{join}</div>
</article>""")
    return '<section class="comp-list">' + "".join(rows) + "</section>"


def index_page(comps: list, admin_view: bool = False) -> str:
    live = [c for c in comps if c.status == "live"]
    body = f"""<section class="hero">
<h1>Ranked competitions</h1>
<p class="lede">Harden your box, keep your services up, and climb the board. Scores are signed by your box and judged by the engine.</p>
</section>
<h2 class="section-title">Live now</h2>{_comp_cards(live)}"""
    if admin_view:
        other = [c for c in comps if c.status != "live"]
        body += f"""
<h2 class="section-title">Other competitions</h2>{_comp_cards(other)}"""
    return layout("Competitions", body, current="home")


def _join_box(comp: dict) -> str:
    if comp["status"] == "live" and comp["join_open"] and \
            (comp["max_players"] <= 0 or comp["player_count"] < comp["max_players"]):
        return f'<a class="btn primary" href="/c/{esc(comp["slug"])}/join">Join this competition</a>'
    reason = {"draft": "Competition hasn't started.", "ended": "Competition has ended."}.get(comp["status"])
    if not reason:
        reason = ("Competition is full."
                  if comp["join_open"] and comp["max_players"]
                  and comp["player_count"] >= comp["max_players"]
                  else "Joins are closed.")
    return f'<span class="muted small">{esc(reason)}</span>'


def _leader_row(r: dict, first: bool) -> str:
    dots = _service_dots(r.get("services"))
    if r["status"] == "running" and r.get("remaining_s", 0) > 0:
        time_cell = (f'<span class="cd" data-remaining="{int(r["remaining_s"])}"'
                     f'>{esc(_fmt_countdown(r["remaining_s"]))}</span>')
    else:
        time_cell = '<span class="muted">final</span>'
    score = (f'<div class="score-cell"><span class="score">{esc(r["total"])}</span>'
             f'<span class="muted small">H {esc(r["hardening_points"])} · S {esc(r["service_points"])}</span></div>')
    return f"""<tr{' class="leader"' if first else ''}>
<td class="rank">{esc(r['rank'])}</td>
<td><div class="pname"><strong>{esc(r['name'])}</strong>{player_badge(r['status'])}</div></td>
<td class="r">{score}</td>
<td>{dots}</td>
<td class="num r">{time_cell}</td></tr>"""


def _board_table(rows: list) -> str:
    body_rows = "".join(_leader_row(r, i == 0) for i, r in enumerate(rows)) \
        or '<tr><td colspan="5" class="empty">No players yet.</td></tr>'
    return (f'<div class="table-wrap"><table><thead><tr>'
            f'<th class="r">#</th><th>Player</th><th class="r">Score</th>'
            f'<th>Services up</th><th class="r">Time</th></tr></thead>'
            f'<tbody>{body_rows}</tbody></table></div>')


def competition_page(data: dict, *, refresh: int = 5) -> str:
    comp = data["competition"]
    rows = data["leaderboard"]
    body = f"""<section class="page-head-row">
<div><div class="title-line"><h1>{esc(comp['name'])}</h1>{comp_badge(comp['status'])}</div>
<p class="meta">{esc(comp['player_count'])} joined of {esc(comp['max_players'])} · {_fmt_duration(comp['duration_s'])} runs · <a href="/c/{esc(comp['slug'])}/display">Big screen</a></p>
{f'<p class="small muted">{esc(comp.get("join_instructions") or "")}</p>' if comp.get('join_instructions') else ''}</div>
<div class="joinbox">{_join_box(comp)}</div>
</section>
<div id="board" data-poll="{refresh * 1000}">
<section class="card"><div class="card-head"><h2>Leaderboard</h2>
<span class="meta">auto-updates · <span class="updated" data-updated>{esc(_fmt_clock())}</span></span></div>
{_board_table(rows)}
</section>
</div>"""
    accent = (comp.get("theme") or {}).get("accent")
    return layout(comp["name"], body, refresh=refresh, accent=accent, current="home")


def display_page(data: dict) -> str:
    comp = data["competition"]
    rows = data["leaderboard"][:10]
    board = "".join(f"""<div class="display-row">
<span class="rank">{esc(r['rank'])}</span>
<span class="name">{esc(r['name'])}</span>
<span class="score">{esc(r['total'])}</span>
<span class="time">{f'<span data-remaining="{int(r["remaining_s"])}">{esc(_fmt_countdown(r["remaining_s"]))}</span>' if r['status'] == 'running' and r.get('remaining_s', 0) > 0 else '<span class="muted">final</span>'}</span>
<span>{_service_dots(r.get('services'))}</span>
</div>""" for r in rows) or '<p class="empty">Waiting for players…</p>'
    body = f"""<section class="display-head"><div class="title-line"><h1>{esc(comp['name'])}</h1>{comp_badge(comp['status'])}</div></section>
<div id="board" data-poll="5000">
<section class="display-board">{board}</section>
<p class="display-meta">{esc(len(rows))} on the board · auto-updates · <span class="updated" data-updated>{esc(_fmt_clock())}</span></p>
</div>"""
    accent = (comp.get("theme") or {}).get("accent")
    return layout(comp["name"], body, refresh=5, body_class="display", accent=accent, chrome=False)


def join_form_page(comp: CompetitionRecord, error: str = "",
                   closed_notice: str = "") -> str:
    if closed_notice:
        body = f"""<section class="hero"><h1>Join {esc(comp.name)}</h1></section>
<section class="card narrow center">
<p class="muted">{esc(closed_notice)}</p>
<a class="btn" href="/c/{esc(comp.slug)}">Back to the leaderboard</a>
</section>"""
        return layout(f"Join {comp.name}", body, comp=comp, current="home")
    body = f"""<section class="hero"><h1>Join {esc(comp.name)}</h1>
<p class="lede">Enter the name your competitors will see. You will get a VM link and a one-time code to run inside the box.</p></section>
<section class="card narrow">
{f'<p class="error">{esc(error)}</p>' if error else ''}
<form method="post" action="/c/{esc(comp.slug)}/join" class="stack">
<label>Display name<input name="name" maxlength="40" required autofocus placeholder="e.g. Ada"></label>
<button class="btn primary" type="submit">Join and get my box</button>
</form>
<p class="muted small">By joining you agree to compete on a disposable ranked box. One box per player; no teams. Provisioning your VM can take a minute.</p>
</section>"""
    return layout(f"Join {comp.name}", body, comp=comp, current="home")


def _claim_retry_form(player: PlayerRecord, csrf: str) -> str:
    return f"""<form method="post" action="/api/public/join/{esc(player.player_id)}/claim" class="inline">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<button class="btn" type="submit">Get a new VM</button></form>"""


def join_success_page(comp: CompetitionRecord, player: PlayerRecord,
                      join_code: str = "", csrf: str = "") -> str:
    code = join_code or player.join_code_plain or ""
    url = player.claim_url
    bound = bool(player.box_id)
    pending = bool(player.claim_ticket and not url)
    err = (player.claim_error or "").strip()

    parts = []
    if url:
        parts.append(
            f'<div class="vm-actions"><a class="btn primary" href="{esc(url)}" '
            f'target="_blank" rel="noopener">Open my VM</a> '
            f'{_copy_btn(url, "Copy link")}</div>')
    if bound:
        parts.append('<p class="okmsg">Your box is joined — the run is live.</p>')
        parts.append(f'<p class="actions"><a class="btn" href="/c/{esc(comp.slug)}/me">My status</a> '
                     f'<a class="btn" href="/c/{esc(comp.slug)}">Leaderboard</a></p>')
    elif url:
        parts.append('<p class="muted small">Your clock starts when you open it. '
                     'The same link re-opens your VM any time while it lives.</p>')
    elif pending:
        parts.append('<p class="muted" id="vm-wait">Your VM is being prepared — '
                     'this page updates automatically.</p>')
        parts.append(_claim_retry_form(player, csrf))
    elif err:
        parts.append(f'<p class="error">We couldn\'t prepare your VM: {esc(err)}</p>')
        parts.append(_claim_retry_form(player, csrf))
    else:
        parts.append('<p class="muted" id="vm-wait">Your VM will appear here '
                     'automatically — provisioning retries in the background.</p>')
        parts.append(_claim_retry_form(player, csrf))
    step1 = "".join(parts)

    vm_script = ""
    if not bound:
        vm_script = f"""
<script>
(function(){{
  var pid={json.dumps(player.player_id)};
  var startUrl={json.dumps(url or "")};
  var startErr={json.dumps(err)};
  var startCodeExp={json.dumps(player.join_code_expires_at or 0)};
  var polls=0;
  var t=setInterval(function(){{
    if(++polls>200){{ clearInterval(t); return; }}
    fetch('/api/public/join/'+pid+'/status').then(function(r){{return r.ok?r.json():null;}}).then(function(d){{
      if(!d) return;
      if(d.box_bound){{ location.reload(); return; }}
      if((d.claim_url||'')!==startUrl||(d.claim_error||'')!==startErr||
         (d.code_expires_at||0)!==startCodeExp){{ location.reload(); }}
    }}).catch(function(){{}});
  }},3000);
}})();
</script>"""

    codebox = (f'<div class="codebox"><code id="joincode">{esc(code)}</code>'
               f'{_copy_btn(code, "Copy code")}</div>' if code else
               '<p class="muted small">No fallback code is available.</p>')
    fallback = f"""<li><h2>Join from the terminal (only if needed)</h2>
<p class="small">You normally never need this — the VM joins itself when
you open the link. If it doesn't, open a terminal in the VM and run:</p>
<pre><code>huitz join</code></pre>
<p>When prompted, enter this code:</p>
{codebox}
<p class="small">The code is single-use and expires; this page updates itself
when it does.</p></li>"""

    body = f"""<section class="page-head-row"><div>
<div class="title-line"><h1>You're in, {esc(player.display_name)}</h1></div>
<p class="meta">Competition: {esc(comp.name)} · your clock starts when you open the VM.</p></div></section>
<section class="card narrow">
<ol class="steps">
<li><h2>Your VM</h2>{step1}</li>{vm_script}
{fallback if err else ''}
<li><h2>Watch the board</h2>
<p><a href="/c/{esc(comp.slug)}">Leaderboard</a> · <a href="/c/{esc(comp.slug)}/me">My status</a></p></li>
</ol>
</section>"""
    return layout("You're in", body, comp=comp, current="home",
                  refresh=None if bound else 5)


def player_page(comp: CompetitionRecord, player: PlayerRecord,
                board_row: Optional[dict], claim_url: Optional[str],
                csrf: str = "") -> str:
    row = board_row or {}
    running = player.status == "running"
    remaining = max(0, int(player.ends_at - time.time())) if (running and player.ends_at) else 0
    if row:
        score = (f'<div class="bigscore">{esc(row.get("total", 0))}</div>'
                 f'<div class="scoresplit"><span>hardening {esc(row.get("hardening_points", 0))}</span>'
                 f'<span>services {esc(row.get("service_points", 0))}</span></div>')
    else:
        score = ('<div class="bigscore muted">—</div>'
                 '<div class="muted small">Your box hasn\'t joined yet — open your VM; '
                 'it joins itself.</div>')
    if running:
        time_block = (f'<span data-remaining="{remaining}">{esc(_fmt_countdown(remaining))}</span>')
    elif player.status == "invited":
        time_block = '<span class="muted small">starts when your box joins</span>'
    else:
        time_block = '<span class="muted">final</span>'
    body = f"""<section class="page-head-row"><div>
<div class="title-line"><h1>{esc(player.display_name)}</h1>{player_badge(player.status)}</div>
<p class="meta">{esc(comp.name)}</p></div></section>
<div id="run" data-poll="15000">
<section class="card narrow">
<div class="row me-top">
<div>{score}</div>
<div class="me-right"><div class="muted small">Time remaining</div>
<div class="bigtime">{time_block}</div>
<div class="muted small">ends {esc(_fmt_ts(player.ends_at))}</div></div>
</div>
<dl class="kv">
<dt>Status</dt><dd>{player_badge(player.status)}</dd>
<dt>Last check-in</dt><dd>{esc(_rel_ts(row.get("last_checkin")))}</dd>
</dl>
{f'<p><a class="btn primary" href="{esc(claim_url)}" target="_blank" rel="noopener">Open my VM</a></p>' if claim_url else ''}
{'' if player.box_id or player.claim_url or player.claim_ticket else _claim_retry_form(player, csrf)}
{f'<p class="error">{esc(player.claim_error)}</p>' if player.claim_error else ''}
<p><a href="/c/{esc(comp.slug)}">Leaderboard →</a></p>
</section>
</div>"""
    return layout(player.display_name, body, comp=comp, current="home")


# --- admin pages -----------------------------------------------------------------


def login_page(error: str = "") -> str:
    body = f"""<section class="card narrow login">
<h1>Admin login</h1>
{f'<p class="error">{esc(error)}</p>' if error else ''}
<form method="post" action="/admin/login" class="stack">
<label>Username<input name="username" autocomplete="username" autofocus required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button class="btn primary" type="submit">Sign in</button>
</form></section>"""
    return layout("Admin login", body, admin=False)


def admin_dashboard_page(comps: list, players_by_comp: dict,
                         csrf: str, msg: str = "") -> str:
    cards = []
    for c in comps:
        n = players_by_comp.get(c.id, 0)
        cards.append(f"""<tr><td><a href="/admin/competitions/{esc(c.id)}">{esc(c.name)}</a><div class="muted small">/c/{esc(c.slug)}</div></td>
<td>{comp_badge(c.status)}</td><td class="num r">{esc(n)}/{esc(c.max_players)}</td>
<td class="num r">{esc(_fmt_duration(c.duration_s))}</td><td><a class="btn" href="/c/{esc(c.slug)}">View</a></td></tr>""")
    body = f"""<section class="page-head-row"><div><h1>Admin console</h1></div>
<div class="actions"><a class="btn primary" href="/admin/competitions/new">New competition</a></div></section>
{f'<p class="okmsg">{esc(msg)}</p>' if msg else ''}
<div id="dash" data-poll="30000">
<section class="card"><div class="card-head"><h2>Competitions</h2>
<span class="meta">auto-updates · <span class="updated" data-updated>{esc(_fmt_clock())}</span></span></div>
<div class="table-wrap"><table><thead><tr><th>Name</th><th>Status</th><th class="r">Players</th><th class="r">Duration</th><th></th></tr></thead><tbody>{''.join(cards) or '<tr><td colspan="5" class="empty">No competitions yet.</td></tr>'}</tbody></table></div></section>
</div>"""
    return layout("Admin", body, admin=True, current="admin")


def admin_new_competition_page(scenarios: list, csrf: str, error: str = "") -> str:
    opts = "".join(
        f'<option value="{esc(name)}|{esc(version)}">{esc(name)} v{esc(version)}</option>'
        for name, version, _path in scenarios
    )
    body = f"""{_page_head("New competition")}
{f'<p class="error">{esc(error)}</p>' if error else ''}
<section class="card narrow"><form method="post" action="/admin/competitions/new" class="stack">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<label>Name<input name="name" required placeholder="Friday Night Ranked" autofocus></label>
<label>Scenario<select name="scenario" required>{opts or '<option value="">No ranked scenarios found</option>'}</select><span class="help">Ranked scenarios uploaded to the engine or built in the box folder.</span></label>
<div class="form-grid">
<label>Max players<input name="max_players" type="number" min="1" value="32"></label>
<label>Run duration (minutes)<input name="duration_min" type="number" min="1" value="120"></label>
</div>
<label>Accent color<input name="accent" type="color" value="#5f4a38"></label>
<button class="btn primary" type="submit">Create draft</button></form></section>"""
    return layout("New competition", body, admin=True, current="admin")


def admin_competition_page(comp: CompetitionRecord, board: dict, players: list,
                           csrf: str, msg: str = "", error: str = "") -> str:
    now = time.time()
    rows = []
    for p in players:
        row = next((r for r in board.get("leaderboard", []) if r["player_id"] == p.player_id), {})
        if row:
            score = (f'<div class="score-cell"><span class="score">{esc(row.get("total", 0))}</span>'
                     f'<span class="muted small">H {esc(row.get("hardening_points", 0))} · S {esc(row.get("service_points", 0))}</span></div>')
        elif p.status == "invited":
            score = '<span class="small muted">not started</span>'
        else:
            score = '<span class="muted">—</span>'
        last = row.get("last_checkin")
        stale = (p.status == "running" and (not last or now - float(last) > 120))
        checkin = (f'<span class="{"stale" if stale else ""}">{esc(_rel_ts(last))}</span>'
                   if (last or p.status == "running") else '<span class="muted">—</span>')
        neutral, danger = [], []
        if p.status == "invited" and not p.box_id:
            neutral.append(f'<form method="post" action="/admin/players/{esc(p.player_id)}/retry-claim" class="inline">'
                           f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                           f'<button class="btn">Retry VM</button></form>')
        if p.status == "invited":
            neutral.append(f'<form method="post" action="/admin/players/{esc(p.player_id)}/reissue" class="inline">'
                           f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                           f'<button class="btn">Reissue code</button></form>')
        if p.status in ("running", "finished"):
            danger.append(f'<form method="post" action="/admin/players/{esc(p.player_id)}/disqualify" class="inline"'
                          f' onsubmit="return confirm(\'Disqualify this player?\')">'
                          f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                          f'<button class="btn danger">Disqualify</button></form>')
        if p.status in ("invited", "running", "finished"):
            danger.append(f'<form method="post" action="/admin/players/{esc(p.player_id)}/remove" class="inline"'
                          f' onsubmit="return confirm(\'Remove this player from the competition?\')">'
                          f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                          f'<button class="btn danger">Remove</button></form>')
        sep = '<span class="act-sep" aria-hidden="true"></span>' if neutral and danger else ""
        actions = "".join(neutral) + sep + "".join(danger)
        claim_note = (f'<div class="small error">{esc(p.claim_error)}</div>'
                      if getattr(p, "claim_error", None) else "")
        rows.append(f"""<tr><td><div class="pname"><strong>{esc(p.display_name)}</strong>{player_badge(p.status)}</div>{claim_note}</td>
<td class="r">{score}</td>
<td>{_service_dots(row.get('services'))}</td>
<td class="num r">{checkin}</td>
<td class="muted small">{esc(p.box_id or '—')}</td>
<td class="small">{f'<div class="row-actions">{actions}</div>' if actions else '<span class="muted">—</span>'}</td></tr>""")
    controls = []
    if comp.status == "draft":
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/start" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn primary">Start competition</button></form>')
    if comp.status == "live":
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/close-join" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn">Close joins</button></form>')
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/end" class="inline" onsubmit="return confirm(\'End the competition for everyone?\')"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn danger">End competition</button></form>')
    if comp.status == "ended":
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/rerun" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn primary">Rerun competition</button></form>')
    join_url = f"/c/{comp.slug}/join"
    # The pool code is portal plumbing (audit log / journal carry it for
    # debugging); the UI stays quiet about pools unless a claim actually fails,
    # in which case the error text lands on the player row.
    body = f"""<section class="page-head-row">
<div><div class="title-line"><h1>{esc(comp.name)}</h1>{comp_badge(comp.status)}</div>
<p class="meta">/c/{esc(comp.slug)} · {esc(comp.scenario_name)} v{esc(comp.scenario_version)}</p></div>
<div class="actions">{''.join(controls)}</div></section>
{f'<p class="okmsg">{esc(msg)}</p>' if msg else ''}{f'<p class="error">{esc(error)}</p>' if error else ''}
<section class="card"><div class="card-head"><h2>Settings</h2></div>
<div class="facts">
<div class="fact"><span class="fact-label">Status</span><span class="fact-value">{esc(comp_status_label(comp.status))} {comp_badge(comp.status)}</span></div>
<div class="fact"><span class="fact-label">Players</span><span class="fact-value">{esc(len(players))} / {esc(comp.max_players)} joined</span></div>
<div class="fact"><span class="fact-label">Run duration</span><span class="fact-value">{_fmt_duration(comp.duration_s)} runs</span></div>
<div class="fact wide"><span class="fact-label">Join URL</span>
<span class="fact-value"><code>{esc(join_url)}</code> {_copy_btn(join_url, "Copy")}
<a class="btn" href="/admin/api/competitions/{esc(comp.id)}/export.csv">Export CSV</a></span></div>
</div></section>
<div id="roster" data-poll="15000">
<section class="card"><div class="card-head"><h2>Players ({esc(len(players))})</h2>
<span class="meta">auto-updates · <span class="updated" data-updated>{esc(_fmt_clock())}</span></span></div>
<div class="table-wrap"><table class="roster"><thead><tr><th>Player</th><th class="r">Score</th><th>Services</th><th class="r">Check-in</th><th>Box</th><th>Actions</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="6" class="empty">No players yet.</td></tr>'}</tbody></table></div></section>
</div>"""
    return layout(comp.name, body, comp=comp, admin=True, current="admin")




# --- design system ---------------------------------------------------------------

CSS = _theme_css() + """
:root{--font-sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--font-serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
--s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;--s7:48px;
--pad-card:var(--s4) var(--s5);--pad-cell:var(--s2) var(--s3);
--control:32px;--gap-stack:var(--s4);--margin-trail:var(--s7)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 var(--font-sans);
--accent-text:var(--accent-dk);--accent-fill:var(--accent-fill-dk)}
html[data-theme=light] body{--accent-text:var(--accent-lt);--accent-fill:var(--accent-fill-lt)}
h1,h2,.brand,.bigscore,.bigtime,.err-code{font-family:var(--font-serif)}
h1,h2{letter-spacing:-.005em;margin:0}
h1{font-size:clamp(1.45rem,3vw,1.95rem)}h2{font-size:1.05rem}
a{color:var(--accent-text);text-decoration:none}a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent-text);outline-offset:2px}
.wrap{max-width:1180px;margin:0 auto;padding:0 var(--s5)}
main.wrap{display:flex;flex-direction:column;gap:var(--gap-stack);padding:var(--s6) var(--s5) var(--s7)}
.top{position:sticky;top:0;z-index:20;background:var(--header);border-bottom:1px solid var(--line-2)}
.top .wrap{display:flex;align-items:center;justify-content:space-between;gap:var(--s5);min-height:56px}
.brand{font-weight:700;color:var(--ink);font-size:1.08rem}
.brand span{color:var(--accent-text);font-family:var(--font-sans);font-weight:700;font-size:.64rem;letter-spacing:.18em;text-transform:uppercase;margin-left:.5rem;vertical-align:middle}
nav{display:flex;gap:var(--s5);align-items:center}
nav a,nav button{color:var(--ink-2);font-weight:600;font-size:.76rem;letter-spacing:.09em;text-transform:uppercase;background:none;border:0;padding:0;cursor:pointer;font-family:var(--font-sans)}
nav a:hover,nav button:hover{color:var(--ink);text-decoration:none}
nav a[aria-current]{color:var(--ink);box-shadow:inset 0 -2px 0 var(--accent-text);padding-bottom:4px}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:var(--control);height:var(--control);border:1px solid var(--line-2);border-radius:0;background:transparent;color:var(--ink-2);cursor:pointer}
.icon-btn:hover{color:var(--ink);border-color:var(--line-2)}
.icon-btn svg{width:1rem;height:1rem}
html[data-theme=dark] .ic-moon{display:none}html[data-theme=light] .ic-sun{display:none}
.section-title{margin:var(--s6) 0 calc(-1 * var(--s2));color:var(--muted);font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em}
.hero{padding:var(--s2) 0 0}
.hero .lede{margin:.35rem 0 0;color:var(--muted);max-width:46rem;font-family:var(--font-serif);font-size:1.02rem}
.page-head,.page-head-row{display:flex;align-items:flex-end;justify-content:space-between;gap:var(--s4);flex-wrap:wrap;padding:var(--s2) 0 0}
.title-line{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.meta{margin:.3rem 0 0;color:var(--muted);font-size:.9rem}
.actions{display:flex;gap:var(--s2);flex-wrap:wrap}
/* Status is a colored dot beside the text it describes; the word rides in the
hover/focus tooltip (data-tip), so color is never the only signal. */
.sdot{display:inline-block;width:8px;height:8px;border-radius:50%;position:relative;border:0;padding:0;background:transparent;cursor:help;color:var(--muted)}
.sdot::before{content:"";display:block;width:100%;height:100%;border-radius:50%;background:currentColor}
.sdot.ok{color:var(--ok)}.sdot.warn{color:var(--warn)}.sdot.danger{color:var(--danger)}
.sdot.lg{width:10px;height:10px}
.sdot:hover::after,.sdot:focus-visible::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 7px);left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;line-height:1;padding:5px 8px;white-space:nowrap;z-index:40;pointer-events:none;border-radius:2px}
.sdot:focus-visible{outline:2px solid var(--accent-text);outline-offset:2px}
.pname{display:flex;align-items:center;gap:var(--s2);min-width:0}
/* One button height everywhere; importance is the fill color, not size. Every
button rests on a quiet tint and empties to an outline on hover. */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--s2);height:var(--control);padding:0 14px;background:var(--surface-2);color:var(--ink-2);border:1px solid transparent;border-radius:0;font-family:var(--font-sans);font-weight:700;font-size:11.5px;letter-spacing:.07em;text-transform:uppercase;cursor:pointer}
.btn:hover{background:transparent;border-color:currentColor;color:var(--ink);text-decoration:none;filter:none}
.btn.primary{color:var(--accent-text);background:var(--accent-fill)}
.btn.primary:hover{background:transparent;border-color:var(--accent-text);color:var(--accent-text)}
.btn.danger{color:var(--danger);background:var(--danger-bg)}
.btn.danger:hover{background:transparent;border-color:var(--danger);color:var(--danger)}
.btn.copied{color:var(--ok);border-color:var(--ok);background:transparent}
.card{background:var(--surface);border:1px solid var(--line);border-radius:0;padding:var(--pad-card)}
.card.narrow{max-width:640px;margin-left:auto;margin-right:auto}
.card h1{font-size:1.3rem}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:var(--s4);min-height:var(--control);margin-bottom:var(--s3)}
.card-head .meta{margin:0;white-space:nowrap;font-variant-numeric:tabular-nums}
.center{text-align:center}
.row{display:flex;align-items:center;justify-content:space-between;gap:var(--s4);flex-wrap:wrap}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:var(--s4) var(--s5)}
.fact{display:flex;flex-direction:column;gap:var(--s1);min-width:0}
.fact-label{color:var(--muted);font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.09em}
.fact-value{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap;font-variant-numeric:tabular-nums}
.fact.wide{grid-column:1 / -1}
.table-wrap{overflow-x:auto;margin:calc(-1 * var(--s2)) calc(-1 * var(--s3))}
table{width:100%;border-collapse:collapse}
th,td{padding:var(--pad-cell);text-align:left;vertical-align:middle;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.09em;white-space:nowrap;border-bottom:1px solid var(--line-2)}
th.r,td.r{text-align:right}
tbody tr:hover td{background:var(--surface-2)}
tbody tr:last-child td{border-bottom:0}
td.rank{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
.score{font-weight:700;font-variant-numeric:tabular-nums}
.score-cell{display:flex;flex-direction:column;align-items:flex-end;gap:2px}
.num{font-variant-numeric:tabular-nums}
tr.leader td:first-child{box-shadow:inset 3px 0 0 var(--accent-text)}
.svcs{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.svcs .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.svcs .dot.up{background:var(--ok)}.svcs .dot.down{background:var(--danger)}.svcs .dot.pending{background:var(--muted)}
.svcs .lbl{color:var(--muted);font-size:.8rem;margin-left:4px;font-variant-numeric:tabular-nums}
.muted{color:var(--muted)}.small{font-size:.82rem}
.empty{color:var(--muted);text-align:center;padding:var(--pad-card)}
.updated{font-variant-numeric:tabular-nums}
.inline{display:inline}
.row-actions{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap}
.row-actions form{display:inline-flex}
.act-sep{width:1px;height:16px;background:var(--line-2);flex:none;margin:0 2px}
.joinbox{min-width:220px;display:flex;flex-direction:column;gap:var(--s2);align-items:flex-end;text-align:right}
.comp-list{display:flex;flex-direction:column;gap:var(--s3)}
.comp-row{display:flex;align-items:center;justify-content:space-between;gap:var(--s5);flex-wrap:wrap}
.comp-main{flex:1;min-width:260px}
.comp-title-line{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.comp-title-line h2{font-size:1.15rem}
.comp-title-line h2 a{color:var(--ink)}
.comp-meta{margin:2px 0 0;color:var(--faint);font-size:.86rem}
.comp-actions{display:flex;gap:var(--s2);flex-wrap:wrap}
.stack{display:flex;flex-direction:column;gap:var(--s3)}
label{display:flex;flex-direction:column;gap:.32rem;color:var(--ink-2);font-weight:600;font-size:.92rem}
input,select,textarea{background:var(--bg);border:1px solid var(--line-2);border-radius:0;color:var(--ink);font:inherit;width:100%}
input,select{height:var(--control);padding:0 .6rem}
textarea{padding:.5rem .6rem}
input[type=color]{padding:.15rem;width:3.2rem;height:2.2rem;cursor:pointer}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent-text);outline-offset:1px;border-color:var(--accent-text)}
.help{color:var(--muted);font-size:.8rem;font-weight:400}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--s3)}
code{background:var(--surface-2);border-radius:0;padding:.08rem .35rem;font-size:.9em}
pre{background:var(--bg);border:1px solid var(--line);border-radius:0;padding:var(--pad-card);overflow:auto}
pre code{background:none;padding:0}
.codebox{display:flex;align-items:center;justify-content:center;gap:var(--s3);font-size:1.9rem;letter-spacing:.28em;text-align:center;background:var(--bg);border:1px dashed var(--line-2);border-radius:0;padding:var(--pad-card);font-weight:800}
.codebox code{background:none;letter-spacing:inherit;padding:0}
.vm-actions{display:grid;grid-template-columns:1fr 1fr;gap:var(--s2)}
.okmsg{color:var(--ok);background:var(--ok-bg);border:1px solid var(--ok);border-radius:0;padding:.6rem .85rem}
.error{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger);border-radius:0;padding:.6rem .85rem}
.stale{color:var(--warn)}
.steps{list-style:none;counter-reset:step;padding:0;margin:0}
.steps>li{position:relative;padding:0 0 1.7rem 2.7rem;margin:0}
.steps>li:last-child{padding-bottom:.2rem}
.steps>li::before{counter-increment:step;content:counter(step);position:absolute;left:0;top:-.1rem;width:1.75rem;height:1.75rem;border-radius:0;background:var(--accent);color:var(--on-accent);font-weight:700;font-size:.9rem;display:flex;align-items:center;justify-content:center;font-family:var(--font-sans)}
.steps>li:not(:last-child)::after{content:"";position:absolute;left:.85rem;top:1.9rem;bottom:.25rem;width:1px;background:var(--line)}
.steps h2{font-size:1.02rem}
.login{margin-top:var(--margin-trail)}
.err-card{text-align:center;margin-top:var(--margin-trail)}
.err-code{font-size:2.4rem;font-weight:800;color:var(--muted);margin:.2rem 0}
.bigscore{font-size:2.6rem;font-weight:800;font-variant-numeric:tabular-nums;line-height:1.15}
.bigtime{font-size:1.9rem;font-weight:700;font-variant-numeric:tabular-nums}
.scoresplit{display:flex;gap:var(--s5);color:var(--muted);font-size:.9rem}
.me-top{align-items:flex-start}
.me-right{text-align:right}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.35rem var(--s5);margin:var(--s3) 0 0;border-top:1px solid var(--line);padding-top:var(--s3)}
.kv dt{color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}.kv dd{margin:0;font-variant-numeric:tabular-nums}
body.display{background:#0f0c09}
body.display main{display:block;max-width:1200px;padding:2.2rem 2rem}
.display-head{display:flex;align-items:center;justify-content:center;gap:var(--s5);flex-wrap:wrap;margin-bottom:1.4rem}
.display-head h1{font-size:2.2rem}
.display-board{max-width:1100px;margin:0 auto}
.display-row{display:grid;grid-template-columns:90px 1fr 200px 150px 140px;gap:var(--s5);align-items:center;padding:var(--pad-card);border-bottom:1px solid var(--line);font-size:1.45rem}
.display-row .rank{font-size:1.9rem}
.display-row .name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.display-row .score{font-size:2rem;font-weight:800;text-align:right;font-variant-numeric:tabular-nums}
.display-row .time{font-size:1.05rem;text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
.display-row .svcs .dot{width:11px;height:11px}
.display-row .svcs .lbl{display:none}
.display-meta{text-align:center;color:var(--muted);margin-top:var(--margin-trail)}
@media(max-width:720px){
.wrap{padding:0 var(--s4)}
main.wrap{padding:var(--s4) var(--s4) var(--s6)}
.top .wrap{flex-wrap:wrap;gap:.5rem;padding-top:.5rem;padding-bottom:.5rem}
nav{gap:var(--s3)}
.hero h1{font-size:1.35rem}
.joinbox{align-items:flex-start;text-align:left}
.form-grid{grid-template-columns:1fr}
.display-row{font-size:.95rem;grid-template-columns:36px 1fr 90px;gap:.6rem}
.display-row .time,.display-row .svcs{display:none}
.display-head h1{font-size:1.5rem}
}
"""

JS = """
(function(){
'use strict';
function $all(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s));}
var tbtn=document.getElementById('theme-toggle');
if(tbtn){
  tbtn.addEventListener('click',function(){
    var r=document.documentElement;
    var next=r.getAttribute('data-theme')==='light'?'dark':'light';
    r.setAttribute('data-theme',next);
    try{localStorage.setItem('huitz-theme',next);}catch(e){}
    tbtn.setAttribute('aria-pressed',next==='dark'?'true':'false');
  });
  tbtn.setAttribute('aria-pressed',
    document.documentElement.getAttribute('data-theme')==='dark'?'true':'false');
}
function flash(btn){
  var lbl=btn.querySelector('span');if(!lbl)return;
  var old=lbl.textContent;lbl.textContent='Copied';btn.classList.add('copied');
  setTimeout(function(){lbl.textContent=old;btn.classList.remove('copied');},1400);
}
document.addEventListener('click',function(ev){
  var btn=ev.target.closest?ev.target.closest('[data-copy]'):null;
  if(!btn)return;
  var val=btn.getAttribute('data-copy');
  function done(){flash(btn);}
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(val).then(done,function(){});
  }else{
    var ta=document.createElement('textarea');ta.value=val;
    ta.style.position='fixed';ta.style.opacity='0';
    document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');done();}catch(e){}
    document.body.removeChild(ta);
  }
});
function pad(n){return (n<10?'0':'')+n;}
function fmtDur(s){
  s=Math.max(0,Math.floor(s));
  var h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  return h>0?h+':'+pad(m)+':'+pad(sec):m+':'+pad(sec);
}
function armCountdowns(){
  $all('[data-remaining]').forEach(function(el){
    if(el._dl===undefined){
      var r=parseFloat(el.getAttribute('data-remaining'));
      el._dl=isFinite(r)?Date.now()/1000+r:null;
    }
  });
}
function tickCountdowns(){
  $all('[data-remaining]').forEach(function(el){
    if(!el._dl)return;
    var s=el._dl-Date.now()/1000;
    if(s<=0){el.textContent=el.getAttribute('data-final')||'0:00';el._dl=null;}
    else{el.textContent=fmtDur(s);}
  });
}
armCountdowns();tickCountdowns();setInterval(tickCountdowns,1000);
var lastTouch=0;
document.addEventListener('click',function(ev){
  if(ev.target.closest&&ev.target.closest('[data-poll]')){lastTouch=Date.now();}
},true);
function poll(){
  if(document.hidden){return;}
  var ae=document.activeElement;
  if(ae&&ae.closest&&ae.closest('[data-poll]')){return;}
  if(Date.now()-lastTouch<8000){return;}
  $all('[data-poll]').forEach(function(node){
    if(!node.id){return;}
    fetch(location.href,{credentials:'same-origin'}).then(function(r){
      if(!r.ok){throw 0;}return r.text();
    }).then(function(text){
      var doc=new DOMParser().parseFromString(text,'text/html');
      var fresh=doc.getElementById(node.id);
      if(fresh&&fresh.outerHTML!==node.outerHTML){
        node.replaceWith(fresh);armCountdowns();
      }
    }).catch(function(){});
  });
}
var rates=$all('[data-poll]').map(function(n){
  return parseInt(n.getAttribute('data-poll'),10)||0;
}).filter(function(v){return v>=2000;});
if(rates.length){setInterval(poll,Math.min.apply(null,rates));}
})();
"""
