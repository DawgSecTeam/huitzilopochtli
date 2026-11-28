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
import hashlib
import html
import json
import re
import time
from typing import Optional

from common.schema import SLA_HISTORY_MAX
from engine import build as engine_build
from engine import claims
from engine import competition
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
        # The projector board keeps its near-black ground in both themes.
        "display-bg": "#0f0c09",
    },
    "light": {
        "bg": "#f7f1e3", "surface": "#efe8d8", "surface-2": "#e6dcc6",
        "header": "#f7f1e3",
        "ink": "#262019", "ink-2": "#50473a", "muted": "#5f5749",
        "faint": "#655c4d",
        "line": "#ddd2ba", "line-2": "#8d7f66",
        "accent": "#5f4a38", "on-accent": "#f7f1e3",
        "ok": "#3a6a41", "warn": "#7c5717", "danger": "#a03a30",
        "display-bg": "#0f0c09",
    },
}
_SEMANTIC_BG = {
    "dark": {"ok": _rgba("#7fae7a", .14), "warn": _rgba("#c9973f", .14),
             "danger": _rgba("#c9584f", .13)},
    "light": {"ok": _rgba("#4a7c50", .11), "warn": _rgba("#9a6d1f", .11),
              "danger": _rgba("#a03a30", .08)},
}


def _theme_css() -> str:
    def decls(theme: str) -> str:
        d = [f"color-scheme:{theme}"]
        d += [f"--{name}:{value}" for name, value in _THEMES[theme].items()]
        d += [f"--{name}-bg:{value}" for name, value in _SEMANTIC_BG[theme].items()]
        return ";".join(d)
    dark, light = decls("dark"), decls("light")
    # Dark roast is the :root base; with JS off, a light-OS preference arrives
    # through the media query. An explicit data-theme attribute (set by the
    # init script, or server-side for the projector board) outranks both.
    return "\n".join([
        f":root{{{dark}}}",
        f"@media (prefers-color-scheme: light){{:root{{{light}}}}}",
        f"html[data-theme=light]{{{light}}}",
        f"html[data-theme=dark]{{{dark}}}",
    ])


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


def _fmt_short_ts(ts) -> str:
    """Compact timestamp for tight table cells: today shows the time only."""
    if not ts:
        return "—"
    dt = datetime.datetime.fromtimestamp(float(ts))
    now = datetime.datetime.now()
    if dt.date() == now.date():
        return dt.strftime("%H:%M")
    return dt.strftime("%m-%d %H:%M")


def _fmt_dt_input(ts) -> str:
    """Value for a datetime-local input (server-local wall clock)."""
    return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%dT%H:%M")


def _countdown_span(seconds: int, title: str = "") -> str:
    """A ticking countdown: server-rendered value + client-side JS tick.

    The JS (bottom of this file) turns any ``[data-remaining]`` into a live
    countdown seeded by this many seconds; page polling swaps in fresh
    values. An optional ``title`` carries the absolute target for a
    hover/focus read. ``data-final`` keeps the zero read in the same format
    as the running clock (0:00:00 for hour-plus runs, never a bare 0:00).
    """
    seconds = max(0, int(seconds))
    title_attr = f' title="{esc(title)}"' if title else ""
    final = "0:00:00" if seconds >= 3600 else "0:00"
    return (f'<span class="cd" role="timer" data-remaining="{seconds}" '
            f'data-final="{final}"{title_attr}>'
            f'{esc(_fmt_countdown(seconds))}</span>')


def _scheduled_end_of(comp) -> Optional[float]:
    """The competition's scheduled end, from a record or a public payload."""
    if isinstance(comp, dict):
        value = comp.get("scheduled_end_at")
    else:
        value = getattr(comp, "scheduled_end_at", None)
    return float(value) if value else None


def _scheduled_end_line(comp, now: Optional[float] = None) -> str:
    """'· ends in <countdown>' for a live competition with a schedule."""
    now = time.time() if now is None else now
    scheduled = _scheduled_end_of(comp)
    status = comp.get("status") if isinstance(comp, dict) else comp.status
    if not scheduled or status != "live":
        return ""
    title = f"Scheduled end: {_fmt_ts(scheduled)}"
    return (f' · <span title="{esc(title)}">ends in '
            f'{_countdown_span(scheduled - now)}</span>')


def _competition_ends_line(comp, now: Optional[float] = None) -> str:
    """Sentence body for a player page: how long until the competition ends.

    Wrapped by each page in its own markup (a dd, a small line); empty when
    no schedule is set or the competition is not live.
    """
    now = time.time() if now is None else now
    scheduled = _scheduled_end_of(comp)
    status = comp.get("status") if isinstance(comp, dict) else comp.status
    if not scheduled or status != "live":
        return ""
    return (f'ends in {_countdown_span(scheduled - now)} '
            f'<span class="muted small">({_fmt_ts(scheduled)})</span>')


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
    """One colored dot; the status word rides in the hover/focus tooltip.

    A <span>, not a <button>: the dot is a read-only indicator, and a button
    announced as pressable is a lie. ``tabindex=0`` keeps the tooltip
    keyboard-reachable; the JS (bottom of this file) toggles it on tap so
    touch users -- who have no hover -- still get the word.
    """
    label, cls = table.get(status, ((status or "?").title(), "muted"))
    return (f'<span class="sdot {cls}" tabindex="0" role="img" '
            f'data-tip="{esc(label)}" '
            f'aria-label="{prefix} status: {esc(label)}"></span>')


def comp_badge(status: str) -> str:
    return _status_dot(status, _COMP_STATUS, "Competition")


def comp_status_label(status: str) -> str:
    return _COMP_STATUS.get(status, ((status or "?").title(), "muted"))[0]


def comp_status_tag(status: str) -> str:
    """Admin view: the dot AND the word, for operator-at-a-glance reads."""
    label, cls = _COMP_STATUS.get(status, ((status or "?").title(), "muted"))
    return (f'<span class="stwdot {cls}">{_status_dot(status, _COMP_STATUS, "Competition")}'
            f'<span class="word">{esc(label)}</span></span>')


def player_badge(status: str) -> str:
    # A finished run is the quiet default (everyone on an ended board is
    # finished); only the states that need action or attention get a dot.
    if status == "finished":
        return ""
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


#: The engine keeps this many per-service observations (common.schema.SLA_HISTORY_MAX).
_SERVICE_TICKS = SLA_HISTORY_MAX


def _service_history(services: list) -> str:
    """Per-service name + the last 10 up/down ticks, oldest -> newest.

    Missing observations render as hollow slots rather than being invented,
    so a fresh box (or one that predates history recording) reads honestly.
    """
    svc = services or []
    if not svc:
        return '<p class="empty">No scored services in this competition.</p>'
    rows = []
    for service in svc:
        name = service.get("display") or service.get("id") or "Service"
        history = [str(item).upper() for item in (service.get("history") or [])
                   if str(item).upper() in ("UP", "DOWN")][-_SERVICE_TICKS:]
        padded = [None] * (_SERVICE_TICKS - len(history)) + history
        ticks = []
        for index, state in enumerate(padded, start=1):
            if state is None:
                cls, desc = "void", "no tick yet"
            else:
                cls, desc = state.lower(), state.lower()
            ticks.append(
                f'<span class="tick {cls}" title="Tick {index}: {esc(desc)}"'
                f' aria-hidden="true"></span>')
        spoken = ", ".join(state.lower() if state else "no tick"
                           for state in padded)
        current = service.get("state", "PENDING")
        state_cls = "up" if current == "UP" else "down" if current == "DOWN" else ""
        rows.append(
            f'<div class="svc-history-row">'
            f'<span class="svc-history-name">{esc(name)}</span>'
            f'<span class="ticks" role="img" aria-label="{esc(name)}, '
            f'last {_SERVICE_TICKS} ticks: {esc(spoken)}">{"".join(ticks)}</span>'
            f'<span class="svc-history-state{(" " + state_cls) if state_cls else ""}">'
            f'{esc(current)}</span></div>')
    return '<div class="svc-history">' + "".join(rows) + "</div>"


def _ungraded_note(row: dict) -> str:
    """How many checks the agent could not grade, when that is not zero.

    A box missing required software (a check's ``requires`` entry was
    absent) scores 0 for those checks -- it must not read as a healthy
    low-scoring run. The roster, leaderboard, and player dashboard all say
    how much of the board went ungraded."""
    try:
        count = int(row.get("ungraded_count") or 0)
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        return ""
    noun = "check" if count == 1 else "checks"
    return (f'<span class="ungraded">{esc(count)} {noun} ungraded: '
            'required software missing</span>')


def _score_cell(row: dict) -> str:
    """Total with the spelled-out breakdown under it (leaderboard + roster)."""
    return (f'<div class="score-cell"><span class="score">{esc(row.get("total", 0))}</span>'
            f'<span class="muted small">hardening {esc(row.get("hardening_points", 0))} · '
            f'services {esc(row.get("service_points", 0))}</span>{_ungraded_note(row)}</div>')


def _time_cell(row: dict) -> str:
    """Live countdown while the run is on; a quiet dot once the clock stops."""
    if row.get("status") == "running" and row.get("remaining_s", 0) > 0:
        return _countdown_span(int(row["remaining_s"]))
    return '<span class="muted">⋅</span>'


def _copy_btn(value: str, label: str) -> str:
    return (f'<button type="button" class="btn" data-copy="{esc(value)}">'
            f'<span>{esc(label)}</span></button>')


# --- layout -------------------------------------------------------------------

# Applied before first paint from an external (cacheable) script in <head>.
# A data-theme attribute already on <html> (server-pinned on the projector
# board) always wins; otherwise the stored choice, else the OS preference --
# which the CSS mirrors for the no-JS case via prefers-color-scheme. Also
# keeps the theme-color meta in step so mobile browser chrome follows.
THEME_INIT = (
    "(function(){try{var d=document.documentElement;"
    "var cur=d.getAttribute('data-theme');"
    "if(cur==='light'||cur==='dark'){var m0=document.querySelector("
    "'meta[name=theme-color]');if(m0)m0.setAttribute('content',"
    "cur==='light'?'#f7f1e3':'#181410');return;}"
    "var t=localStorage.getItem('huitz-theme');"
    "if(t!=='light'&&t!=='dark'){t=(window.matchMedia&&"
    "matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';}"
    "d.setAttribute('data-theme',t);"
    "var m=document.querySelector('meta[name=theme-color]');"
    "if(m)m.setAttribute('content',t==='light'?'#f7f1e3':'#181410');}"
    "catch(e){d.setAttribute('data-theme','light');}})();"
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
    skip = ""
    if chrome:
        skip = '<a class="skip" href="#main">Skip to content</a>'
        header = (
            '<header class="top"><div class="wrap">'
            '<a class="brand" href="/">Huitzilopochtli</a>'
            f'<nav><a href="/"{cur_home}>Competitions</a><a href="/admin"{cur_admin}>Admin</a>'
            f'{logout}{_THEME_TOGGLE}</nav>'
            '</div></header>'
        )
    # CSS/JS/theme-init ship as hashed static assets (cacheable, and they keep
    # the page payload -- and the CSP -- free of inline script/style blocks);
    # only the per-competition accent vars stay as a body style attribute.
    return f"""<!doctype html>
<html lang="en"{theme_attr}><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" id="theme-color" content="#181410">
<link rel="icon" href="{_FAVICON}">
<title>{esc(title)} · Huitzilopochtli</title>{noscript}
<script src="{static_url('theme-init.js')}"></script>
<link rel="stylesheet" href="{static_url('web.css')}">
</head><body class="{esc(body_class)}" style="{accent_vars}">
{skip}{header}<main class="wrap" id="main">{body}</main>
<script src="{static_url('web.js')}"></script>
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


def _players_joined(joined, max_players) -> str:
    """'3 of 32 joined' -- or plain '3 joined' when the cap is unlimited (<=0)."""
    if max_players and int(max_players) > 0:
        return f"{esc(joined)} of {esc(max_players)} joined"
    return f"{esc(joined)} joined"


def _players_capacity(max_players) -> str:
    """The no-count card meta: 'up to 32 players', 'unlimited players' at <=0."""
    if max_players and int(max_players) > 0:
        return f"up to {esc(max_players)} players"
    return "unlimited players"


def _comp_cards(comps: list, players_by_comp: Optional[dict] = None,
                show_status: bool = True,
                empty: str = "No open competitions.") -> str:
    if not comps:
        return f'<p class="empty">{esc(empty)}</p>'
    counts = players_by_comp or {}
    rows = []
    for c in comps:
        joined = counts.get(c.id)
        full = (c.status == "live" and c.max_players > 0
                and joined is not None and joined >= c.max_players)
        join = ""
        if c.status == "live" and c.join_open and not full:
            join = f'<a class="btn primary" href="/c/{esc(c.slug)}/join">Join</a>'
        if c.status == "ended":
            meta = "finished"
        elif joined is not None:
            meta = f"{_players_joined(joined, c.max_players)} · {_fmt_duration(c.duration_s)} runs"
            # Fullness rides in the meta line; the action slot only ever
            # carries a real button, never a floating word beside one.
            if full:
                meta += ' · <span class="fullflag">full</span>'
        else:
            meta = f"{_fmt_duration(c.duration_s)} runs · {_players_capacity(c.max_players)}"
        # The section header already says "Live", so live-section cards skip
        # the status dot; mixed-status sections keep it as the differentiator.
        badge = comp_badge(c.status) if show_status else ""
        rows.append(f"""<article class="card comp-row"><div class="comp-main">
<div class="comp-title-line"><h2><a href="/c/{esc(c.slug)}">{esc(c.name)}</a></h2>{badge}</div>
<p class="comp-meta">{meta}</p></div>
<div class="comp-actions"><a class="btn" href="/c/{esc(c.slug)}">Leaderboard</a>{join}</div>
</article>""")
    return '<section class="comp-list">' + "".join(rows) + "</section>"


def index_page(comps: list, admin_view: bool = False,
               players_by_comp: Optional[dict] = None) -> str:
    live = [c for c in comps if c.status == "live"]
    body = f"""<section class="hero">
<h1>Available competitions</h1>
</section>
<div id="home" data-poll="15000">
<h2 class="section-title">Live</h2>{_comp_cards(live, players_by_comp, show_status=False)}"""
    if admin_view:
        other = [c for c in comps if c.status != "live"]
        body += f"""
<h2 class="section-title">Other competitions</h2>{_comp_cards(other, players_by_comp, empty="No other competitions.")}"""
    body += "</div>"
    return layout("Competitions", body, admin=admin_view, current="home",
                  refresh=15)


def _join_box(comp: dict, viewer_comp: Optional[CompetitionRecord] = None) -> str:
    if viewer_comp is not None:
        # A player already has a run: never offer a second Join button.
        if viewer_comp.id == comp["id"]:
            return ('<p class="okmsg">You\'re in this competition.</p>'
                    '<a class="btn primary" href="/">Go to my run</a>')
        return (f'<p class="muted small">You\'re in {esc(viewer_comp.name)} — '
                'one competition at a time.</p><a class="btn" href="/">Go to my run</a>')
    if comp["status"] == "live" and comp["join_open"] and \
            (comp["max_players"] <= 0 or comp["player_count"] < comp["max_players"]):
        return f'<a class="btn primary" href="/c/{esc(comp["slug"])}/join">Join this competition</a>'
    if comp["status"] == "live" and comp["join_open"] and comp["max_players"] \
            and comp["player_count"] >= comp["max_players"]:
        # The one join-blocking state worth shouting about.
        return '<p class="fullnote">Competition is full</p>'
    if comp["status"] == "ended":
        # The title-area badge already says the competition ended; the join
        # slot adds nothing and stays empty.
        return ""
    reason = {"draft": "Competition hasn't started."}.get(comp["status"], "Joins are closed.")
    return f'<span class="muted small">{esc(reason)}</span>'


def _leader_row(r: dict) -> str:
    # data-th feeds the mobile card layout's per-cell labels (see the 720px
    # media query); the thead stays in the a11y tree via scope="col".
    return f"""<tr>
<td class="rank" data-th="#">{esc(r['rank'])}</td>
<td data-th="Player"><div class="pname"><strong>{esc(r['name'])}</strong>{player_badge(r['status'])}</div></td>
<td class="r" data-th="Score">{_score_cell(r)}</td>
<td data-th="Services up">{_service_dots(r.get("services"))}</td>
<td class="num r" data-th="Time">{_time_cell(r)}</td></tr>"""


def _board_table(rows: list, empty: str = "No players yet.") -> str:
    body_rows = "".join(_leader_row(r) for r in rows) \
        or f'<tr><td colspan="5" class="empty" data-th="">{esc(empty)}</td></tr>'
    return (f'<div class="table-wrap"><table><thead><tr>'
            f'<th class="r" scope="col">#</th><th scope="col">Player</th><th class="r" scope="col">Score</th>'
            f'<th scope="col">Services up</th><th class="r" scope="col">Time</th></tr></thead>'
            f'<tbody>{body_rows}</tbody></table></div>')


def competition_page(data: dict, *, refresh: int = 5,
                     viewer_comp: Optional[CompetitionRecord] = None,
                     admin: bool = False) -> str:
    comp = data["competition"]
    rows = data["leaderboard"]
    join_box = _join_box(comp, viewer_comp)
    full = (comp["status"] == "live" and comp["max_players"] > 0
            and comp["player_count"] >= comp["max_players"])
    full_flag = ' · <span class="fullflag">full</span>' if full else ""
    # Reserved seats that never got a VM, named apart from "joined": the
    # board lists players only once a box is bound, so without this line a
    # waiting name simply looks missing.
    waiting = int(comp.get("waiting_count") or 0)
    waiting_line = (f' · {esc(waiting)} waiting for a VM'
                    if waiting and comp["status"] == "live" else "")
    body = f"""<section class="page-head-row">
<div><div class="title-line"><h1>{esc(comp['name'])}</h1>{comp_badge(comp['status'])}</div>
<p class="meta">{_players_joined(comp['player_count'], comp['max_players'])}{waiting_line} · {_fmt_duration(comp['duration_s'])} runs{full_flag} · <a href="/c/{esc(comp['slug'])}/display">Big screen</a>{_scheduled_end_line(comp)}</p>
{f'<p class="small muted">{esc(comp.get("join_instructions") or "")}</p>' if comp.get('join_instructions') else ''}</div>
{f'<div class="joinbox">{join_box}</div>' if join_box else ''}
</section>
<div id="board" data-poll="{refresh * 1000}">
<section class="board"><div class="board-head"><h2>Leaderboard</h2>
{'' if comp.get("leaderboard_hidden") else
('<button type="button" class="btn" data-shot title="Copy an image of the leaderboard to the clipboard"'
 ' aria-label="Copy an image of the leaderboard to the clipboard"><span>Screenshot</span></button>')}
</div>
{_board_table(rows, empty=("No scored runs — reserved seats that never bound a box are not listed." if comp["status"] == "ended" else "No players yet.")) if not comp.get("leaderboard_hidden") else
('<p class="empty muted">Standings are hidden by the organizers.</p>')}
</section>
</div>"""
    accent = (comp.get("theme") or {}).get("accent")
    return layout(comp["name"], body, refresh=refresh, accent=accent,
                  admin=admin, current="home")


def display_page(data: dict) -> str:
    comp = data["competition"]
    rows = data["leaderboard"][:10]
    board = "".join(f"""<div class="display-row">
<span class="rank">{esc(r['rank'])}</span>
<span class="name">{esc(r['name'])}</span>
<span class="score">{esc(r['total'])}</span>
<span class="time">{_time_cell(r)}</span>
<span>{_service_dots(r.get('services'))}</span>
</div>""" for r in rows) or '<p class="empty">Waiting for players…</p>'
    if comp.get("leaderboard_hidden"):
        board = '<p class="empty muted">Standings are hidden by the organizers.</p>'
    body = f"""<section class="display-head"><div class="title-line"><h1>{esc(comp['name'])}</h1>{comp_badge(comp['status'])}</div></section>
<div id="board" data-poll="5000">
<section class="display-board">{board}</section>
<p class="display-meta">{esc(len(rows))} on the board{_scheduled_end_line(comp)}</p>
</div>"""
    accent = (comp.get("theme") or {}).get("accent")
    return layout(comp["name"], body, refresh=5, body_class="display", accent=accent, chrome=False)


def join_form_page(comp: CompetitionRecord, error: str = "",
                   closed_notice: str = "",
                   blocked_comp: Optional[CompetitionRecord] = None,
                   admin: bool = False,
                   recoverable_name: Optional[str] = None) -> str:
    if blocked_comp is not None:
        # One competition at a time: point them at the run they already own
        # instead of rendering a form whose POST can only be refused.
        body = f"""<section class="hero"><h1>Join {esc(comp.name)}</h1></section>
<section class="card narrow">
<p class="fullnote">You're already in {esc(blocked_comp.name)}</p>
<p class="muted">A player can compete in only one competition at a time.
Finish (or leave) your current run before joining another.</p>
<p class="actions"><a class="btn primary" href="/">Go to my run</a>
<a class="btn" href="/c/{esc(blocked_comp.slug)}">Its leaderboard</a></p>
</section>"""
        return layout(f"Join {comp.name}", body, comp=comp, admin=admin,
                      current="home")
    if closed_notice:
        body = f"""<section class="hero"><h1>Join {esc(comp.name)}</h1></section>
<section class="card narrow center">
<p class="muted">{esc(closed_notice)}</p>
<a class="btn" href="/c/{esc(comp.slug)}">Back to the leaderboard</a>
</section>"""
        return layout(f"Join {comp.name}", body, comp=comp, admin=admin,
                      current="home")
    # Seat recovery: a reserved-but-never-bound seat whose owner's browser
    # lost the huitz_player cookie (slow cold provisioning, closed tab) is
    # otherwise unreachable -- the dashboard needs the cookie and every
    # re-join under that name is refused. The form below the join form
    # re-links this browser to that seat by name; the server only honors it
    # while the seat has no box (a live run is never recoverable by name).
    recovery = ""
    if recoverable_name:
        recovery = f"""<section class="card narrow">
<form method="post" action="/c/{esc(comp.slug)}/recover" class="stack">
<input type="hidden" name="recover" value="1">
<label>Seat name<input name="name" maxlength="40" required value="{esc(recoverable_name)}"></label>
<button class="btn primary" type="submit">That's me — recover my seat</button>
</form>
<p class="muted small">Recovery re-links this browser to that still-empty seat
(only a seat without a VM can be recovered; a live run needs the organizer).</p>
</section>"""
    body = f"""<section class="hero"><h1>Join {esc(comp.name)}</h1>
<p class="lede">Enter the name your competitors will see. You will get a VM link and a one-time code to run inside the box.</p></section>
<section class="card narrow">
{f'<p class="error">{esc(error)}</p>' if error else ''}
<form method="post" action="/c/{esc(comp.slug)}/join" class="stack">
<label>Display name<input name="name" maxlength="40" required autofocus placeholder="e.g. Ada"></label>
<button class="btn primary" type="submit">Join and get my box</button>
</form>
<p class="muted small">Display names may contain spaces; they are trimmed and
matched case-insensitively. Each name seats exactly one player and stays
reserved for them until an admin frees the seat. By joining you agree to
compete on a disposable ranked box. A seat is a team: teammates join it
through your team link, and multi-box competitions bind one box per
scenario with the same join code on one shared clock. One competition at
a time. Provisioning your VM can take a minute.</p>
</section>{recovery}"""
    return layout(f"Join {comp.name}", body, comp=comp, admin=admin,
                  current="home")


def team_join_page(comp: CompetitionRecord, player: PlayerRecord, csrf: str,
                   error: str = "", blocked_msg: str = "") -> str:
    """The team-link landing page: a teammate names themselves, and the POST
    of this form registers them on the seat's roster and seats their browser.

    ``blocked_msg`` renders the one-competition-at-a-time refusal instead of
    the form (mirrors join_form_page's blocked card: a POST here could only
    be refused, so none is offered)."""
    if blocked_msg:
        body = f"""<section class="hero"><h1>Join {esc(player.display_name)}</h1></section>
<section class="card narrow">
<p class="fullnote">{esc(blocked_msg)}</p>
<p class="actions"><a class="btn primary" href="/">Go to my run</a></p>
</section>"""
        return layout(f"Join {comp.name}", body, comp=comp, current="home")
    url = f"/c/{esc(comp.slug)}/team/{esc(player.team_token_plain or '')}"
    body = f"""<section class="hero"><h1>Join {esc(player.display_name)}</h1>
<p class="lede">A team in {esc(comp.name)} invited you. You share their boxes,
their score and their clock — your name joins the team roster.</p></section>
<section class="card narrow">
{f'<p class="error">{esc(error)}</p>' if error else ''}
<form method="post" action="{url}" class="stack">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<label>Your name<input name="name" maxlength="60" required autofocus placeholder="e.g. Grace H."></label>
<button class="btn primary" type="submit">Join the team</button>
</form>
<p class="muted small">This name is listed on the team roster only — it never
takes a competition seat, a VM or a join code. Everyone on the team shares
one run: same boxes, same score, same clock.</p>
</section>"""
    return layout(f"Join {comp.name}", body, comp=comp, current="home")


def _claim_retry_form(player: PlayerRecord, csrf: str,
                      scenario: Optional[str] = None) -> str:
    scen = (f'<input type="hidden" name="scenario" '
            f'value="{esc(scenario)}">' if scenario else "")
    return f"""<form method="post" action="/api/public/join/{esc(player.player_id)}/claim" class="inline">
<input type="hidden" name="csrf" value="{esc(csrf)}">{scen}
<button class="btn" type="submit">Get a new VM</button></form>"""


def _post_run_phrase() -> str:
    """The access-window sentence for player pages (engine-receipt wording)."""
    grace = claims.post_run_grace_s()
    minutes = int(round(grace / 60)) if grace >= 30 else 0
    if minutes < 1:
        return ("Scoring stops when your clock ends; the box is shut down "
                "and deleted right after.")
    return (f"Scoring stops when your clock ends; the box then stays up "
            f"for {minutes} more minutes to investigate before it is shut "
            f"down and deleted.")


def _team_inner(comp: CompetitionRecord, player: PlayerRecord, csrf: str,
                members: list, team_url: str) -> str:
    """The shared-seat block: copyable team link, rotate, the named roster.
    Empty for a seat that never got a token (a slot created before teams
    existed and never visited a page that mints one lazily).

    Returns content only; the run pages wrap it in a card and the join
    success page in a step, so the block cannot drift between them.
    """
    if not player.team_token_plain:
        return ""
    url = team_url or f"/c/{esc(comp.slug)}/team/{esc(player.team_token_plain)}"
    rows = "".join(
        f'<li><span>{esc(handle)}</span>'
        f'<form method="post" action="/c/{esc(comp.slug)}/team" class="inline">'
        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
        f'<input type="hidden" name="action" value="remove">'
        f'<input type="hidden" name="handle" value="{esc(handle)}">'
        f'<button class="btn ghost-sm" type="submit">Remove</button></form></li>'
        for handle, _added in members)
    cap = max(1, comp.max_team_members)
    count = len(members)
    return f"""<p class="small">Teammates who open this link pick a name and
join this roster — same seat, same boxes, same clock. Rotating invalidates
the old link at once.</p>
<p><code>{esc(url)}</code> {_copy_btn(url, "Copy link")}</p>
<form method="post" action="/c/{esc(comp.slug)}/team">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<input type="hidden" name="action" value="rotate">
<button class="btn" type="submit">Rotate team link</button></form>
<h3>Members <span class="muted small">{count}/{cap}</span></h3>
<ul>{rows or '<li class="muted small">No teammates listed yet.</li>'}</ul>
<p class="muted small">Add by hand (teammates can also add themselves with
the link):</p>
<form method="post" action="/c/{esc(comp.slug)}/team">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<input type="hidden" name="action" value="add">
<input type="text" name="handle" maxlength="60" placeholder="teammate handle" required>
<button class="btn" type="submit">Add</button></form>"""


def join_success_page(comp: CompetitionRecord, player: PlayerRecord,
                      join_code: str = "", csrf: str = "",
                      admin: bool = False, team_members=None,
                      team_url: str = "", boxes=None) -> str:
    code = join_code or player.join_code_plain or ""
    url = player.claim_url
    bound = bool(player.box_id)
    pending = bool(player.claim_ticket and not url)
    err = (player.claim_error or "").strip()
    competition_ends = _competition_ends_line(comp)

    parts = []
    if player.status == "disqualified":
        parts.append('<p class="warnmsg"><strong>Disqualified.</strong> You '
                     'keep your box and your clock — work on until the end — '
                     'but your score will not appear on the leaderboard.</p>')
    if url:
        parts.append(
            f'<div class="vm-actions"><a class="btn primary" href="{esc(url)}" '
            f'target="_blank" rel="noopener">Open my VM</a> '
            f'{_copy_btn(url, "Copy link")}</div>')
    if bound:
        parts.append('<p class="okmsg">Your box is joined — the run is live.</p>')
        if player.ends_at:
            parts.append(
                f'<p class="muted small">Run ends {esc(_fmt_ts(player.ends_at))} '
                f'· hard stop {esc(_fmt_ts(player.ends_at - 300))} '
                f'(five minutes before). {_post_run_phrase()}</p>')
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

    # Claim-status polling is data-driven: web.js watches #vm-poll and reloads
    # the page when the box binds or the claim url/error/code-expiry changes,
    # so no inline script is needed on this page.
    vm_poll = ""
    if not bound:
        vm_poll = (f'<div id="vm-poll" hidden data-pid="{esc(player.player_id)}"'
                   f' data-url="{esc(url or "")}" data-err="{esc(err)}"'
                   f' data-code-exp="{esc(player.join_code_expires_at or 0)}"></div>')

    codebox = (f'<div class="codebox"><code id="joincode">{esc(code)}</code>'
               f'{_copy_btn(code, "Copy code")}</div>' if code else
               '<p class="muted small">No fallback code is available.</p>')
    fallback = f"""<li><h2>Join from the terminal</h2>
<p class="small">Open a terminal in the VM and run
<code>huitz join</code> followed by the code below (or run it alone and
enter the code when prompted):</p>
<pre><code>huitz join {esc(code)}</code></pre>
{codebox}
<p class="small">The code is single-use and expires; this page updates itself
when it does.</p></li>"""

    team = _team_inner(comp, player, csrf, team_members or [], team_url)
    body = f"""<section class="page-head-row"><div>
<div class="title-line"><h1>You're in, {esc(player.display_name)}</h1></div>
<p class="meta">Competition: {esc(comp.name)} · your clock starts when you open the VM.{f' · Competition {competition_ends}' if competition_ends else ''}</p></div></section>
<section class="card narrow">
<ol class="steps">
<li><h2>Your VM</h2>{step1}</li>{vm_poll}
{('<li><h2>Your boxes</h2>' + _boxes_panels(comp, player, csrf, boxes) + '</li>') if boxes else ''}
{fallback if (code and not bound) else ''}
{f'<li><h2>Invite your team</h2>{team}</li>' if team else ''}
<li><h2>Watch the board</h2>
<p><a href="/c/{esc(comp.slug)}">Leaderboard</a> · <a href="/c/{esc(comp.slug)}/me">My status</a></p></li>
</ol>
</section>"""
    return layout("You're in", body, comp=comp, admin=admin, current="home",
                  refresh=None if bound else 5)


def _run_clock(comp: CompetitionRecord, player: PlayerRecord,
               now: Optional[float] = None):
    """Shared clock computation for the two player run pages (/me and home).

    Returns (time_block, end_note, competition_ends, remaining). The run
    clock counts to the run's effective end: the run's own deadline or an
    earlier scheduled competition end, whichever comes first.
    """
    now = time.time() if now is None else now
    running = player.status == "running"
    effective_end = competition.effective_run_end(comp, player) if running else None
    remaining = max(0, int((effective_end or 0) - now)) if (running and effective_end) else 0
    end_note = ""
    if effective_end:
        end_note = f"ends {esc(_fmt_ts(effective_end))}"
        if player.ends_at is not None and effective_end != player.ends_at:
            end_note += " (competition end)"
    competition_ends = _competition_ends_line(comp, now)
    if running:
        time_block = _countdown_span(remaining, title=end_note)
    elif player.status == "invited":
        time_block = '<span class="muted small">starts when your box joins</span>'
    else:
        time_block = '<span class="muted">—</span>'
    return time_block, end_note, competition_ends, remaining


def _run_score_block(row: dict, player: PlayerRecord, big_class: str) -> str:
    """The score area for player run pages, in one place so /me and the run
    home page cannot drift apart. ``big_class`` is the page's big-number class."""
    joined = bool(player.box_id)
    if row:
        return (f'<div class="{big_class}">{esc(row.get("total", 0))}</div>'
                f'<div class="scoresplit"><span>hardening {esc(row.get("hardening_points", 0))}</span>'
                f'<span>services {esc(row.get("service_points", 0))}</span></div>'
                + _ungraded_note(row))
    if joined and player.status == "disqualified":
        return (f'<div class="{big_class} muted">off-board</div>'
                '<div class="muted small">Disqualified: the box keeps '
                'scoring its own report; the board is closed to this run.</div>')
    if joined:
        return (f'<div class="{big_class} muted">—</div>'
                '<div class="muted small">Your box is joined — waiting for its '
                'first engine check-in.</div>')
    return (f'<div class="{big_class} muted">—</div>'
            '<div class="muted small">Not scoring: your box has not joined yet — '
            'open your VM, then run <code>huitz join</code> with your code.</div>')


def player_page(comp: CompetitionRecord, player: PlayerRecord,
                board_row: Optional[dict], claim_url: Optional[str],
                csrf: str = "", admin: bool = False,
                join_code: str = "", team_members=None,
                team_url: str = "", boxes=None) -> str:
    row = board_row or {}
    joined = bool(player.box_id)
    time_block, end_note, competition_ends, _remaining = _run_clock(comp, player)
    score = _run_score_block(row, player, "bigscore")
    join_panel = ""
    if not joined:
        code = (join_code or player.join_code_plain or "").strip()
        code_block = (f'<div class="codebox" aria-label="one-time join code">'
                      f'<code>{esc(code)}</code></div>' if code else
                      '<p class="muted" id="code-wait">Your one-time code is being '
                      'prepared — refresh this page in a moment.</p>')
        join_panel = f'''<div class="warnmsg"><strong>You have not joined yet.</strong>
Your box is not on the board, nothing is scoring, and your clock has not
started. Open your VM, run <code>huitz join</code> in its terminal, and enter
this code:</div>
{code_block}
<p class="small">1. Open your VM. 2. In its terminal run
<code>huitz join</code>. 3. Enter the code above. This page updates when the
box joins.</p>'''
    body = f"""<section class="page-head-row"><div>
<div class="title-line"><h1>{esc(player.display_name)}</h1>{player_badge(player.status)}{'' if joined else '<span class="fullflag">not joined</span>'}</div>
<p class="meta">{esc(comp.name)}</p></div></section>
<div id="run" data-poll="15000">
<section class="card narrow">
{join_panel}
{f'<p class="warnmsg"><strong>Disqualified.</strong> You keep your box and your clock — work on until the end — but your score will not appear on the leaderboard.</p>' if player.status == "disqualified" else ''}
<div class="row me-top">
<div>{score}</div>
<div class="me-right"><div class="muted small">Time remaining</div>
<div class="bigtime">{time_block}</div>
<div class="muted small">{end_note}</div>
{f'<div class="muted small">Competition {competition_ends}</div>' if competition_ends else ''}</div>
</div>
<dl class="kv">
<dt>Status</dt><dd>{player_badge(player.status)}</dd>
<dt>Last check-in</dt><dd>{esc(_rel_ts(row.get("last_checkin")))}</dd>
</dl>
{f'<p><a class="btn primary" href="{esc(claim_url)}" target="_blank" rel="noopener">Open my VM</a></p>' if claim_url else ''}
{'' if player.box_id or player.claim_url or player.claim_ticket else _claim_retry_form(player, csrf)}
{f'<p class="error">{esc(player.claim_error)}</p>' if player.claim_error and 'join code' not in player.claim_error.lower() else ''}
<p><a href="/c/{esc(comp.slug)}">Leaderboard →</a></p>
</section>
{f'<section class="card narrow"><h2>Boxes</h2>{_boxes_panels(comp, player, csrf, boxes)}</section>' if boxes else ''}
{f'<section class="card narrow"><h2>Team</h2>{_team_inner(comp, player, csrf, team_members or [], team_url)}</section>' if player.team_token_plain else ''}
</div>"""
    return layout(player.display_name, body, comp=comp, admin=admin,
                  current="home", refresh=15)


def _home_vm_card(comp: CompetitionRecord, player: PlayerRecord,
                  claim_url: Optional[str], csrf: str) -> str:
    url = claim_url
    if player.box_id:
        note = '<p class="okmsg">Your box is joined — the run is live.</p>'
    elif url:
        note = ('<p class="muted small">Your clock starts when you open it. '
                'The same link re-opens your VM any time while it lives.</p>')
    elif player.claim_ticket:
        note = ('<p class="muted" id="vm-wait">Your VM is being prepared — '
                'this page updates automatically.</p>')
    elif player.claim_error:
        note = (f'<p class="error">We couldn\'t prepare your VM: '
                f'{esc(player.claim_error)}</p>')
    else:
        note = ('<p class="muted" id="vm-wait">Your VM will appear here '
                'automatically — provisioning retries in the background.</p>')
    actions = []
    if url:
        actions.append(f'<a class="btn primary" href="{esc(url)}" target="_blank" '
                       f'rel="noopener">Open my VM</a>')
        actions.append(_copy_btn(url, "Copy link"))
    elif not player.box_id:
        actions.append(_claim_retry_form(player, csrf))
    action_html = (f'<div class="home-actions">{"".join(actions)}</div>'
                   if actions else "")
    fallback = ""
    join_hint = ""
    if not player.box_id:
        # The code has to be visible where the player lands, not only on the
        # success page: without it the VM looks joined but nothing is scoring.
        code = (player.join_code_plain or "").strip()
        code_block = (f'<div class="codebox"><code>{esc(code)}</code></div>'
                      if code else
                      '<p class="muted" id="code-wait">Your one-time code is '
                      'being prepared — this page updates automatically.</p>')
        join_hint = f'''<div class="warnmsg"><strong>Not joined yet.</strong> Open
your VM, run <code>huitz join</code> in its terminal, and enter this code:</div>
{code_block}
<p class="small">Nothing is scoring and your clock has not started until the
box joins.</p>'''
        # The success page still holds the same code + instructions.
        fallback = (f'<p class="small"><a href="/c/{esc(comp.slug)}/join/success">'
                    'Join instructions</a></p>')
    return f"""<section class="card home-card">
<div class="card-head"><h2>Your VM</h2>{player_badge(player.status)}</div>
{note}{join_hint}{action_html}{fallback}
</section>"""


def _boxes_panels(comp: CompetitionRecord, player: PlayerRecord, csrf: str,
                   boxes: list) -> str:
    """One VM card per lineup entry (multi-box competitions only; single
    boxes never get here -- their page renders the legacy single card).

    The one-time join code belongs to the SEAT, not a box, so it is shown
    once above the cards: the same code joins every box of the lineup (each
    box identifies its own scenario to the engine).
    """
    parts = []
    unbound = [b for b in boxes if not b["bound"]]
    if unbound and player.join_code_plain:
        parts.append(f"""<section class="card home-card">
<div class="card-head"><h2>Join your boxes</h2>{player_badge(player.status)}</div>
<div class="warnmsg"><strong>Not every box is joined yet.</strong> Open a
box's VM, run <code>huitz join</code> in its terminal, and enter this code —
it works on every box of this competition:</div>
<div class="codebox"><code>{esc(player.join_code_plain)}</code></div>
</section>""")
    for b in boxes:
        if b["bound"]:
            note = ('<p class="okmsg">Joined — this box is live.</p>'
                    if not b["released_at"] else
                    '<p class="muted small">Released.</p>')
        elif b["claim_url"]:
            note = ('<p class="muted small">Opening starts scoring for this '
                    'box. Your team clock runs from your first joined box.</p>')
        elif b["pending"]:
            note = '<p class="muted">This box is being prepared.</p>'
        elif b["error"]:
            note = f'<p class="error">We couldn\'t prepare this box: {esc(b["error"])}</p>'
        else:
            note = ('<p class="muted">This box will appear automatically — '
                    'provisioning retries in the background.</p>')
        actions = []
        if b["claim_url"] and not b["bound"]:
            actions.append(f'<a class="btn primary" href="{esc(b["claim_url"])}" '
                           f'target="_blank" rel="noopener">Open VM</a>')
            actions.append(_copy_btn(b["claim_url"], "Copy link"))
            actions.append(_claim_retry_form(player, csrf,
                                            scenario=b["scenario_name"]))
        elif b["claim_url"]:
            actions.append(f'<a class="btn" href="{esc(b["claim_url"])}" '
                           f'target="_blank" rel="noopener">Open VM</a>')
        elif not b["bound"]:
            actions.append(_claim_retry_form(player, csrf,
                                             scenario=b["scenario_name"]))
        act = (f'<div class="home-actions">{"".join(actions)}</div>'
               if actions else "")
        parts.append(f"""<section class="card home-card">
<div class="card-head"><h2>Box · {esc(b["scenario_name"])}</h2></div>
{note}{act}
</section>""")
    return "".join(parts)


def _home_leave_card(comp: CompetitionRecord, player: PlayerRecord,
                     leave_csrf: str) -> str:
    if player.status == "running":
        consequence = ("Leaving ends your run immediately, releases your VM, "
                       "and removes you from the leaderboard.")
    else:
        consequence = "Leaving releases your reserved VM and frees your slot."
    return f"""<section class="card home-card leave-card">
<h2>Leave competition</h2>
<p class="muted small">{esc(consequence)} This cannot be undone.</p>
<p class="muted small"><strong>This forfeits the whole team.</strong> The seat
is shared — leaving removes every teammate on the roster with it.</p>
<form method="post" action="/c/{esc(comp.slug)}/leave" class="inline"
      data-confirm="Leave this competition? The whole team (every listed member) is removed with the seat. This cannot be undone.">
<input type="hidden" name="csrf" value="{esc(leave_csrf)}">
<button class="btn danger" type="submit">Leave competition</button>
</form>
</section>"""


def home_competition_page(comp: CompetitionRecord, player: PlayerRecord,
                          board_row: Optional[dict], board_rows: list,
                          claim_url: Optional[str], csrf: str = "",
                          leave_csrf: str = "",
                          player_count: Optional[int] = None,
                          services: Optional[list] = None,
                          admin: bool = False,
                          team_members=None,
                          team_url: str = "",
                          boxes=None) -> str:
    """The main page while a run is active: a full-width run dashboard.

    The old narrow card left most of the viewport empty. This layout uses the
    available width for the score, clock, a live top-five board, and the VM /
    leave actions -- and it is the only place another competition is not
    offered, because one is already in progress.
    """
    row = board_row or {}
    rows = board_rows or []
    services = (services if services is not None
                else (row.get("services") or []))
    joined = comp.max_players if player_count is None else player_count
    time_block, end_note, competition_ends, _remaining = _run_clock(comp, player)
    score_block = _run_score_block(row, player, "stat-big")
    if row:
        # With a hidden board the server still sends the player's own row
        # (carrying board_total); the public rows list stays empty.
        board_total = row.get("board_total") or len(rows)
        rank_line = (f'Rank {esc(row.get("rank"))} of {esc(board_total)} on the board'
                     if row.get("rank") and board_total else "On the board")
    else:
        rank_line = "Not on the board yet"
    # The organizers can pause the public standings for the run; while they
    # are hidden the player's board shows a quiet note instead of scores
    # (check-ins, the clock and the run itself keep working).
    board = (_board_table(rows[:8]) if rows and not comp.leaderboard_hidden
             else ('<p class="empty muted">Standings are hidden by the '
                   'organizers.</p>' if comp.leaderboard_hidden else
                   '<p class="empty">No scores on the board yet.</p>'))
    body = f"""<section class="home-hero">
<div><div class="title-line"><h1>You're in {esc(comp.name)}</h1>{comp_badge(comp.status)}</div>
<p class="meta">{esc(player.display_name)} · this is your main page while your run is active
· <a href="/c/{esc(comp.slug)}">leaderboard</a></p></div>
</section>
<div id="run" data-poll="15000">
<section class="home-grid">
<div class="home-col">
<section class="card home-card">
<div class="card-head"><h2>Your score</h2><span class="muted small">{esc(rank_line)}</span></div>
{score_block}
</section>
<section class="card home-card">
<div class="card-head"><h2>Run clock</h2>{player_badge(player.status)}</div>
<div class="stat-clock">{time_block}</div>
<p class="muted small">{end_note if end_note else 'ends when your run ends'}</p>
<dl class="kv">
<dt>Last check-in</dt><dd>{esc(_rel_ts(row.get("last_checkin")))}</dd>
<dt>Services</dt><dd>{_service_dots(services)}</dd>
</dl>
</section>
<section class="card home-card">
<div class="card-head"><h2>Service uptime</h2>
<span class="muted small">last 10 check-ins</span></div>
{_service_history(services)}
</section>
</div>
<div class="home-col">
{_boxes_panels(comp, player, csrf, boxes) if boxes else _home_vm_card(comp, player, claim_url, csrf)}
{f'<section class="card home-card"><div class="card-head"><h2>Team</h2></div>{_team_inner(comp, player, csrf, team_members or [], team_url)}</section>' if player.team_token_plain else ''}
<section class="card home-card">
<div class="card-head"><h2>Competition</h2>
<a class="small" href="/c/{esc(comp.slug)}/display">Big screen →</a></div>
<dl class="kv home-facts">
<dt>Scenario</dt><dd>{esc(comp.scenario_name)}</dd>
<dt>Players</dt><dd>{_players_joined(joined, comp.max_players)}</dd>
<dt>Duration</dt><dd>{esc(_fmt_duration(comp.duration_s))}</dd>
{f'<dt>Scheduled end</dt><dd>{competition_ends}</dd>' if competition_ends else ''}
</dl>
</section>
{_home_leave_card(comp, player, leave_csrf)}
</div>
<section class="card home-card home-board">
<div class="card-head"><h2>Leaderboard</h2>
<a class="small" href="/c/{esc(comp.slug)}">Full board →</a></div>
{board}
</section>
</section>
</div>
<p class="home-note">You can join another competition once this run ends.</p>"""
    return layout("My competition", body, comp=comp, admin=admin,
                  current="home", refresh=15)


# --- admin pages -----------------------------------------------------------------


def login_page(error: str = "", csrf: str = "") -> str:
    # csrf is a pre-session token (cookie-paired by the server): it defends
    # against login-CSRF even though no session exists yet.
    csrf_input = (f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                  if csrf else "")
    body = f"""<section class="login-page">
<h1>Admin login</h1>
{f'<p class="error">{esc(error)}</p>' if error else ''}
<form method="post" action="/admin/login" class="stack">
{csrf_input}
<label>Username<input name="username" autocomplete="username" autofocus required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button class="btn primary" type="submit">Sign in</button>
</form></section>"""
    return layout("Admin login", body, admin=False, body_class="login-body")


def _build_line() -> str:
    """The exact build the running engine process was loaded from.

    Outside the poll div on purpose: this is process-static (it changes only
    at restart), while the poll swaps the dashboard's inner content.
    """
    info = engine_build.build_info()
    if not info["commit"]:
        return ('<p class="muted small">Engine build unknown: this checkout '
                'has no build_info.json (built dev checkout).</p>')
    short = esc(info["commit"][:7])
    built = ""
    if info["built_at"]:
        try:
            # Epoch seconds (a bundle stamp could carry them) render through
            # the shared formatter; ISO stamps render as-is, trimmed.
            built = f" · built {esc(_fmt_ts(float(info['built_at'])))}"
        except (TypeError, ValueError):
            built = " · built " + esc(str(info["built_at"])[:16].replace("T", " "))
    src = f' ({esc(info["source"])})' if info["source"] else ""
    started = esc(_fmt_ts(engine_build.STARTED_AT))
    return f'<p class="muted small" title="{esc(info["commit"])}">Engine build <code>{short}</code>{src}{built} · process started {started}</p>'


def admin_dashboard_page(comps: list, players_by_comp: dict,
                         csrf: str, msg: str = "",
                         pool_warn: Optional[dict] = None,
                         pool_counts: Optional[dict] = None) -> str:
    pool_warn = pool_warn or {}
    pool_counts = pool_counts or {}
    live = sum(1 for c in comps if c.status == "live")
    cards = []
    for c in comps:
        n = players_by_comp.get(c.id, 0)
        # A competition that could not pre-deploy anything says so on its row,
        # so the operator learns it before opening the page and pressing the
        # button (the page itself carries the full reason and the fix).
        warn = pool_warn.get(c.id)
        warn_line = (f'<div class="fullflag">{esc(warn)}</div>' if warn else "")
        # Two competitions can hold pools at once; the row says how much of
        # this one's pool is warm (one portal read feeds every row).
        counts = pool_counts.get(c.workshop_pool_code) \
            if c.workshop_pool_code else None
        pool_cell = (f'{esc(counts["available"])}/{esc(counts["total"])}'
                     if counts else '<span class="muted">&mdash;</span>')
        # The whole row is one click target (the name link stays for
        # keyboard/middle-click use); the JS delegates so polling can swap
        # rows freely.
        # A scheduled end rides under the duration so the operator sees, at
        # a glance, which competitions end themselves and when.
        schedule_note = ""
        if c.status in ("draft", "live") and c.scheduled_end_at:
            schedule_note = (f'<div class="muted small">ends '
                             f'{esc(_fmt_short_ts(c.scheduled_end_at))}</div>')
        players_cell = (f'{esc(n)}/{esc(c.max_players)}'
                        if c.max_players and c.max_players > 0 else f'{esc(n)}')
        cards.append(f"""<tr data-href="/admin/competitions/{esc(c.id)}"><td data-th="Name"><a href="/admin/competitions/{esc(c.id)}">{esc(c.name)}</a><div class="muted small">/c/{esc(c.slug)}</div>{warn_line}</td>
<td data-th="Status">{comp_status_tag(c.status)}</td><td class="num r" data-th="Players">{players_cell}</td>
<td class="num r" data-th="Pool ready">{pool_cell}</td>
<td class="num r" data-th="Duration">{esc(_fmt_duration(c.duration_s))}{schedule_note}</td><td data-th=""><a class="btn" href="/c/{esc(c.slug)}">View</a><form method="post" action="/admin/api/competitions/{esc(c.id)}/leaderboard-visibility" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="hidden" value="{0 if c.leaderboard_hidden else 1}"><button class="btn" type="submit">{'Show leaderboard' if c.leaderboard_hidden else 'Hide leaderboard'}</button></form></td></tr>""")
    live_note = (f'<p class="meta">{live} competition{"s" if live != 1 else ""} '
                 f'live right now &middot; each holds its own VM pool.</p>'
                 if live else "")
    body = f"""<section class="page-head-row"><div><h1>Admin console</h1></div>
<div class="actions"><a class="btn" href="/admin/audit">Audit log</a>
<a class="btn primary" href="/admin/competitions/new">New competition</a></div></section>
{f'<p class="okmsg">{esc(msg)}</p>' if msg else ''}
{live_note}
<div id="dash" data-poll="30000">
<section class="card"><div class="card-head"><h2>Competitions</h2>
</div>
<div class="table-wrap"><table><thead><tr><th scope="col">Name</th><th scope="col">Status</th><th class="r" scope="col">Players</th><th class="r" scope="col">Pool ready</th><th class="r" scope="col">Duration</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead><tbody>{''.join(cards) or '<tr><td colspan="6" class="empty">No competitions yet.</td></tr>'}</tbody></table></div></section>
</div>
{_build_line()}"""
    return layout("Admin", body, admin=True, current="admin")


def _audit_detail_cell(details_json) -> str:
    """Detail column: the logged JSON as ``key value`` pairs, raw on hover.

    Whoever logged the action chose the payload's shape, so nothing here
    pretends to a schema -- dict or not, the stored text is shown, and the
    untouched JSON stays in the cell's tooltip.
    """
    if not details_json:
        return '<span class="muted">&mdash;</span>'
    try:
        parsed = json.loads(details_json)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict) and parsed:
        pairs = []
        for key in sorted(parsed):
            value = parsed[key]
            text = (value if isinstance(value, str)
                    else json.dumps(value, sort_keys=True))
            pairs.append(f"{esc(key)} {esc(text)}")
        shown = " &middot; ".join(pairs)
    else:
        shown = esc(details_json)
    return f'<span class="small" title="{esc(details_json)}">{shown}</span>'


def admin_audit_page(rows: list, comps: list, *, competition_id: str = "",
                     limit: int = 200, limit_max: int = 1000,
                     scan: Optional[int] = None, unknown_filter: str = "",
                     player_names: Optional[dict] = None) -> str:
    """The admin audit trail: who did what to which competition, newest first.

    One card, one table -- the same shell the console and the roster use. The
    filter is a GET form so a filtered view is a URL an operator can paste
    into a ticket; ``/admin/audit?competition=&limit=``. Times render through
    ``_fmt_ts`` like every other page in the console (engine-local, with the
    zone spelled out) and the column header says so. Rows are
    ``store.AuditRecord``s; nothing here invents a column the store does not
    keep.
    """
    player_names = player_names or {}
    by_id = {c.id: c for c in comps}
    opts = ['<option value="">All competitions</option>']
    for c in comps:
        selected = " selected" if c.id == competition_id else ""
        opts.append(f'<option value="{esc(c.slug)}"{selected}>{esc(c.name)}</option>')
    out = []
    for r in rows:
        comp = by_id.get(r.competition_id)
        if comp is not None:
            target = (f'<a href="/admin/competitions/{esc(comp.id)}">'
                      f'{esc(comp.name)}</a>'
                      f'<div class="muted small">/c/{esc(comp.slug)}</div>')
        elif r.competition_id:
            # A competition that has since been removed still owns its rows;
            # the id is all the record has, so the id is what shows.
            target = f'<span class="small">{esc(r.competition_id)}</span>'
        else:
            target = '<span class="muted">&mdash;</span>'
        if r.player_id:
            target += (f'<div class="muted small">player '
                       f'{esc(player_names.get(r.player_id) or r.player_id)}</div>')
        actor = esc(r.actor)
        if r.remote_addr:
            actor += f'<div class="muted small">{esc(r.remote_addr)}</div>'
        out.append(f"""<tr><td class="num" data-th="Time">{esc(_fmt_ts(r.ts))}</td><td data-th="Actor">{actor}</td>
<td data-th="Action"><code>{esc(r.action)}</code></td><td data-th="Competition">{target}</td>
<td data-th="Detail">{_audit_detail_cell(r.details_json)}</td></tr>""")
    empty = ("No matching audit entries." if competition_id or unknown_filter
             else "Nothing logged yet.")
    meta = "Newest first &middot; times are engine-local"
    if scan is not None:
        # The store keeps one append-only table, so a filtered view searches a
        # bounded window of it; say which window rather than implying "all".
        meta += f" &middot; filter searched the newest {esc(scan)} entries"
    filters = f"""<form method="get" action="/admin/audit" class="filter-form">
<label class="small">Competition<select name="competition">{"".join(opts)}</select></label>
<label class="small">Rows<input class="input-md" name="limit" type="number" min="1" max="{esc(limit_max)}" value="{esc(limit)}"></label>
<button class="btn" type="submit">Apply</button></form>"""
    body = f"""{_page_head("Audit log")}
{f'<p class="warnmsg">No competition matches <code>{esc(unknown_filter)}</code>.</p>' if unknown_filter else ''}
<section class="card"><div class="card-head"><h2>Entries</h2>
{filters}</div>
<p class="meta">{meta}</p>
<div class="table-wrap"><table><thead><tr><th scope="col">Time (local)</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Competition</th><th scope="col">Detail</th></tr></thead><tbody>{"".join(out) or f'<tr><td colspan="5" class="empty">{empty}</td></tr>'}</tbody></table></div></section>"""
    return layout("Audit log", body, admin=True, current="admin")


def admin_new_competition_page(scenarios: list, csrf: str, error: str = "") -> str:
    opts, unusable = [], []
    for row in scenarios:
        name, version, _path = row[0], row[1], row[2]
        problem = row[3] if len(row) > 3 else None
        # The version stays in the value as invisible plumbing; it is never
        # rendered as a label.
        if problem:
            # A committed box whose pool block cannot expand stays on the
            # list -- disabled, with the reason stated -- so the operator
            # sees the box exists and what to fix, instead of the whole
            # picker failing or the scenario silently vanishing.
            opts.append(f'<option value="{esc(name)}|{esc(version)}" disabled>'
                        f'{esc(name)} — pool not configured</option>')
            unusable.append(f'<li><strong>{esc(name)}</strong>: {esc(problem)}</li>')
        else:
            opts.append(f'<option value="{esc(name)}|{esc(version)}">'
                        f'{esc(name)}</option>')
    unusable_block = (
        '<p class="warnmsg small">These boxes are in the folder but cannot '
        'start a competition until their pool is configured:</p>'
        f'<ul class="small muted">{"".join(unusable)}</ul>'
        if unusable else "")
    body = f"""<div class="form-page">
{_page_head("New competition")}
{f'<p class="error">{esc(error)}</p>' if error else ''}
<form method="post" action="/admin/competitions/new" class="stack">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<div class="form-grid form-lead">
<label>Name<input name="name" required placeholder="Friday Night Ranked" autofocus></label>
<label>Box lineup<select name="scenario" required multiple size="5" aria-describedby="help-scenario">{"".join(opts) or '<option value="">No ranked scenarios found</option>'}</select><span class="help" id="help-scenario">Ranked scenarios from the engine's committed box folder (boxes/). The run is scored against the exact version picked for each. Pick more than one for a multi-box competition: every team joins one box per selected scenario with the same code, on one shared clock.</span></label>
</div>
{unusable_block}
<div class="form-grid form-cols">
<label>Max teams<input name="max_players" type="number" min="1" value="32" aria-describedby="help-max-players"><span class="help" id="help-max-players">Each seat is one team; teammates share it through its team link without consuming seats.</span></label>
<label>Max members per team<input name="max_team_members" type="number" min="1" value="10" aria-describedby="help-max-members"><span class="help" id="help-max-members">Named people allowed on one team's roster.</span></label>
<label>Run duration (minutes)<input name="duration_min" type="number" min="1" value="120"></label>
<label>Accent color<input name="accent" type="color" value="#5f4a38"></label>
</div>
<label class="check"><input type="checkbox" name="auto_end" value="1" aria-describedby="help-auto-end"> End automatically once joins are closed and every run has finished<span class="help" id="help-auto-end">Releases the competition's VM pool without an operator pressing End. Off by default; you can flip it on the competition page.</span></label>
<div class="form-foot"><button class="btn primary" type="submit">Create draft</button></div>
</form></div>"""
    return layout("New competition", body, admin=True, current="admin")


def admin_competition_page(comp: CompetitionRecord, board: dict, players: list,
                           csrf: str, msg: str = "", error: str = "",
                           warm: Optional[dict] = None,
                           pool: Optional[dict] = None,
                           public_base: str = "",
                           predeploy_warn: str = "",
                           team_members: Optional[dict] = None,
                           lineup: Optional[list] = None) -> str:
    now = time.time()
    warm = warm or {"status": "idle"}
    pool = pool or {"status": "unknown"}
    # A removed player is a tombstone: it keeps the row (and its freed name)
    # but is gone from the roster, the count and the action buttons. The
    # tombstone is what lets the same name join again.
    players = [p for p in players if p.status != "removed"]
    rows = []
    for p in players:
        row = next((r for r in board.get("leaderboard", []) if r["player_id"] == p.player_id), {})
        if row:
            score = _score_cell(row)
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
                          f' data-confirm="Disqualify: keeps their box and clock, drops them from the board. Continue?">'
                          f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                          f'<button class="btn danger">Disqualify</button></form>')
        if p.status == "disqualified":
            # §7.1: disqualification is a board exclusion and the run is
            # still alive, so the row offers Reinstate (back on the board)
            # and Remove -- the only verb that releases the box and frees
            # the seat.
            neutral.append(f'<form method="post" action="/admin/players/{esc(p.player_id)}/reinstate" class="inline">'
                           f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                           f'<button class="btn">Reinstate</button></form>')
        if p.status in ("invited", "running", "finished", "disqualified"):
            danger.append(f'<form method="post" action="/admin/players/{esc(p.player_id)}/remove" class="inline"'
                          f' data-confirm="Remove this player from the competition?">'
                          f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                          f'<button class="btn danger">Remove</button></form>')
        if p.box_id and p.claim_uid:
            # The post-run lifecycle: ends this run's access window now by
            # destroying the VM (the seat frees for the next claim). Player
            # status, score and history stay.
            neutral.append(f'<form method="post" action="/admin/players/{esc(p.player_id)}/release_box" class="inline"'
                           f' data-confirm="Release (destroy) this player\'s box now? Their run is over even if their clock says otherwise. Continue?">'
                           f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                           f'<button class="btn">Release box</button></form>')
        sep = '<span class="act-sep" aria-hidden="true"></span>' if neutral and danger else ""
        actions = "".join(neutral) + sep + "".join(danger)
        # Up to four verbs per row was a button wall; they now live behind one
        # "Actions" menu per row (delegated open/close in web.js, so polling
        # can swap rows freely). The forms keep their own buttons + confirms.
        actions_cell = '<span class="muted">—</span>'
        if actions:
            actions_cell = (f'<div class="menu-wrap"><button type="button" class="btn" '
                            f'data-menu-btn aria-haspopup="true" aria-expanded="false">'
                            f'Actions <span aria-hidden="true">▾</span></button>'
                            f'<div class="menu" hidden>{actions}</div></div>')
        claim_note = (f'<div class="small error">{esc(p.claim_error)}</div>'
                      if getattr(p, "claim_error", None) else "")
        # The seat's named roster: handles, not just a count, so an admin
        # adjudicating a dispute can see who was on the team.
        handles = [handle for handle, _added
                   in ((team_members or {}).get(p.player_id) or [])]
        team_note = ""
        if handles:
            team_note = (f'<div class="muted small">{len(handles)}/'
                         f'{max(1, comp.max_team_members)} members: '
                         f'{esc(", ".join(handles))}</div>')
        box_count = (board.get("competition") or {}).get("box_count", 1)
        if box_count > 1:
            got = len(row.get("boxes") or [])
            team_note += (f'<div class="muted small">{got}/{box_count} '
                          f'boxes joined</div>')
        rows.append(f"""<tr><td data-th="Player"><div class="pname"><strong>{esc(p.display_name)}</strong>{player_badge(p.status)}</div>{team_note}{claim_note}</td>
<td class="r" data-th="Score">{score}</td>
<td data-th="Services">{_service_dots(row.get('services'))}</td>
<td class="num r" data-th="Check-in">{checkin}</td>
<td class="small" data-th="Actions">{actions_cell}</td></tr>""")
    controls = []
    if comp.status == "draft":
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/start" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn primary">Start competition</button></form>')
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/end" class="inline" data-confirm="Discard this draft and release any pre-deployed boxes?"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn danger">Discard draft</button></form>')
    if comp.status == "live":
        if comp.join_open:
            controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/close-join" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn">Close joins</button></form>')
        else:
            # Joins closed by mistake used to be permanent: close-join had no
            # counterpart verb, so the only way back was a new competition.
            controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/open-join" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn">Reopen joins</button></form>')
        # Overtime: nudging the run deadline is metadata on the engine side
        # (the boxes and the scoring do not change), so it is offered as a
        # plain form like the other controls.
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/extend" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><label class="small">Extend (min)<input class="input-sm" name="minutes" type="number" min="1" max="360" value="15"></label><button class="btn">Extend</button></form>')
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/end" class="inline" data-confirm="End the competition for everyone?"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn danger">End competition</button></form>')
    if comp.status == "ended":
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/rerun" class="inline"><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn primary">Rerun competition</button></form>')
        controls.append(f'<form method="post" action="/admin/api/competitions/{esc(comp.id)}/delete" class="inline" data-confirm="Remove this competition and its player records? This cannot be undone."><input type="hidden" name="csrf" value="{esc(csrf)}"><button class="btn danger">Remove competition</button></form>')
    join_path = f"/c/{comp.slug}/join"
    # Copy hands the player the whole URL their browser needs, not just the
    # path tail; without a public base the path is all we know.
    join_url = f"{public_base.rstrip('/')}{join_path}" if public_base else join_path
    # A roster export only makes sense once there is a run to export.
    csv_btn = (f'<a class="btn" href="/admin/api/competitions/{esc(comp.id)}'
               f'/export.csv">Export CSV</a>'
               if comp.status in ("live", "ended") else "")
    warm_block = ""
    if comp.status != "ended":
        requested = int(warm.get("requested") or 0)
        available = int(warm.get("available") or 0)
        total = int(warm.get("total") or 0)
        waited = warm.get("waited_s")
        state = warm.get("status")
        if state == "running":
            note = f'<p class="meta">Pre-deploying {requested} boxes…</p>'
        elif state == "queued":
            note = ('<p class="meta">Queued: another competition is filling its '
                    'pool first (the portal provisions one pool at a time).</p>')
        elif state == "ready":
            # A completed pre-deploy is news for a few seconds; the standing
            # count line above carries the state after that, across reloads.
            done = warm.get("finished_at")
            note = ('' if done is not None and now - float(done) > 10
                    else '<p class="okmsg">Box pre-deployment completed.</p>')
        elif state in ("timeout", "error"):
            note = f'<p class="error">{esc(warm.get("error") or "Pre-deploy did not finish.")}</p>'
        else:
            note = ('<p class="meta">Nothing pre-deployed yet: the portal clones '
                    'each box when its player joins. Warm the pool first to move '
                    'that wait off the join.</p>')
        default_count = min(max(1, int(comp.max_players or 8)), 64)
        # A competition with nothing to clone from must not offer a button
        # whose only outcome is a failed job: the reason sits in the card and
        # the click is refused before the thread starts. The form lives inside
        # the polled node so the button re-enables by itself once the scenario
        # (or the engine's pools file) gains the missing pool block.
        blocked = bool(predeploy_warn)
        stale_pin = (pool.get("status") == "unpinned"
                     and bool(comp.workshop_pool_code))
        if blocked:
            pool_line = f'<p class="warnmsg">{esc(predeploy_warn)}</p>'
        # Standing live count from the portal snapshot (survives engine
        # restarts, unlike the in-memory job note below it); both lines live
        # in the polled node so they update without a reload.
        elif pool.get("status") == "ok":
            pool_line = (f"<p class=\"meta\">{int(pool.get('available') or 0)} of "
                         f"{int(pool.get('total') or 0)} boxes ready to claim</p>")
        elif stale_pin:
            # A pin outlives its pool only until the next warm/claim; this is a
            # notice, not an error, and it must not read as "nothing set up".
            pool_line = ('<p class="warnmsg">The pool this competition used is '
                         'gone from the portal; the next pre-deploy or join '
                         'clones a fresh one from the scenario template.</p>')
        elif pool.get("status") == "unpinned":
            pool_line = '<p class="meta">No boxes pre-deployed yet.</p>'
        elif pool.get("status") == "unavailable":
            pool_line = '<p class="meta">Pool count unavailable right now.</p>'
        else:
            pool_line = ""
        if state == "idle" and (blocked or stale_pin
                                or pool.get("status") not in ("unpinned",
                                                               "unknown")):
            # The "nothing pre-deployed yet" explainer only fits an empty pool
            # with nothing else to say; a count, a stale-pin notice or a
            # blocker would contradict it.
            note = ""
        button = (f'<button class="btn" type="submit" disabled title="{esc(predeploy_warn)}">Pre-deploy</button>'
                  if blocked else '<button class="btn" type="submit">Pre-deploy</button>')
        warm_block = f"""<section class="card"><div class="card-head"><h2>Pre-deploy boxes</h2></div>
<div id="warm" data-poll="10000">{pool_line}{note}
<form method="post" action="/admin/api/competitions/{esc(comp.id)}/warm" class="warm-form">
<input type="hidden" name="csrf" value="{esc(csrf)}">
<label class="small">Boxes <input class="input-md" name="count" type="number" min="1" max="64" value="{default_count}"></label>
{button}</form></div></section>"""
    # The pool code is portal plumbing (audit log / journal carry it for
    # debugging); the UI stays quiet about pools unless a claim actually fails,
    # in which case the error text lands on the player row.
    # Scheduled end: a wall-clock auto-End for the whole competition. The
    # sweeper fires it (runs still in progress stop, pool torn down, exactly
    # like pressing End); players see a countdown. Setting/cancelling is a
    # plain form like the other controls.
    schedule_value = "—"
    schedule_controls = ""
    if comp.status in ("draft", "live"):
        scheduled = comp.scheduled_end_at
        cancel_btn = ""
        if scheduled:
            cancel_btn = (
                f' <form method="post" action="/admin/api/competitions/'
                f'{esc(comp.id)}/schedule-end" class="inline">'
                f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                f'<input type="hidden" name="ends_at" value="">'
                f'<button class="btn">Cancel</button></form>')
            schedule_value = (f'{esc(_fmt_ts(scheduled))} · in '
                              f'{_countdown_span(scheduled - now)}'
                              f'{cancel_btn}')
        confirm_attr = (' data-confirm="End the competition automatically at '
                        'the picked time? Runs still in progress stop and '
                        'boxes are torn down. Continue?"'
                        if comp.status == "live" else "")
        schedule_controls = (
            f'<form method="post" action="/admin/api/competitions/'
            f'{esc(comp.id)}/schedule-end" class="inline"{confirm_attr}>'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<label class="small">Ends at '
            f'<input type="datetime-local" name="ends_at" step="60" '
            f'aria-describedby="help-scheduled-end" '
            f'value="{_fmt_dt_input(scheduled) if scheduled else ""}" '
            f'min="{_fmt_dt_input(now)}"></label> '
            f'<button class="btn">{"Update" if scheduled else "Schedule end"}</button>'
            f'</form>')
    elif comp.scheduled_end_at:
        # Kept for the record on an ended competition.
        schedule_value = esc(_fmt_ts(comp.scheduled_end_at))
    auto_end_btn = ""
    if comp.status in ("draft", "live"):
        verb = "Disable" if comp.auto_end else "Enable"
        auto_end_btn = (
            f' <form method="post" action="/admin/api/competitions/'
            f'{esc(comp.id)}/toggle-auto-end" class="inline">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<button class="btn">{verb}</button></form>')
    body = f"""<section class="page-head-row">
<div><div class="title-line"><h1>{esc(comp.name)}</h1>{comp_status_tag(comp.status)}</div>
<p class="meta">/c/{esc(comp.slug)} · {esc(" + ".join(lineup or [comp.scenario_name]))}</p></div>
<div class="actions">{''.join(controls)}</div></section>
{f'<p class="okmsg">{esc(msg)}</p>' if msg else ''}{f'<p class="error">{esc(error)}</p>' if error else ''}
<section class="card"><div class="card-head"><h2>Settings</h2></div>
<div class="facts">
<div class="fact"><span class="fact-label">Status</span><span class="fact-value">{esc(comp_status_label(comp.status))} {comp_badge(comp.status)}</span></div>
<div class="fact"><span class="fact-label">Players</span><span class="fact-value">{_players_joined(len(players), comp.max_players)}</span></div>
<div class="fact"><span class="fact-label">Run duration</span><span class="fact-value">{_fmt_duration(comp.duration_s)} runs</span></div>
<div class="fact wide"><span class="fact-label">Scheduled end</span>
<span class="fact-value">{schedule_value}{schedule_controls}
<span class="help" id="help-scheduled-end">Ends the competition automatically at this time (server clock): every run still in progress stops and boxes are torn down. Competitors see a countdown; Extend moves this along too.</span></span></div>
<div class="fact"><span class="fact-label">Auto-end</span><span class="fact-value">{'On' if comp.auto_end else 'Off'}{auto_end_btn}</span></div>
<div class="fact wide"><span class="fact-label">Join URL</span>
<span class="fact-value"><code>{esc(join_url)}</code> {_copy_btn(join_url, "Copy")}
{csv_btn}</span></div>
</div></section>
{warm_block}
<div id="roster" data-poll="15000">
<section class="card"><div class="card-head"><h2>Players</h2>
</div>
<div class="table-wrap"><table class="roster"><thead><tr><th scope="col">Player</th><th class="r" scope="col">Score</th><th scope="col">Services</th><th class="r" scope="col">Check-in</th><th scope="col">Actions</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="5" class="empty">No players yet.</td></tr>'}</tbody></table></div></section>
</div>"""
    return layout(comp.name, body, comp=comp, admin=True, current="admin")


def styleguide_page() -> str:
    """Admin-only component reference, not linked from the nav.

    Every shared chrome element rendered with the real classes and fake data,
    so a design change can be eyeballed against the whole kit -- and both
    themes, via the nav toggle -- without standing up a competition.
    """

    def swatches(theme: str) -> str:
        chips = "".join(
            f'<div class="fact"><span class="fact-label">{esc(name)}</span>'
            f'<span class="fact-value"><span style="display:inline-block;width:14px;'
            f'height:14px;background:{esc(value)};border:1px solid var(--line-2)"></span>'
            f'<code>{esc(value)}</code></span></div>'
            for name, value in _THEMES[theme].items())
        return f'<div class="facts">{chips}</div>'

    sample_rows = [
        {"rank": 1, "name": "Blue 07", "status": "running", "total": 556,
         "hardening_points": 210, "service_points": 346, "remaining_s": 7199,
         "services": [{"display": "Web", "state": "UP"},
                      {"display": "SSH", "state": "UP"},
                      {"display": "DB", "state": "DOWN"}]},
        {"rank": 2, "name": "Blue 04", "status": "finished", "total": 554,
         "hardening_points": 210, "service_points": 344, "remaining_s": 0,
         "services": [{"display": "Web", "state": "UP"},
                      {"display": "SSH", "state": "UP"},
                      {"display": "DB", "state": "UP"}]},
    ]
    history_services = [
        {"display": "Web", "state": "UP",
         "history": ["UP", "UP", "DOWN", "UP", "UP", "UP", "UP", "UP", "UP", "UP"]},
        {"display": "DB", "state": "DOWN", "history": ["UP", "DOWN", "DOWN"]},
    ]
    body = f"""{_page_head("Styleguide")}
<section class="card"><div class="card-head"><h2>Typography</h2>
<span class="meta">serif display · sans labels</span></div>
<h1 class="demo-h1">Heading one (serif)</h1>
<h2>Heading two</h2>
<p>Body copy runs in the sans face at 16px. <a href="#">A link</a> takes the
readable accent; <span class="muted">muted text</span> and
<span class="small">small text</span> stay chrome-quiet.</p>
<p class="meta">.meta — the caption line under a page title</p>
<p class="help">.help — the whisper under a form field</p>
</section>
<section class="card"><div class="card-head"><h2>Buttons</h2>
<span class="meta">one 32px height · fill carries importance</span></div>
<p class="actions"><button class="btn" type="button">Default</button>
<button class="btn primary" type="button">Primary</button>
<button class="btn danger" type="button">Danger</button>
<button class="btn copied" type="button">Copied (transient)</button>
{_THEME_TOGGLE}</p>
<div class="menu-wrap"><button type="button" class="btn" data-menu-btn aria-haspopup="true" aria-expanded="false">Actions <span aria-hidden="true">▾</span></button>
<div class="menu" hidden><form class="inline" data-confirm="Styleguide demo — this form goes nowhere."><button class="btn" type="submit">Row action</button></form>
<span class="act-sep" aria-hidden="true"></span>
<form class="inline" data-confirm="Styleguide demo — this form goes nowhere."><button class="btn danger" type="submit">Destructive</button></form></div></div>
</section>
<section class="card"><div class="card-head"><h2>Fields</h2>
<span class="meta">the new-competition grid</span></div>
<div class="form-grid form-lead">
<label>Name<input name="sg-name" type="text" placeholder="Friday Night Ranked"></label>
<label>Scenario<select><option>Broadneck Post v1</option></select>
<span class="help">.help — one line of context under a field.</span></label>
</div>
<div class="form-grid form-cols">
<label>Number<input type="number" value="32"></label>
<label>Color<input type="color" value="#5f4a38"></label>
<label>Text<input type="text"></label>
</div>
<div class="form-foot"><button class="btn primary" type="button">Submit on a hairline</button></div>
</section>
<section class="card"><div class="card-head"><h2>Status</h2>
<span class="meta">dots carry the word in a tooltip</span></div>
<p class="row-actions">{comp_badge("live")}{comp_badge("draft")}{comp_badge("ended")}
{player_badge("invited")}{player_badge("running")}{player_badge("disqualified")}
{comp_status_tag("live")}</p>
<p class="row-actions">{_service_dots(sample_rows[0]["services"])}
{_service_dots([])}
<span class="fullflag">full</span>
<span class="fullnote">Competition is full</span></p>
</section>
<section class="card"><div class="card-head"><h2>Service uptime</h2>
<span class="muted small">last 10 ticks</span></div>
{_service_history(history_services)}
</section>
<section class="card"><div class="card-head"><h2>Table</h2>
<span class="meta">leaderboard board, no container</span></div>
{_board_table(sample_rows)}
</section>
<section class="card"><div class="card-head"><h2>Data displays</h2></div>
<div class="facts">
<div class="fact"><span class="fact-label">Status</span><span class="fact-value">{comp_status_label("live")} {comp_badge("live")}</span></div>
<div class="fact"><span class="fact-label">Players</span><span class="fact-value">8 / 32 joined</span></div>
</div>
<dl class="kv">
<dt>Last check-in</dt><dd>{esc(_rel_ts(0))}</dd>
<dt>Duration</dt><dd>{esc(_fmt_duration(5400))} runs</dd>
</dl>
<p class="actions"><span class="bigscore">556</span>
<span class="scoresplit"><span>hardening 210</span><span>services 346</span></span></p>
<div class="codebox"><code>H7X2-9KQA</code>{_copy_btn("H7X2-9KQA", "Copy code")}</div>
</section>
<section class="card"><div class="card-head"><h2>Messages</h2></div>
<p class="okmsg">.okmsg — the box is joined.</p>
<p class="warnmsg">.warnmsg — there is no pool to pre-deploy from.</p>
<p class="error">.error — we couldn't prepare your VM.</p>
<p class="empty">.empty — no players yet.</p>
</section>
<section class="card"><div class="card-head"><h2>Palette — dark roast (:root)</h2></div>
{swatches("dark")}
</section>
<section class="card"><div class="card-head"><h2>Palette — cream (light)</h2></div>
{swatches("light")}
</section>"""
    return layout("Styleguide", body, admin=True, current="admin")




# --- design system ---------------------------------------------------------------

CSS = _theme_css() + """
:root{--font-sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--font-serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
--s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;--s7:48px;
--pad-card:var(--s4) var(--s5);--pad-cell:var(--s2) var(--s3);
--control:32px;--gap-stack:var(--s4);--margin-trail:var(--s7);--header-h:56px}
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
.skip{position:absolute;left:-9999px;top:0;z-index:200}
.visually-hidden{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.skip:focus-visible{left:var(--s2);top:var(--s2);background:var(--surface);border:1px solid var(--line-2);padding:var(--s2) var(--s3);color:var(--ink);font-weight:700;font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;text-decoration:none}
.top{position:sticky;top:0;z-index:20;background:var(--header);border-bottom:1px solid var(--line-2)}
.top .wrap{display:flex;align-items:center;justify-content:space-between;gap:var(--s5);min-height:var(--header-h)}
.brand{font-weight:700;color:var(--ink);font-size:1.08rem}
nav{display:flex;gap:var(--s5);align-items:center}
nav form{display:flex}
/* Every nav entry reserves the same 4px underline slot, so the aria-current
bar changes nothing about the row's alignment (no baseline jump on active).
line-height:1 keeps every entry the same box height; the form is flex so the
logout button skips the anonymous line-box strut that pushed it low. */
nav a,nav button{color:var(--ink-2);font-weight:600;font-size:.76rem;letter-spacing:.09em;text-transform:uppercase;background:none;border:0;padding:0 0 4px;cursor:pointer;font-family:var(--font-sans);transition:color .12s ease;line-height:1}
nav a:hover,nav button:hover{color:var(--ink);text-decoration:none}
nav a[aria-current]{color:var(--ink);box-shadow:inset 0 -2px 0 var(--accent-text)}
/* Borderless glyph: padding:0 drops the nav underline slot (it carries no
text), and the 2px nudge matches the text entries' optical center — their own
4px underline padding rides the glyphs 2px above box center. */
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:var(--control);height:var(--control);border:0;border-radius:0;background:transparent;color:var(--ink-2);cursor:pointer;padding:0;position:relative;top:-2px}
.icon-btn:hover{color:var(--ink)}
.icon-btn svg{width:1rem;height:1rem}
html[data-theme=dark] .ic-moon{display:none}html[data-theme=light] .ic-sun{display:none}
.section-title{margin:var(--s6) 0 calc(-1 * var(--s2));color:var(--muted);font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em}
.hero{padding:var(--s2) 0 0}
.hero .lede{margin:.35rem 0 0;color:var(--muted);max-width:46rem;font-family:var(--font-serif);font-size:1.02rem}
.page-head,.page-head-row{display:flex;align-items:flex-end;justify-content:space-between;gap:var(--s4);flex-wrap:wrap;padding:var(--s2) 0 0}
.title-line{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.meta{margin:.3rem 0 0;color:var(--muted);font-size:.9rem}
.actions{display:flex;gap:var(--s2);flex-wrap:wrap}
/* Header action forms follow the row-action / pre-deploy shape: a captioned
   field keeps its caption above the input and the button base-aligns with the
   input, so Extend doesn't drop its button onto a third row beside the plain
   buttons. */
.actions form{display:inline-flex;align-items:flex-end;gap:var(--s2)}
/* Status is a colored dot beside the text it describes; the word rides in the
hover/focus tooltip (data-tip), so color is never the only signal. */
.sdot{display:inline-block;width:8px;height:8px;border-radius:50%;position:relative;border:0;padding:0;background:transparent;cursor:help;color:var(--muted)}
.sdot::before{content:"";display:block;width:100%;height:100%;border-radius:50%;background:currentColor}
.sdot.ok{color:var(--ok)}.sdot.warn{color:var(--warn)}.sdot.danger{color:var(--danger)}
.sdot.lg{width:10px;height:10px}
.sdot:hover::after,.sdot:focus-visible::after,.sdot.show::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 7px);left:50%;transform:translateX(-50%);background:var(--ink);color:var(--bg);font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;line-height:1;padding:5px 8px;white-space:nowrap;z-index:40;pointer-events:none;border-radius:2px}
/* Near the viewport top (first table rows under the sticky header) the
   tooltip flips below the dot instead of clipping; JS toggles .below. */
.sdot.below:hover::after,.sdot.below:focus-visible::after,.sdot.below.show::after{bottom:auto;top:calc(100% + 7px)}
.sdot:focus-visible{outline:2px solid var(--accent-text);outline-offset:2px}
.pname{display:flex;align-items:center;gap:var(--s2);min-width:0}
/* Admin reads: dot + written-out word, same slot either theme. */
.stwdot{display:inline-flex;align-items:center;gap:var(--s2);font-size:.72rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--ink-2);white-space:nowrap}
/* Draft is the one status that asks for attention before anything is
   happening; the word takes the amber so it survives a scan in light mode. */
.stwdot.warn .word{color:var(--warn)}
tr[data-href]{cursor:pointer}
/* One button height everywhere; importance is the fill color, not size. Every
button rests on a quiet tint and empties to an outline on hover. */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--s2);height:var(--control);padding:0 14px;background:var(--surface-2);color:var(--ink-2);border:1px solid transparent;border-radius:0;font-family:var(--font-sans);font-weight:700;font-size:11.5px;letter-spacing:.07em;text-transform:uppercase;cursor:pointer}
.btn:hover{background:transparent;border-color:currentColor;color:var(--ink);text-decoration:none;filter:none}
.btn.primary{color:var(--accent-text);background:var(--accent-fill)}
.btn.primary:hover{background:transparent;border-color:var(--accent-text);color:var(--accent-text)}
.btn.danger{color:var(--danger);background:var(--danger-bg)}
.btn.danger:hover{background:transparent;border-color:var(--danger);color:var(--danger)}
.btn.copied{color:var(--ok);border-color:var(--ok);background:transparent}
.btn:active{transform:translateY(1px)}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
/* A refused action (no pool to pre-deploy from) must not look pressable. */
.btn[disabled],.btn:disabled{opacity:.55;cursor:not-allowed}
.btn[disabled]:hover,.btn:disabled:hover{background:var(--surface-2);border-color:transparent;color:var(--ink-2)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:0;padding:var(--pad-card)}
.card.narrow{max-width:640px;margin-left:auto;margin-right:auto}
.card h1{font-size:1.3rem}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:var(--s4);min-height:var(--control);margin-bottom:var(--s3)}
.card-head .meta{margin:0;white-space:nowrap;font-variant-numeric:tabular-nums}
.center{text-align:center}
/* The public leaderboard runs straight on the page ground: a head row and the
   table, no panel behind them (the column headers carry the only hairline). */
.board-head{display:flex;align-items:baseline;justify-content:space-between;gap:var(--s4);min-height:var(--control);margin-bottom:var(--s2)}
.board .table-wrap{margin:0}
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
.svcs{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.svcs .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.svcs .dot.up{background:var(--ok)}.svcs .dot.down{background:var(--danger)}.svcs .dot.pending{background:var(--muted)}
.svcs .lbl{color:var(--muted);font-size:.8rem;margin-left:4px;font-variant-numeric:tabular-nums}
.muted{color:var(--muted)}.small{font-size:.82rem}
.cd{font-variant-numeric:tabular-nums}
.input-sm{width:4.5rem}.input-md{width:6rem}
.demo-h1{font-size:1.6rem}
.empty{color:var(--muted);text-align:center;padding:var(--pad-card)}
.inline{display:inline}
.row-actions{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap}
.row-actions form{display:inline-flex}
.act-sep{width:1px;height:16px;background:var(--line-2);flex:none;margin:0 2px}
/* Per-row action menu (admin roster): one trigger, forms stack inside. */
.menu-wrap{position:relative;display:inline-block}
.menu{position:absolute;right:0;top:calc(100% + 4px);z-index:60;min-width:13rem;background:var(--surface);border:1px solid var(--line-2);padding:var(--s1);display:flex;flex-direction:column;gap:2px}
.menu[hidden]{display:none}
.menu form{display:flex}
.menu .btn{width:100%;justify-content:flex-start}
.menu .act-sep{width:auto;height:1px;margin:2px 0}
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
input[type=color]{padding:.15rem;width:3.2rem;height:var(--control);cursor:pointer}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent-text);outline-offset:1px;border-color:var(--accent-text)}
.help{color:var(--muted);font-size:.8rem;font-weight:400}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:var(--s3)}
/* Full-page admin form: one centered column on the bare page ground — no
   card, no tint; the terminal action sits on a hairline. */
.form-page{max-width:46rem;margin:0 auto;width:100%}
.form-lead{grid-template-columns:minmax(0,2fr) minmax(0,3fr)}
.form-cols{grid-template-columns:1fr 1fr 1fr;align-items:start}
.form-foot{display:flex;justify-content:flex-end;border-top:1px solid var(--line);padding-top:var(--s4)}
/* The pre-deploy row: caption+input sit in one column, the button base-aligns
with the input (flex-end, both --control tall), so nothing stacks crooked. */
.warm-form{display:flex;gap:var(--s2);align-items:flex-end;flex-wrap:wrap}
/* The audit filter row is the same shape as the pre-deploy row; one line so
the page keeps the button/field baseline without a rule of its own. */
.filter-form{display:flex;gap:var(--s2);align-items:flex-end;flex-wrap:wrap}
code{background:var(--surface-2);border-radius:0;padding:.08rem .35rem;font-size:.9em}
pre{background:var(--bg);border:1px solid var(--line);border-radius:0;padding:var(--pad-card);overflow:auto}
pre code{background:none;padding:0}
.codebox{display:flex;align-items:center;justify-content:center;gap:var(--s3);font-size:1.9rem;letter-spacing:.28em;text-align:center;background:var(--bg);border:1px dashed var(--line-2);border-radius:0;padding:var(--pad-card);font-weight:800;max-width:100%}
.codebox code{background:none;letter-spacing:inherit;padding:0;overflow-wrap:anywhere}
.vm-actions{display:grid;grid-template-columns:1fr 1fr;gap:var(--s2)}
.okmsg{color:var(--ok);background:var(--ok-bg);border:1px solid var(--ok);border-radius:0;padding:.6rem .85rem}
.warnmsg{color:var(--warn);background:var(--warn-bg);border:1px solid var(--warn);border-radius:0;padding:.6rem .85rem}
.error{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger);border-radius:0;padding:.6rem .85rem}
/* Capacity states users must not miss. */
.fullnote{display:inline-flex;align-items:center;gap:var(--s2);margin:0;color:var(--warn);background:var(--warn-bg);padding:var(--s2) var(--s3);font-size:.78rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;white-space:nowrap}
.fullflag{color:var(--warn);font-weight:700;text-transform:uppercase;letter-spacing:.06em;font-size:.82em}
.stale{color:var(--warn)}
.ungraded{color:var(--warn);font-size:.78rem;font-weight:600}
.steps{list-style:none;counter-reset:step;padding:0;margin:0}
.steps>li{position:relative;padding:0 0 1.7rem 2.7rem;margin:0}
.steps>li:last-child{padding-bottom:.2rem}
.steps>li::before{counter-increment:step;content:counter(step);position:absolute;left:0;top:-.1rem;width:1.75rem;height:1.75rem;border-radius:0;background:var(--accent);color:var(--on-accent);font-weight:700;font-size:.9rem;display:flex;align-items:center;justify-content:center;font-family:var(--font-sans)}
.steps>li:not(:last-child)::after{content:"";position:absolute;left:.85rem;top:1.9rem;bottom:.25rem;width:1px;background:var(--line)}
.steps h2{font-size:1.02rem}
/* Admin login owns the viewport: no card, vertically centered, wide type.
   The header is --header-h tall plus its 1px bottom border. */
body.login-body main.wrap{min-height:calc(100vh - var(--header-h) - 1px);justify-content:center}
.login-page{width:100%;max-width:36rem;margin:0 auto}
.login-page h1{font-size:clamp(2.2rem,5vw,3.1rem);line-height:1.05;margin-bottom:var(--s3)}
.login-page .stack{gap:var(--s4)}
.err-card{text-align:center;margin-top:var(--margin-trail)}
.err-code{font-size:2.4rem;font-weight:800;color:var(--muted);margin:.2rem 0}
.bigscore{font-size:2.6rem;font-weight:800;font-variant-numeric:tabular-nums;line-height:1.15}
.bigtime{font-size:1.9rem;font-weight:700;font-variant-numeric:tabular-nums}
.scoresplit{display:flex;gap:var(--s5);color:var(--muted);font-size:.9rem}
.me-top{align-items:flex-start}
.me-right{text-align:right}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.35rem var(--s5);margin:var(--s3) 0 0;border-top:1px solid var(--line);padding-top:var(--s3)}
.kv dt{color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}.kv dd{margin:0;font-variant-numeric:tabular-nums}
/* The in-competition main page: the viewport is the run. Two columns use the
   full width instead of one narrow card floating in empty space. */
.home-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:var(--s5);flex-wrap:wrap;padding:var(--s2) 0 0}
.home-hero h1{font-size:clamp(2rem,4.5vw,3.2rem);line-height:1.05}
.home-hero .meta{font-size:.95rem}
.home-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(300px,.8fr);gap:var(--s4);align-items:start}
.home-col{display:flex;flex-direction:column;gap:var(--s4);min-width:0}
.home-card{padding:var(--s5)}
.home-card h2{font-size:1.15rem}
.stat-big{font-size:clamp(3rem,7vw,5.2rem);font-weight:800;font-variant-numeric:tabular-nums;line-height:1;font-family:var(--font-serif)}
.stat-clock{font-size:clamp(2.1rem,4.5vw,3.4rem);font-weight:700;font-variant-numeric:tabular-nums;line-height:1.1;font-family:var(--font-serif)}
.home-actions{display:flex;gap:var(--s2);flex-wrap:wrap;margin-top:var(--s3)}
.home-board{grid-column:1 / -1}
/* Per-service last-10-ticks strip: name, oldest->newest dots, current state. */
.svc-history{display:flex;flex-direction:column;gap:2px}
.svc-history-row{display:flex;align-items:center;gap:var(--s3);flex-wrap:wrap;padding:.45rem 0;border-bottom:1px solid var(--line)}
.svc-history-row:last-child{border-bottom:0}
.svc-history-name{flex:1 1 170px;min-width:0;font-weight:600;overflow-wrap:anywhere}
.svc-history .ticks{display:inline-flex;gap:4px;flex:none}
.tick{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--line-2)}
.tick.up{background:var(--ok)}.tick.down{background:var(--danger)}
.tick.void{background:transparent;border:1px solid var(--line-2)}
.svc-history-state{flex:none;font-size:.7rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);min-width:2.6rem;text-align:right}
.svc-history-state.up{color:var(--ok)}.svc-history-state.down{color:var(--danger)}
.home-note{margin:var(--s4) 0 0;color:var(--muted);font-size:.86rem}
.leave-card{border-color:var(--danger)}
/* Polling lost its connection: one quiet banner, added by JS only on failure. */
.poll-err{position:fixed;left:50%;bottom:var(--s4);transform:translateX(-50%);background:var(--danger-bg);color:var(--danger);border:1px solid var(--danger);padding:.5rem .9rem;font-size:.8rem;font-weight:700;letter-spacing:.04em;z-index:90;white-space:nowrap}
/* Confirm modal for [data-confirm] forms (built once by JS, no inline handlers). */
.modal-back{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:100;padding:var(--s4)}
.modal{background:var(--surface);border:1px solid var(--line-2);padding:var(--pad-card);max-width:26rem}
.modal-msg{margin:0 0 var(--s4);font-weight:600}
.modal-actions{display:flex;gap:var(--s2);justify-content:flex-end}
@media(max-width:900px){.home-grid{grid-template-columns:1fr}.home-hero h1{font-size:clamp(1.7rem,6vw,2.6rem)}}
body.display{background:var(--display-bg)}
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
.codebox{font-size:1.35rem;letter-spacing:.18em;padding:var(--s3) var(--s4)}
/* Wide tables become stacked cards: each row is a framed card, each cell a
   label/value pair fed by its data-th attribute. The thead stays in the
   a11y tree (scope="col" still applies), just visually hidden. */
.table-wrap table,.table-wrap tbody,.table-wrap tr,.table-wrap td{display:block;width:100%}
.table-wrap thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.table-wrap tbody tr{border:1px solid var(--line);margin:0 0 var(--s3);padding:var(--s1) 0}
.table-wrap tbody tr:hover td{background:transparent}
.table-wrap tbody tr:hover{background:var(--surface-2)}
.table-wrap td{border:0;border-bottom:1px solid var(--line);padding:.35rem var(--s3);display:flex;align-items:baseline;justify-content:space-between;gap:var(--s3)}
.table-wrap td:last-child{border-bottom:0}
.table-wrap td::before{content:attr(data-th);flex:none;color:var(--muted);font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.09em}
.table-wrap td[data-th=""]::before{content:none}
.table-wrap td.empty{display:block;text-align:center;padding:var(--pad-card)}
.table-wrap td.empty::before{content:none}
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
function themeLabel(t){return t==='dark'?'Switch to light theme':'Switch to dark theme';}
function setThemeMeta(t){
  var m=document.querySelector('meta[name=theme-color]');
  if(m)m.setAttribute('content',t==='light'?'#f7f1e3':'#181410');
}
if(tbtn){
  tbtn.addEventListener('click',function(){
    var r=document.documentElement;
    var next=r.getAttribute('data-theme')==='light'?'dark':'light';
    r.setAttribute('data-theme',next);
    try{localStorage.setItem('huitz-theme',next);}catch(e){}
    tbtn.setAttribute('aria-pressed',next==='dark'?'true':'false');
    tbtn.setAttribute('title',themeLabel(next));
    tbtn.setAttribute('aria-label',themeLabel(next));
    setThemeMeta(next);
  });
  var curTheme=document.documentElement.getAttribute('data-theme')==='dark'?'dark':'light';
  tbtn.setAttribute('aria-pressed',curTheme==='dark'?'true':'false');
  tbtn.setAttribute('title',themeLabel(curTheme));
  tbtn.setAttribute('aria-label',themeLabel(curTheme));
}
/* Status dots: tap toggles the tooltip (touch has no hover), and dots near the
   viewport top flip the tooltip below themselves. */
document.addEventListener('click',function(ev){
  var d=ev.target.closest?ev.target.closest('.sdot'):null;
  if(d){d.classList.toggle('show');}
});
document.addEventListener('mouseover',function(ev){
  var d=ev.target.closest?ev.target.closest('.sdot'):null;
  if(d){d.classList.toggle('below',d.getBoundingClientRect().top<64);}
});
document.addEventListener('focusin',function(ev){
  var d=ev.target.closest?ev.target.closest('.sdot'):null;
  if(d){d.classList.toggle('below',d.getBoundingClientRect().top<64);}
});
/* [data-confirm] forms: one shared modal instead of per-form inline handlers.
   The message arrives as plain text (textContent), never as HTML. */
var modal=null,modalMsg=null,modalOk=null,modalForm=null,modalReturn=null;
function closeModal(ok){
  if(!modal)return;
  modal.remove();modal=null;
  if(modalReturn){modalReturn.focus();modalReturn=null;}
  if(ok&&modalForm){modalForm._confirmed=true;modalForm.requestSubmit?modalForm.requestSubmit():modalForm.submit();}
  modalForm=null;
}
document.addEventListener('submit',function(ev){
  var f=ev.target;
  if(!f||!f.getAttribute)return;
  var msg=f.getAttribute('data-confirm');
  if(!msg||f._confirmed)return;
  ev.preventDefault();
  if(!modal){
    modal=document.createElement('div');
    modal.className='modal-back';
    modal.innerHTML='<div class="modal" role="alertdialog" aria-modal="true" aria-label="Confirm action"><p class="modal-msg"></p><div class="modal-actions"><button type="button" class="btn" data-mc="cancel">Cancel</button><button type="button" class="btn danger" data-mc="ok">Confirm</button></div></div>';
    document.body.appendChild(modal);
    modalMsg=modal.querySelector('.modal-msg');
    modalOk=modal.querySelector('[data-mc=ok]');
    modalOk.addEventListener('click',function(){closeModal(true);});
    modal.querySelector('[data-mc=cancel]').addEventListener('click',function(){closeModal(false);});
    modal.addEventListener('click',function(ev){if(ev.target===modal)closeModal(false);});
    document.addEventListener('keydown',function(ev){
      if(ev.key==='Escape'&&modal){ev.preventDefault();closeModal(false);}
    });
  }
  modalMsg.textContent=msg;
  modalForm=f;
  modalReturn=document.activeElement;
  modal.hidden=false;
  modalOk.focus();
},true);
/* Per-row action menus ([data-menu-btn] + .menu): one open at a time, close
   on outside click or Esc. Delegated, so polled row swaps need no rewiring. */
function closeMenus(){
  $all('.menu').forEach(function(m){m.hidden=true;});
  $all('[data-menu-btn]').forEach(function(b){b.setAttribute('aria-expanded','false');});
}
document.addEventListener('click',function(ev){
  var b=ev.target.closest?ev.target.closest('[data-menu-btn]'):null;
  if(b){
    var wrap=b.closest('.menu-wrap'), m=wrap&&wrap.querySelector('.menu');
    var wasOpen=!!(m&&!m.hidden);
    closeMenus();
    if(m&&!wasOpen){m.hidden=false;b.setAttribute('aria-expanded','true');}
    return;
  }
  if(!(ev.target.closest&&ev.target.closest('.menu')))closeMenus();
});
document.addEventListener('keydown',function(ev){
  if(ev.key==='Escape')closeMenus();
});
function flash(btn,label){
  var lbl=btn.querySelector('span');if(!lbl)return;
  var old=lbl.textContent;lbl.textContent=label||'Copied';btn.classList.add('copied');
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
/* [data-shot] paints the closest .board section onto a canvas and puts the
   PNG on the clipboard (download fallback where ClipboardItem is missing).
   Hand-rolled renderer: the engine ships no third-party JS, so the table is
   redrawn element by element from the live DOM — backgrounds, borders, round
   status dots, and per-line text with its computed font and colors. */
function shotOpaque(color){return !!color&&color!=='transparent'&&color!=='rgba(0, 0, 0, 0)';}
function shotFont(cs){
  return cs.fontStyle+' '+cs.fontWeight+' '+cs.fontSize+' '+cs.fontFamily;
}
function shotTransform(text,tf){
  if(tf==='uppercase')return text.toUpperCase();
  if(tf==='lowercase')return text.toLowerCase();
  if(tf==='capitalize')return text.replace(/\\b\\w/g,function(c){return c.toUpperCase();});
  return text;
}
function shotDrawText(node,ctx){
  var text=node.nodeValue||'';
  if(!text.trim())return;
  var parent=node.parentElement;if(!parent)return;
  var cs=getComputedStyle(parent);
  if(cs.visibility!=='visible')return;
  ctx.font=shotFont(cs);
  ctx.fillStyle=cs.color;
  ctx.textBaseline='middle';
  ctx.textAlign='left';
  if('letterSpacing' in ctx){ctx.letterSpacing=cs.letterSpacing||'0px';}
  text=shotTransform(text,cs.textTransform);
  var r=document.createRange();
  var curTop=null,curStart=0,curRect=null;
  function flush(i,rect){
    if(rect&&i>curStart){
      var piece=text.slice(curStart,i);
      if(piece.trim())ctx.fillText(piece,rect.left,rect.top+rect.height/2);
    }
  }
  for(var i=0;i<text.length;i++){
    r.setStart(node,i);r.setEnd(node,i+1);
    var rects=r.getClientRects();
    var hit=null,j;
    for(j=0;j<rects.length;j++){if(rects[j].width>0||rects[j].height>0){hit=rects[j];break;}}
    if(!hit)continue;
    if(curTop===null){curTop=hit.top;curStart=i;curRect=hit;}
    else if(Math.abs(hit.top-curTop)>2){flush(i,curRect);curTop=hit.top;curStart=i;curRect=hit;}
  }
  if(curTop!==null)flush(text.length,curRect);
}
function shotSkip(el){
  var tag=el.tagName;
  return tag==='BUTTON'||tag==='INPUT'||tag==='SELECT'||tag==='TEXTAREA'||tag==='SVG'
    ||tag==='SCRIPT'||tag==='STYLE'||tag==='NOSCRIPT';
}
function paintShots(el,ctx,rootRect){
  var cs=getComputedStyle(el);
  if(shotSkip(el))return;
  if(cs.visibility!=='visible'||cs.display==='none')return;
  var rect=el.getBoundingClientRect();
  if(rect.bottom<rootRect.top||rect.top>rootRect.bottom)return;
  var small=Math.min(rect.width,rect.height);
  var radius=parseFloat(cs.borderTopLeftRadius)||0;
  if(shotOpaque(cs.backgroundColor)){
    ctx.fillStyle=cs.backgroundColor;
    if(radius>0&&radius>=small/2&&small<=14){
      /* A status dot: fill the circle it declares, never a square. */
      ctx.save();
      ctx.beginPath();
      ctx.arc(rect.left+rect.width/2,rect.top+rect.height/2,small/2,0,Math.PI*2);
      ctx.clip();
      ctx.fillRect(rect.left,rect.top,rect.width,rect.height);
      ctx.restore();
    }else{
      ctx.fillRect(rect.left,rect.top,rect.width,rect.height);
    }
  }
  ['Top','Bottom','Left','Right'].forEach(function(side){
    var w=parseFloat(cs['border'+side+'Width'])||0;
    var stl=cs['border'+side+'Style'];
    if(!w||stl==='none'||stl==='hidden')return;
    if(!shotOpaque(cs['border'+side+'Color']))return;
    ctx.fillStyle=cs['border'+side+'Color'];
    if(side==='Top'||side==='Bottom'){
      ctx.fillRect(rect.left,side==='Top'?rect.top:rect.bottom-w,rect.width,w);
    }else{
      ctx.fillRect(side==='Left'?rect.left:rect.right-w,rect.top,w,rect.height);
    }
  });
}
function shotWalk(el,ctx,rootRect){
  paintShots(el,ctx,rootRect);
  Array.prototype.slice.call(el.childNodes).forEach(function(child){
    if(child.nodeType===3){
      shotDrawText(child,ctx);
    }else if(child.nodeType===1&&!shotSkip(child)){
      shotWalk(child,ctx,rootRect);
    }
  });
}
function shotRootRect(section){
  /* The table hangs wider than the section via the wrap's negative margins:
     grow the capture to cover it, but only while it is not scrolled. */
  var rect=section.getBoundingClientRect();
  var out={left:rect.left,right:rect.right,top:rect.top,bottom:rect.bottom};
  $all('.table-wrap',section).forEach(function(wr){
    if(wr.scrollWidth>wr.clientWidth+1)return;
    var r=wr.getBoundingClientRect();
    if(r.left<out.left)out.left=r.left;
    if(r.right>out.right)out.right=r.right;
  });
  out.width=out.right-out.left;
  out.height=out.bottom-out.top;
  return out;
}
function shotFlashLater(btn,label){return function(){flash(btn,label);};}
document.addEventListener('click',function(ev){
  var btn=ev.target.closest?ev.target.closest('[data-shot]'):null;
  if(!btn||btn._busy)return;
  var section=btn.closest('.board');
  if(!section)return;
  var rect=shotRootRect(section);
  if(rect.width<2||rect.height<2)return;
  btn._busy=true;
  var dpr=Math.min(2,window.devicePixelRatio||1);
  var canvas=document.createElement('canvas');
  canvas.width=Math.ceil(rect.width*dpr);
  canvas.height=Math.ceil(rect.height*dpr);
  var ctx=canvas.getContext('2d');
  ctx.scale(dpr,dpr);
  ctx.translate(-rect.left,-rect.top);
  var bodyBg=getComputedStyle(document.body).backgroundColor;
  ctx.fillStyle=shotOpaque(bodyBg)?bodyBg:'#ffffff';
  ctx.fillRect(rect.left,rect.top,rect.width,rect.height);
  shotWalk(section,ctx,rect);
  var done=shotFlashLater(btn,'Saved');
  var fail=shotFlashLater(btn,'Failed');
  function download(){
    canvas.toBlob(function(blob){
      if(!blob){fail();return;}
      var url=URL.createObjectURL(blob);
      var a=document.createElement('a');
      a.href=url;a.download='leaderboard.png';
      document.body.appendChild(a);a.click();
      setTimeout(function(){document.body.removeChild(a);URL.revokeObjectURL(url);},0);
      done();
    },'image/png');
  }
  if(navigator.clipboard&&window.ClipboardItem&&navigator.clipboard.write){
    var payload=new Promise(function(res){canvas.toBlob(res,'image/png');});
    var item=null;
    try{item=new ClipboardItem({'image/png':payload});}catch(e){item=null;}
    if(item!==null){
      navigator.clipboard.write([item]).then(done,download);
    }else{
      /* Older engines reject a promise payload; hand them the blob once ready. */
      payload.then(function(blob){
        if(!blob){fail();return;}
        try{navigator.clipboard.write([new ClipboardItem({'image/png':blob})]).then(done,download);}
        catch(e2){download();}
      });
    }
  }else{download();}
  setTimeout(function(){btn._busy=false;},300);
});
/* Click anywhere on a competition row (delegated, so polling can swap rows);
   links and buttons inside keep their own behavior. */
document.addEventListener('click',function(ev){
  var row=ev.target.closest?ev.target.closest('tr[data-href]'):null;
  if(row&&!ev.target.closest('a,button')){
    location.href=row.getAttribute('data-href');
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
var pollFails=0,pollBanner=null;
function pollFail(){
  pollFails++;
  if(pollFails>=2&&!pollBanner){
    pollBanner=document.createElement('div');
    pollBanner.className='poll-err';
    pollBanner.setAttribute('role','status');
    pollBanner.textContent='Connection lost — retrying…';
    document.body.appendChild(pollBanner);
  }
  if(pollBanner)pollBanner.hidden=false;
}
function pollOk(){
  pollFails=0;
  if(pollBanner)pollBanner.hidden=true;
}
function poll(){
  if(document.hidden){return;}
  var ae=document.activeElement;
  if(ae&&ae.closest&&ae.closest('[data-poll]')){return;}
  if(Date.now()-lastTouch<8000){return;}
  $all('[data-poll]').forEach(function(node){
    if(!node.id){return;}
    /* Ask for just this node (?frag=<id>): the server answers with the
       fragment alone, so a poll costs a few hundred bytes, not the page. */
    var url=location.href+(location.href.indexOf('?')>=0?'&':'?')+
            'frag='+encodeURIComponent(node.id);
    fetch(url,{credentials:'same-origin'}).then(function(r){
      if(!r.ok){throw 0;}return r.text();
    }).then(function(text){
      pollOk();
      var doc=new DOMParser().parseFromString(text,'text/html');
      var fresh=doc.getElementById(node.id);
      if(fresh&&fresh.outerHTML!==node.outerHTML){
        node.replaceWith(fresh);armCountdowns();
      }
    }).catch(pollFail);
  });
}
var rates=$all('[data-poll]').map(function(n){
  return parseInt(n.getAttribute('data-poll'),10)||0;
}).filter(function(v){return v>=2000;});
if(rates.length){setInterval(poll,Math.min.apply(null,rates));}
/* Join-success claim polling: #vm-poll carries the player id and the claim
   state at render time; reload when the box binds or any of it changes. */
var vmp=document.getElementById('vm-poll');
if(vmp){
  (function(){
    var pid=vmp.getAttribute('data-pid')||'';
    var startUrl=vmp.getAttribute('data-url')||'';
    var startErr=vmp.getAttribute('data-err')||'';
    var startCodeExp=parseFloat(vmp.getAttribute('data-code-exp')||'0');
    var polls=0;
    var t=setInterval(function(){
      if(++polls>200){clearInterval(t);return;}
      fetch('/api/public/join/'+encodeURIComponent(pid)+'/status').then(function(r){return r.ok?r.json():null;}).then(function(d){
        if(!d)return;
        if(d.box_bound){location.reload();return;}
        if((d.claim_url||'')!==startUrl||(d.claim_error||'')!==startErr||
           (d.code_expires_at||0)!==startCodeExp){location.reload();}
      }).catch(function(){});
    },3000);
  })();
}
})();
"""


# --- static assets --------------------------------------------------------------
# The theme-init script, the stylesheet and the page script ship from /static/
# under a content-hash URL: cacheable across pages and poll fetches, and they
# keep the page free of inline script blocks so the CSP needs no
# 'unsafe-inline' for script-src. Only the per-competition accent variables
# stay as a body style attribute (style-src keeps 'unsafe-inline').

_STATIC_BODIES = {"theme-init.js": THEME_INIT, "web.css": CSS, "web.js": JS}


def _h(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def static_url(logical: str) -> str:
    """Cache-busting URL for a static asset, e.g. static_url('web.css')."""
    return f"/static/{logical}.{_h(_STATIC_BODIES[logical])}"


def static_asset(path: str):
    """(content_type, body) for a /static/<logical>.<hash> request, or None."""
    name = path.rsplit("/", 1)[-1]
    logical = name.rpartition(".")[0]
    if logical in _STATIC_BODIES:
        ctype = "text/css" if logical.endswith(".css") else "application/javascript"
        return ctype, _STATIC_BODIES[logical]
    return None


# --- poll fragments ---------------------------------------------------------------

_FRAG_DIV = re.compile(r"<(/?)div\b[^>]*>", re.IGNORECASE)


def extract_fragment(page_html: str, frag_id: str):
    """The outer HTML of the ``<div id="frag_id">…</div>`` poll node, or None.

    Poll fetches ask for ``?frag=<id>`` so they download only the node they
    swap in, not the whole page. The scan is a balanced ``<div>`` count over
    our own generated markup (no attribute value ever contains ``<div``).
    """
    m = re.search(r'<div\s+id="%s"[^>]*>' % re.escape(frag_id), page_html)
    if not m:
        return None
    depth = 1
    for tag in _FRAG_DIV.finditer(page_html, m.end()):
        if tag.group(1):
            depth -= 1
            if depth == 0:
                return page_html[m.start():tag.end()]
        else:
            depth += 1
    return None
