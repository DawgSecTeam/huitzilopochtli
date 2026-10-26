"""Unit tests for the redesigned engine web pages (engine/web.py).

Covers the theming contract (dark + light tokens, no-FOUC script, toggle),
progressive-enhancement hooks (polling, countdowns, copy buttons), the shared
formatting helpers, and the join-gating logic.
"""
import json
import time

from engine.store import CompetitionRecord, PlayerRecord
from engine import web


def _comp(**over):
    now = time.time()
    base = dict(id="c1", slug="demo", name="Demo Cup", scenario_name="demo",
                scenario_version=1, status="live", join_open=True, max_players=32,
                duration_s=7200, workshop_pool_code=None, theme_json=None,
                join_instructions=None, created_at=now, started_at=now, ended_at=None)
    base.update(over)
    return CompetitionRecord(**base)


def _player(**over):
    now = time.time()
    base = dict(player_id="p1", competition_id="c1", display_name="Ada",
                display_name_norm="ada", status="running", join_code_hash=None,
                join_code_plain="ABCD2345", join_code_expires_at=now + 1800,
                joined_at=now, started_at=now, ends_at=now + 3600, finished_at=None,
                box_id="box-1", claim_url="http://guac/x", claim_uid=None,
                claim_ticket=None, claim_expires_at=None)
    base.update(over)
    return PlayerRecord(**base)


def _board_row(**over):
    now = time.time()
    row = dict(player_id="p1", name="Ada", status="running", total=120,
               hardening_points=100, service_points=20, started_at=now,
               ends_at=now + 3600, remaining_s=7199, last_checkin=now - 30,
               services=[{"id": "web", "display": "Demo web", "check_id": "s1",
                          "state": "UP", "accrued_points": 3, "last_changed_at": now},
                         {"id": "ssh", "display": "SSH", "check_id": "s2",
                          "state": "DOWN", "accrued_points": 0, "last_changed_at": now}],
               box_bound=True, rank=1)
    row.update(over)
    return row


def _payload(**over):
    comp = _comp()
    data = dict(competition=dict(id=comp.id, slug=comp.slug, name=comp.name,
                                 scenario_name=comp.scenario_name,
                                 scenario_version=comp.scenario_version,
                                 status=comp.status, join_open=True, max_players=32,
                                 player_count=1, duration_s=comp.duration_s,
                                 started_at=comp.started_at, ended_at=None,
                                 theme={}, join_instructions=None, can_join=True),
                leaderboard=[_board_row()], generated_at=time.time())
    data["competition"].update(over.pop("competition", {}))
    data.update(over)
    return data


# --- theming -----------------------------------------------------------------


def test_layout_has_both_theme_token_sets_and_no_flash_script():
    page = web.layout("T", "<p>hi</p>")
    # Dark-roast tokens on :root, cream overrides keyed off data-theme.
    assert ":root{" in web.CSS and "--bg:#181410" in web.CSS
    assert "html[data-theme=light]" in web.CSS and "--bg:#f7f1e3" in web.CSS
    # Cream editorial signature: serif headings, hard espresso frames, sharp
    # panels -- but the status/service *dots* are round.
    assert "Palatino,Georgia,serif" in web.CSS
    assert "--line-2:#8d7f66" in web.CSS
    assert "border-radius:50%" in web.CSS
    assert ".card{background:var(--surface);border:1px solid var(--line);border-radius:0" in web.CSS
    # The theme-init script runs before the stylesheet (no flash of wrong theme).
    head = page.split("<style>")[0]
    assert "localStorage.getItem('huitz-theme')" in head
    assert "matchMedia" in head
    assert 'id="theme-toggle"' in page


def test_theme_toggle_only_responds_to_data_theme():
    # Icon visibility is driven purely by the html attribute, not JS state.
    assert "html[data-theme=dark] .ic-moon{display:none}" in web.CSS
    assert "html[data-theme=light] .ic-sun{display:none}" in web.CSS


def test_theme_colors_come_from_one_python_table():
    # CSS, the favicon, and the accent-contrast anchors all read _THEMES, so a
    # palette edit cannot desync between CSS and Python.
    assert web.CSS.startswith(":root{color-scheme:dark;--bg:#181410")
    assert "html[data-theme=light]{color-scheme:light;--bg:#f7f1e3" in web.CSS
    assert web._THEMES["dark"]["bg"] in web._FAVICON.replace("%23", "#")
    assert web._THEMES["dark"]["accent"] in web._FAVICON.replace("%23", "#")
    assert web._CANVAS["dark"] == web._THEMES["dark"]["surface-2"]
    assert web._INK_ANCHOR["light"] == web._THEMES["light"]["ink"]


def test_spacing_tokens_exist_and_dead_rules_are_gone():
    # One 4px scale plus derived padding/control tokens; the old ad-hoc gaps
    # and the ghost/sm button tiers are gone.
    for token in ("--s1", "--s2", "--s3", "--s4", "--s5", "--s6", "--s7",
                  "--pad-card", "--pad-cell", "--control", "--gap-stack",
                  "--font-sans", "--font-serif"):
        assert token in web.CSS
    for dead in (".chip-links", ".link{", "#clock", "font-weight:650",
                 "font-weight:750", ".page-head .btn{", ".badge",
                 ".btn.ghost", ".btn.sm", "--gap-actions", "--gap-layout"):
        assert dead not in web.CSS


def test_display_board_is_chrome_free_and_pinned_dark():
    page = web.display_page(_payload())
    assert 'data-theme="dark"' in page  # pinned before any script runs
    assert "<header" not in page and "<footer" not in page
    assert 'data-poll="5000"' in page


def test_accent_sanitized_and_on_accent_luminance_guard():
    assert web.sanitize_accent("#E05D3F") == "#E05D3F"
    assert web.sanitize_accent("red") == web.DEFAULT_ACCENT
    assert web.sanitize_accent("#zzzzzz") == web.DEFAULT_ACCENT
    assert web._on_accent("#c99a62") == "#211c16" or web._on_accent("#5f4a38") == "#ffffff"
    assert web._on_accent("#f7e01e") == "#1f2328"   # light accent -> dark text
    page = web.competition_page(_payload(competition={"theme": {"accent": "#f7e01e"}}))
    assert '--on-accent:#1f2328' in page


# --- contrast contract -------------------------------------------------------


def test_default_accent_is_unreadable_on_dark_and_variant_fixes_it():
    # The regression this guards: the default admin-picked accent (#5f4a38)
    # was 1.8:1 as dark-theme link text.
    assert web._contrast_ratio("#5f4a38", "#2b251d") < 4.5
    fixed = web._readable_text("#5f4a38", "dark")
    assert web._contrast_ratio(fixed, "#2b251d") >= 4.5


def test_accent_text_variants_meet_contrast_on_both_themes():
    for accent in ("#5f4a38", "#c99a62", "#f7e01e", "#2e7d32", "#0d47a1",
                   "#ffffff", "#000000"):
        dark_text = web._readable_text(accent, "dark")
        light_text = web._readable_text(accent, "light")
        assert web._contrast_ratio(dark_text, "#2b251d") >= 4.5, accent
        assert web._contrast_ratio(light_text, "#e6dcc6") >= 4.5, accent
    # Already-readable accents pass through untouched.
    assert web._readable_text("#c99a62", "dark") == "#c99a62"
    assert web._readable_text("#5f4a38", "light") == "#5f4a38"


def test_layout_ships_accent_text_variants_and_css_uses_them():
    page = web.admin_competition_page(_comp(), {"leaderboard": []}, [], "csrf")
    assert "--accent-dk:#" in page and "--accent-lt:#" in page
    # Whisper fills for the primary button's resting state ship alongside.
    assert "--accent-fill-dk:" in page and "--accent-fill-lt:" in page
    assert "a{color:var(--accent-text)" in web.CSS
    assert "html[data-theme=light] body{--accent-text:var(--accent-lt)" in web.CSS
    # Accent-as-text never uses the raw accent (raw stays for fills: steps).
    assert "a{color:var(--accent)}" not in web.CSS
    # Row actions are buttons now; the text-link idiom is gone.
    assert ".link{" not in web.CSS


def test_buttons_share_one_height_and_tint_at_rest():
    # One height everywhere; importance is color, not size. Resting state is a
    # quiet tint; hover empties the button to an outline.
    assert "--control:32px" in web.CSS
    assert ".btn.primary{color:var(--accent-text);background:var(--accent-fill)}" in web.CSS
    assert ".btn.danger{color:var(--danger);background:var(--danger-bg)}" in web.CSS
    assert ".btn:hover{background:transparent" in web.CSS
    # Inputs match the control height so form rows align.
    assert "input,select{height:var(--control)" in web.CSS


def test_palette_tokens_clear_45_to_1_on_worst_surface():
    import re
    def tokens(block):
        return dict(re.findall(
            r"--(surface-2|ink|ink-2|muted|faint|ok|warn|danger):(#[0-9a-f]{6})", block))
    dark = tokens(web.CSS.split("html[data-theme=light]")[0])
    light = tokens(web.CSS.split("html[data-theme=light]")[1])
    for name in ("muted", "faint", "ok", "warn", "danger"):
        dark_ratio = web._contrast_ratio(dark[name], dark["surface-2"])
        light_ratio = web._contrast_ratio(light[name], light["surface-2"])
        assert dark_ratio >= 4.5, f"dark --{name} {dark[name]} is {dark_ratio:.2f}:1"
        assert light_ratio >= 4.5, f"light --{name} {light[name]} is {light_ratio:.2f}:1"


# --- progressive enhancement ----------------------------------------------------


def test_leaderboard_polls_and_carries_countdown_data():
    page = web.competition_page(_payload())
    assert 'id="board" data-poll="5000"' in page
    assert "<noscript><meta http-equiv=\"refresh\" content=\"5\"></noscript>" in page
    # Server-rendered countdown fallback + data attribute for the JS ticker.
    assert 'data-remaining="7199"' in page and ">1:59:59<" in page
    assert 'data-updated' in page


def test_leaderboard_folds_point_columns_into_the_score_cell():
    page = web.competition_page(_payload())
    assert "<th>Hardening</th>" not in page
    assert "<th>Services</th>" not in page
    assert "<th>Services up</th>" in page
    assert "H 100 · S 20" in page  # breakdown rides under the total


def test_settings_card_is_a_fact_grid():
    page = web.admin_competition_page(_comp(), _payload(), [_player()], "csrf")
    assert 'class="facts"' in page and 'class="fact-label">Status<' in page
    assert 'class="fact-label">Players<' in page and "1 / 32 joined" in page
    assert 'class="fact-label">Join URL<' in page


def test_copy_buttons_present_on_join_success_and_admin_comp():
    # The terminal fallback (with the copyable code) appears only when the
    # automatic join failed; pending and ready states never need it.
    failed = _player(status="invited", box_id=None, claim_url=None,
                     claim_error="huitz not found in the guest")
    page = web.join_success_page(_comp(), failed, join_code="ABCD2345",
                                 csrf="csrf1")
    assert 'data-copy="ABCD2345"' in page and "Copy code" in page
    pending = _player(status="invited", box_id=None, claim_url=None,
                      claim_ticket="t1")
    page = web.join_success_page(_comp(), pending, join_code="ABCD2345",
                                 csrf="csrf1")
    assert 'data-copy="ABCD2345"' not in page
    ready = _player(status="invited", box_id=None,
                    claim_url="http://portal/r/u1")
    page = web.join_success_page(_comp(), ready, join_code="ABCD2345",
                                 csrf="csrf1")
    assert 'data-copy="http://portal/r/u1"' in page  # stable open link
    board = _payload()
    admin = web.admin_competition_page(_comp(), board, [_player()], "csrf")
    assert 'data-copy="/c/demo/join"' in admin  # join URL


def test_join_success_leads_with_the_link_and_hides_retry_once_vmed():
    ready = _player(status="invited", box_id=None,
                    claim_url="http://portal/r/u1")
    page = web.join_success_page(_comp(), ready, join_code="ABCD2345",
                                 csrf="csrf1")
    assert "Open my VM" in page
    assert "clock starts when you open" in page
    # A working VM link is never paired with a "get a new one" button.
    assert 'action="/api/public/join/p1/claim"' not in page
    assert "Get a new VM" not in page
    # Open + copy sit in an equal two-column row.
    assert '<div class="vm-actions">' in page
    # All buttons are one size; the copy button matches its neighbor exactly.
    assert 'class="btn" data-copy="http://portal/r/u1"' in page


def test_back_links_are_buttons_everywhere():
    assert '<a class="btn" href="/">Back</a>' in web.error_page(404, "Not found")
    page = web.join_form_page(_comp(), closed_notice="Joins are closed.")
    assert 'class="btn" href="/c/demo"' in page


def test_join_success_shows_claim_error_and_retry():
    failed = _player(status="invited", box_id=None, claim_url=None,
                     claim_error="No VMs available right now.")
    page = web.join_success_page(_comp(), failed, csrf="csrf1")
    assert "No VMs available right now." in page
    assert "Get a new VM" in page
    # The old dead-end copy is gone.
    assert "ask the admin" not in page


def test_join_success_pending_page_polls_without_a_dead_end():
    pending = _player(status="invited", box_id=None, claim_url=None,
                      claim_ticket="t1")
    page = web.join_success_page(_comp(), pending, csrf="csrf1")
    assert "being prepared" in page
    assert "/status" in page
    assert "ask the admin" not in page
    assert "Get a new VM" in page


def test_bound_join_success_hides_the_fallback_code():
    page = web.join_success_page(_comp(), _player(), join_code="ABCD2345")
    assert "Your box is joined" in page
    assert 'data-copy="ABCD2345"' not in page


def test_player_page_hides_retry_once_a_vm_exists():
    vmed = _player(status="invited", box_id=None,
                   claim_url="http://portal/r/u1")
    page = web.player_page(_comp(), vmed, None, "http://portal/r/u1",
                           csrf="csrf1")
    assert "Open my VM" in page
    assert 'action="/api/public/join/p1/claim"' not in page
    # Error and never-claimed states keep the recovery form.
    failed = _player(status="invited", box_id=None, claim_url=None,
                     claim_error="portal down")
    assert 'action="/api/public/join/p1/claim"' in web.player_page(
        _comp(), failed, None, None, csrf="csrf1")


def test_admin_page_hides_pool_plumbing_and_keeps_claim_retry():
    failed = _player(status="invited", box_id=None, claim_url=None,
                     claim_error="workshop portal unreachable")
    pinned = web.admin_competition_page(_comp(workshop_pool_code="POOL1"),
                                        _payload(), [failed], "csrf")
    # The pool is engine-provisioned plumbing: neither the code nor pool prose
    # appears in the UI at all; failures surface on the player row instead.
    assert "Workshop pool" not in pinned and "provisioned" not in pinned
    assert "POOL1" not in pinned
    assert 'name="pool_code"' not in pinned
    assert "Save pool" not in pinned
    assert 'action="/admin/players/p1/retry-claim"' in pinned
    assert "workshop portal unreachable" in pinned


def test_player_page_shows_score_countdown_and_checkin():
    page = web.player_page(_comp(), _player(), _board_row(), "http://guac/x")
    assert 'data-poll="15000"' in page
    assert "Last check-in" in page
    assert "data-remaining" in page


def test_status_dots_carry_the_word_in_a_tooltip():
    # Color is never the only signal: the label lives in data-tip/aria-label.
    live = web.comp_badge("live")
    assert 'data-tip="Live"' in live and 'aria-label="Competition status: Live"' in live
    assert 'class="sdot ok"' in live
    assert 'data-tip="Draft"' in web.comp_badge("draft")
    assert 'data-tip="Ended"' in web.comp_badge("ended")
    assert 'data-tip="Disqualified"' in web.player_badge("disqualified")
    assert 'class="badge' not in live + web.player_badge("invited")


def test_service_dots_carry_text_not_color_alone():
    dots = web._service_dots([{"display": "Demo web", "state": "UP"},
                              {"display": "SSH", "state": "DOWN"}])
    assert 'title="Demo web — UP"' in dots and 'title="SSH — DOWN"' in dots
    assert "1/2 up" in dots


# --- formatting helpers ----------------------------------------------------------


def test_countdown_format_never_ambiguous():
    assert web._fmt_countdown(7199) == "1:59:59"
    assert web._fmt_countdown(59) == "0:59"
    assert web._fmt_countdown(3600) == "1:00:00"


def test_duration_format():
    assert web._fmt_duration(7200) == "2h"
    assert web._fmt_duration(5400) == "1h 30m"
    assert web._fmt_duration(2700) == "45 min"


def test_relative_timestamps():
    now = time.time()
    assert web._rel_ts(now - 3, now) == "just now"
    assert web._rel_ts(now - 42, now) == "42s ago"
    assert web._rel_ts(now - 300, now) == "5m ago"
    assert web._rel_ts(None, now) == "—"


# --- join gating ----------------------------------------------------------------


def test_join_box_reasons():
    def comp(**over):
        return _payload(competition=over)["competition"]
    live = comp(status="live", join_open=True, max_players=4, player_count=1)
    assert "Join this competition" in web._join_box(live)
    full = comp(status="live", join_open=True, max_players=4, player_count=4)
    assert "Competition is full." in web._join_box(full)
    closed = comp(status="live", join_open=False, max_players=4, player_count=1)
    assert "Joins are closed." in web._join_box(closed)
    draft = comp(status="draft", join_open=True, max_players=4, player_count=0)
    assert "Competition hasn&#x27;t started." in web._join_box(draft)
    ended = comp(status="ended", join_open=True, max_players=4, player_count=1)
    assert "Competition has ended." in web._join_box(ended)


def test_join_form_closed_notice_replaces_the_form():
    page = web.join_form_page(_comp(), closed_notice="Joins are closed.")
    assert "<form" not in page
    assert "Joins are closed." in page
    open_page = web.join_form_page(_comp())
    assert 'name="name"' in open_page


def test_index_cards_only_offer_join_when_live_and_open():
    out = web._comp_cards([_comp()])
    assert '>/demo/join"' not in out or "Join" in out
    assert "Join" in web._comp_cards([_comp(status="live", join_open=True)])
    assert "/join" not in web._comp_cards([_comp(status="draft", join_open=True)])
    assert "/join" not in web._comp_cards([_comp(status="ended", join_open=False)])


# --- error pages -----------------------------------------------------------------


def test_error_page_is_styled_with_back_link():
    page = web.error_page(404, "Not found", "Nothing here.", "/c/demo")
    assert page.startswith("<!doctype html>")
    assert ">404<" in page or "404</p>" in page
    assert "Nothing here." in page and 'href="/c/demo"' in page


# --- admin extras ------------------------------------------------------------------


def test_admin_roster_confirmations_on_destructive_actions():
    board = _payload()
    page = web.admin_competition_page(_comp(), board, [_player()], "csrf")
    assert "Disqualify this player?" in page
    assert "Remove this player from the competition?" in page
    # The csrf hidden input keeps its exact shape (tests parse it with a regex).
    assert '<input type="hidden" name="csrf" value="csrf">' in page


def test_admin_roster_actions_are_spaced_and_danger_set_apart():
    invited = _player(status="invited", box_id=None)
    page = web.admin_competition_page(_comp(), {"leaderboard": []}, [invited], "csrf")
    # Actions used to concatenate into "Retry VMReissue codeRemove".
    assert '<div class="row-actions">' in page
    assert 'class="act-sep"' in page        # a rule between neutral and danger
    assert 'class="btn">Retry VM</button>' in page
    assert 'class="btn">Reissue code</button>' in page
    assert 'class="btn danger">Remove</button>' in page
    running = web.admin_competition_page(_comp(), {"leaderboard": []},
                                         [_player()], "csrf")
    assert 'class="btn danger">Disqualify</button>' in running
    # The join code is plumbing: never rendered in the roster, copyable or not.
    assert 'data-copy="ABCD2345"' not in page
    assert "ABCD2345" not in page


def test_admin_roster_marks_unstarted_players():
    invited = _player(status="invited", box_id=None)
    page = web.admin_competition_page(_comp(), {"leaderboard": []}, [invited], "csrf")
    assert "not started" in page
    page = web.admin_competition_page(_comp(), _payload(), [_player()], "csrf")
    assert "not started" not in page
    # A bound box has consumed the join code; the chip (and copy) go away.
    assert 'data-copy="ABCD2345"' not in page


def test_admin_roster_rows_are_single_line():
    invited = _player(status="invited", box_id=None)
    page = web.admin_competition_page(_comp(), {"leaderboard": []}, [invited], "csrf")
    # Name and status dot share one line (the join code no longer rides along).
    assert '<div class="pname"><strong>Ada</strong><button class="sdot' in page
    # Score breakdown rides under the total in one right-aligned cell.
    page = web.admin_competition_page(_comp(), _payload(), [_player()], "csrf")
    assert ('<div class="score-cell"><span class="score">120</span>'
            '<span class="muted small">H 100 · S 20</span></div>') in page
    assert 'class="roster"' in page


def test_admin_roster_disqualified_player_has_no_actions():
    dq = _player(status="disqualified")
    page = web.admin_competition_page(_comp(), {"leaderboard": []}, [dq], "csrf")
    assert "Retry VM" not in page and "Remove</button>" not in page
    assert '<span class="muted">—</span></td></tr>' in page


# --- round 2: form automation + de-chroming ---------------------------------------


def test_derive_slug():
    import re
    from engine.competition import derive_slug
    assert re.match(r"^[a-z0-9-]+$", derive_slug("Friday Night Ranked!", set()))
    assert derive_slug("Friday Night Ranked", set()) == "friday-night-ranked"
    assert derive_slug("Initial Test", set()) == "initial-test"
    assert derive_slug("  ", set()) == "competition"
    assert derive_slug("Demo", {"demo"}) == "demo-2"
    assert derive_slug("Demo", {"demo", "demo-2", "demo-3"}) == "demo-4"
    # Non-ASCII is replaced, not transliterated.
    assert derive_slug("Héllo -- World!!", set()) == "h-llo-world"


def test_new_competition_form_dropdown_from_folder():
    page = web.admin_new_competition_page(
        [("Ranked Demo", 2, "/boxes/ranked-demo"),
         ("Static Pine Community Radio", 1, "/boxes/static-pine-radio")], "csrf")
    assert 'name="name"' in page
    assert 'name="scenario"' in page and 'value="Ranked Demo|2"' in page
    assert 'name="max_players"' in page and 'name="duration_min"' in page
    assert 'name="accent"' in page
    for gone in ('name="slug"', 'name="workshop_pool_code"',
                 'name="pool_code"', 'Workshop pool',
                 'name="join_instructions"'):
        assert gone not in page
    empty = web.admin_new_competition_page([], "csrf")
    assert "No ranked scenarios found" in empty
    # Centered heading with the short Back link beneath it.
    assert 'class="page-head"' in page and ">Back</a>" in page


def test_dashboard_has_no_audit_card_or_scenario_column():
    page = web.admin_dashboard_page([_comp()], {"c1": 1}, "csrf")
    assert "Recent admin actions" not in page
    assert "<th>Scenario</th>" not in page


def test_footer_removed_sitewide():
    for page in (web.index_page([_comp()]), web.login_page(),
                 web.competition_page(_payload())):
        assert "<footer" not in page and 'id="clock"' not in page


def test_nav_is_identical_across_pages_and_logout_is_admin_only():
    """The Admin entry is the same element in the same slot everywhere; only
    admin pages additionally carry the POST-only Log out control."""
    import re

    def nav_hrefs(doc):
        nav = re.search(r"<nav>(.*?)</nav>", doc, re.S).group(1)
        return re.findall(r'<a href="([^"]*)"', nav)

    public = [web.index_page([_comp()]), web.login_page(),
              web.competition_page(_payload()),
              web.error_page(404, "Not found", "", "/")]
    for page in public:
        assert nav_hrefs(page) == ["/", "/admin"]
        assert 'href="/admin"' in page.split("<nav>")[1]  # plain nav link
        assert 'class="btn ghost sm" href="/admin"' not in page
        assert "/admin/logout" not in page
    admin = [web.admin_dashboard_page([], {}, "csrf"),
             web.admin_new_competition_page([], "csrf"),
             web.admin_competition_page(_comp(), {"leaderboard": []}, [], "csrf")]
    for page in admin:
        assert nav_hrefs(page) == ["/", "/admin"]
        assert 'action="/admin/logout"' in page
        assert ">Log out</button>" in page


def test_index_competitions_are_stacked_rows():
    out = web._comp_cards([_comp()])
    assert 'class="comp-list"' in out and 'class="card comp-row"' in out
    assert 'class="grid"' not in out


def test_workshop_admin_calls_carry_basic_auth(monkeypatch):
    import base64
    from engine import workshop
    seen = {}

    def fake_call(base, method, path, *args, **kw):
        seen.update(method=method, path=path, headers=kw.get("headers"))
        return []

    monkeypatch.setattr(workshop, "_call", fake_call)
    expected = base64.b64encode(b"admin:pw").decode()
    workshop.list_pools("http://portal", "pw")
    assert (seen["method"], seen["path"]) == ("GET", "/api/admin/pools")
    assert seen["headers"]["Authorization"] == f"Basic {expected}"
    workshop.delete_pool("http://portal", "pw", "ABCDE")
    assert (seen["method"], seen["path"]) == ("DELETE", "/api/admin/pools/ABCDE")


# --- round 3: rerun, admin login button, public index filtering -------------------


def test_public_index_shows_only_live_admins_see_all():
    live = _comp()
    draft = _comp(status="draft", slug="draft-cup", name="Draft Cup")
    ended = _comp(status="ended", slug="old-cup", name="Old Cup")
    public = web.index_page([live, draft, ended], admin_view=False)
    assert "Draft Cup" not in public and "Old Cup" not in public
    assert "Demo Cup" in public
    admin = web.index_page([live, draft, ended], admin_view=True)
    assert "Draft Cup" in admin and "Old Cup" in admin


def test_status_dots_render_on_every_competition_card():
    # The dot sits beside the title with its tooltip; there is no separate
    # badge column and no hidden-vs-shown distinction between sections.
    out = web._comp_cards([_comp()])
    assert 'data-tip="Live"' in out
    other = web._comp_cards([_comp(status="ended")])
    assert 'data-tip="Ended"' in other
    assert 'class="badge' not in out + other


def test_public_nav_has_admin_login_button():
    page = web.index_page([], admin_view=False)
    assert 'href="/admin">Admin</a>' in page
    admin_page = web.admin_dashboard_page([], {}, "csrf")
    # Admin nav keeps its link; on admin pages it is the current page.
    assert 'href="/admin" aria-current="page">Admin</a>' in admin_page


def test_ended_competition_has_rerun_button():
    comp = _comp(status="ended")
    page = web.admin_competition_page(comp, {"leaderboard": []}, [], "csrf")
    assert "Rerun competition" in page
    assert f'/admin/api/competitions/{comp.id}/rerun' in page
    live_page = web.admin_competition_page(_comp(), {"leaderboard": []}, [], "csrf")
    assert "Rerun competition" not in live_page


# --- round 4: box-folder scenario source -------------------------------------------


def test_box_scenario_scanner(tmp_path, monkeypatch):
    from engine import scenario
    boxes = tmp_path / "boxes"
    ranked = boxes / "ranked-demo"
    ranked.mkdir(parents=True)
    (ranked / "engine_record.json").write_text(json.dumps(
        {"rubric": {"scenario_name": "Ranked Demo", "scenario_version": 2},
         "adversary": {}, "services": [{"id": "web"}], "mode": "ranked"}))
    ranked_v3 = boxes / "static-pine"
    ranked_v3.mkdir()
    (ranked_v3 / "engine_record-r3.json").write_text(json.dumps(
        {"rubric": {"scenario_name": "Static Pine R3", "scenario_version": 1},
         "adversary": {"events": []}, "services": [], "mode": "ranked"}))
    honor = boxes / "chocolate-factory"
    honor.mkdir()
    (honor / "engine_record.json").write_text(json.dumps(
        {"rubric": {"scenario_name": "Chocolate Factory", "scenario_version": 1},
         "adversary": {}, "services": [], "mode": "honor"}))
    junk = boxes / "broken-box"
    junk.mkdir()
    (junk / "engine_record.json").write_text("{not json")

    monkeypatch.setenv("HUITZILOPOCHTLI_BOXES_DIR", str(boxes))
    listed = scenario.list_box_scenarios()
    assert [("Ranked Demo", 2), ("Static Pine R3", 1)] == [(n, v) for n, v, _ in listed]
    record = scenario.load_box_scenario("Ranked Demo", 2)
    assert record[0]["scenario_name"] == "Ranked Demo"
    assert record[2] == [{"id": "web"}]
    assert scenario.load_box_scenario("Chocolate Factory", 1) is None
    assert scenario.load_box_scenario("Nope", 9) is None


def test_box_scanner_empty_dir(tmp_path, monkeypatch):
    from engine import scenario
    monkeypatch.setenv("HUITZILOPOCHTLI_BOXES_DIR", str(tmp_path))
    assert scenario.list_box_scenarios() == []
    monkeypatch.setenv("HUITZILOPOCHTLI_BOXES_DIR", str(tmp_path / "missing"))
    assert scenario.list_box_scenarios() == []


def test_comp_row_tag_layout():
    out = web._comp_cards([_comp(status="ended")])
    # Title and status dot share one line; meta sits under, actions right.
    assert ('<div class="comp-title-line"><h2><a href="/c/demo">'
            in out)


def test_mobile_header_wraps_instead_of_overflowing():
    # At 375px the brand + nav + theme toggle used to push the document 14px
    # wide; the header wraps instead.
    assert "@media(max-width:720px)" in web.CSS
    assert ".top .wrap{flex-wrap:wrap" in web.CSS


def test_layout_declares_an_inline_favicon():
    # No /favicon.ico 404 noise in the console.
    page = web.layout("T", "<p>x</p>")
    assert '<link rel="icon" href="data:image/svg+xml,' in page
