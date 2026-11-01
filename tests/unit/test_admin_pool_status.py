"""Admin competition page: join-URL copy and the live pre-deploy counter.

The main web-page suite pins the rest of the admin comp page; these cover the
portal-snapshot counter and the full-URL copy, which read data the page
handler passes in (claims.live_pool_status, the server's public base).
"""
import time

from engine.store import CompetitionRecord
from engine import web


def _comp(**over):
    now = time.time()
    base = dict(id="c1", slug="demo", name="Demo Cup", scenario_name="demo",
                scenario_version=1, status="draft", join_open=True,
                max_players=32, duration_s=7200, workshop_pool_code=None,
                theme_json=None, join_instructions=None, created_at=now,
                started_at=now, ended_at=None)
    base.update(over)
    return CompetitionRecord(**base)


def test_join_url_copy_carries_the_whole_url():
    # The code box and the copy button carry the full player-facing URL;
    # without a public base the path is all that is known.
    page = web.admin_competition_page(_comp(), {"leaderboard": []}, [], "csrf",
                                      public_base="http://10.0.0.160:8080")
    assert 'data-copy="http://10.0.0.160:8080/c/demo/join"' in page
    assert "<code>http://10.0.0.160:8080/c/demo/join</code>" in page
    plain = web.admin_competition_page(_comp(), {"leaderboard": []}, [], "csrf")
    assert 'data-copy="/c/demo/join"' in plain


def test_pre_deploy_card_shows_the_live_box_count():
    page = web.admin_competition_page(_comp(workshop_pool_code="ABCD12"),
                                      {"leaderboard": []}, [], "csrf",
                                      pool={"status": "ok", "available": 4,
                                            "total": 12})
    assert "4 of 12 boxes ready to claim" in page
    assert 'id="warm" data-poll="10000"' in page
    unpinned = web.admin_competition_page(_comp(), {"leaderboard": []}, [],
                                          "csrf", pool={"status": "unpinned"})
    assert "No boxes pre-deployed yet." in unpinned
    down = web.admin_competition_page(_comp(workshop_pool_code="ABCD12"),
                                      {"leaderboard": []}, [], "csrf",
                                      pool={"status": "unavailable"})
    assert "Pool count unavailable right now." in down


def test_export_csv_waits_for_a_run():
    draft = web.admin_competition_page(_comp(status="draft"),
                                       {"leaderboard": []}, [], "csrf")
    assert "Export CSV" not in draft
    live = web.admin_competition_page(_comp(status="live"),
                                      {"leaderboard": []}, [], "csrf")
    assert "export.csv" in live


def test_pre_deploy_card_warns_and_disables_when_there_is_nothing_to_clone():
    reason = ("No pool to pre-deploy from: the scenario 'demo' carries no "
              "pool block")
    page = web.admin_competition_page(_comp(), {"leaderboard": []}, [], "csrf",
                                      pool={"status": "unpinned"},
                                      predeploy_warn=reason)
    assert 'class="warnmsg"' in page
    # The button is off, and the tooltip carries the same reason.
    assert '<button class="btn" type="submit" disabled title=' in page
    # It replaces the idle notes instead of stacking a third message on them.
    assert "Nothing pre-deployed yet" not in page
    assert "No boxes pre-deployed yet." not in page


def test_pre_deploy_card_does_not_block_a_live_pool():
    page = web.admin_competition_page(
        _comp(workshop_pool_code="ABCD12"), {"leaderboard": []}, [], "csrf",
        pool={"status": "ok", "available": 4, "total": 12})
    assert "4 of 12 boxes ready to claim" in page
    assert 'type="submit" disabled' not in page
    assert 'class="warnmsg"' not in page
    # A pool that already holds boxes is not described as "nothing yet".
    assert "Nothing pre-deployed yet" not in page


def test_pre_deploy_card_distinguishes_a_stale_pool_from_an_empty_one():
    # A pin the portal lost is a notice, not an error: the next warm/join
    # clones a fresh pool from the scenario template, so the button stays live.
    stale = web.admin_competition_page(
        _comp(workshop_pool_code="GONE1"), {"leaderboard": []}, [], "csrf",
        pool={"status": "unpinned"})
    assert 'class="warnmsg"' in stale
    assert "gone from the portal" in stale
    assert 'type="submit" disabled' not in stale
    assert "Nothing pre-deployed yet" not in stale
    # Never pre-deployed is the ordinary state and stays quiet.
    empty = web.admin_competition_page(_comp(), {"leaderboard": []}, [],
                                       "csrf", pool={"status": "unpinned"})
    assert "No boxes pre-deployed yet." in empty
    assert 'class="warnmsg"' not in empty


def test_dashboard_flags_a_competition_with_no_pool_to_pre_deploy_from():
    flagged = web.admin_dashboard_page(
        [_comp(status="draft")], {"c1": 0}, "csrf",
        pool_warn={"c1": "No pool to pre-deploy from"})
    assert 'class="fullflag">No pool to pre-deploy from</div>' in flagged
    clean = web.admin_dashboard_page([_comp(status="draft")], {"c1": 0}, "csrf")
    assert "No pool to pre-deploy from" not in clean
