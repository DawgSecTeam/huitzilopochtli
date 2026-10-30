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
