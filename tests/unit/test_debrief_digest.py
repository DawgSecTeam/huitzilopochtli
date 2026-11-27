"""Digest-layer tests: the facts a debrief is allowed to state."""

from __future__ import annotations

import pytest

from debrief import digest as digest_mod
from tests.helpers import make_db


@pytest.fixture()
def db_path(tmp_path):
    return make_db(tmp_path)


def test_competition_loaded(tmp_path):
    """The digest carries the competition's own identity, once per team."""
    d = digest_mod.build_digest(make_db(tmp_path))
    assert d[0]["competition"]["name"] == "Spring Range 2025"
    assert d[0]["competition"]["scenario_name"] == "Broadneck Post"


def test_teams_ranked_by_total(tmp_path):
    d = digest_mod.build_digest(make_db(tmp_path))
    assert len(d) == 3
    totals = [t["team"]["score"]["total"] for t in d]
    assert totals == sorted(totals, reverse=True)


def test_incidents_have_shape(tmp_path):
    d = digest_mod.build_digest(make_db(tmp_path))
    for team in d:
        for inc in team["team"]["incidents"]:
            assert "event_id" in inc
            assert isinstance(inc["restored"], bool)


def test_feedback_pool_present(tmp_path):
    d = digest_mod.build_digest(make_db(tmp_path))
    for team in d:
        assert isinstance(team["feedback_pool"], list)


def test_members_in_team_facts(tmp_path):
    """The named roster rides the team facts: the handles a seat registered
    through its team link, oldest first; [] for a seat that never did."""
    d = digest_mod.build_digest(make_db(tmp_path))
    by_name = {t["team"]["display_name"]: t["team"]["members"] for t in d}
    assert by_name["rosemoor-1"] == ["Grace H.", "anne d"]
    assert by_name["rosemoor-2"] == []
    assert by_name["harborline-1"] == []
