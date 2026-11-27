"""v1.2 teams: a player seat is a team with a shareable link + named roster.

The engine never learned a "team" entity on purpose -- a seat is one clock,
one box, one slot. These tests pin that a *team* is exactly the seat plus a
named roster (members self-register through the link, deduped on the
normalized handle, capped by the competition's max_team_members) and a link
token, and that the seat's identity (cookie, clock, box binding) is
untouched by any of it.
"""
import time

import pytest

from engine import competition
from engine import scenario as scenario_mod
from engine.store import Store
from common.schema import SCHEMA_VERSION


def _rubric():
    return {
        "schema_version": SCHEMA_VERSION,
        "scenario_name": "TestTeam",
        "scenario_version": 1,
        "entries": [{"check_id": "banner", "category": "vuln",
                     "matcher": {"tag": "equals", "value": "ok"}, "points": 10,
                     "sla": None}],
    }


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _rubric(), {}, [])
    return s


@pytest.fixture()
def comp(store):
    c = competition.create_competition(
        store, slug="team-comp", name="Team Comp", scenario_name="TestTeam",
        scenario_version=1, max_players=4, duration_s=3600)
    store.start_competition(c.id)
    return store.get_competition(c.id)


SECRET = b"server-secret"


def _seat(store, comp, name="Alpha"):
    player, code, err = competition.create_player_with_code(
        store, comp, name, SECRET)
    assert err is None, err
    return store.get_player(player.player_id), code


def test_join_mints_a_team_link(store, comp):
    player, _code = _seat(store, comp)
    assert player.team_token_plain and player.team_token_hash
    # The link resolves to exactly this seat.
    resolved = store.get_player_by_team_token(
        competition.hash_team_token(SECRET, player.team_token_plain))
    assert resolved.player_id == player.player_id


def test_team_token_is_not_a_join_code_hash(store, comp):
    # Domain separation: the same secret must not let a join-code hash double
    # as a team-token hash (they share no code space).
    player, code = _seat(store, comp)
    assert store.get_player_by_team_token(
        competition.hash_join_code(SECRET, code)) is None


def test_rotate_invalidates_the_old_link(store, comp):
    player, _ = _seat(store, comp)
    old = player.team_token_plain
    new = competition.rotate_team_token(store, player, SECRET)
    assert new and new != old
    assert store.get_player_by_team_token(
        competition.hash_team_token(SECRET, old)) is None
    assert store.get_player_by_team_token(
        competition.hash_team_token(SECRET, new)).player_id == player.player_id


def test_two_teams_have_distinct_links(store, comp):
    a, _ = _seat(store, comp, "Alpha")
    b, _ = _seat(store, comp, "Bravo")
    assert a.team_token_plain != b.team_token_plain
    assert (store.get_player_by_team_token(
        competition.hash_team_token(SECRET, b.team_token_plain)).player_id
        == b.player_id)


def test_roster_membership_adds_removes_and_counts(store, comp):
    player, _ = _seat(store, comp)
    assert store.add_team_member(player.player_id, "anne") is True
    # handle is unique per seat, case-insensitively (self-serve joins must
    # not turn one person into two members via casing) -- re-adding the
    # same one in any spelling is a no-op.
    assert store.add_team_member(player.player_id, "anne") is False
    assert store.add_team_member(player.player_id, "ANNE") is False
    store.add_team_member(player.player_id, "bob")
    handles = [h for h, _ in store.list_team_members(player.player_id)]
    assert handles == ["anne", "bob"]
    assert store.count_team_members(comp.id) == {player.player_id: 2}
    assert {pid: [h for h, _ in members] for pid, members in
            store.team_members_by_competition(comp.id).items()} == {
        player.player_id: ["anne", "bob"]}
    assert store.remove_team_member(player.player_id, "anne") is True
    # Removal is by normalized handle: any casing finds the member.
    assert store.remove_team_member(player.player_id, "BOB") is True
    assert store.remove_team_member(player.player_id, "nobody") is False
    assert [h for h, _ in store.list_team_members(player.player_id)] == []


def test_member_handle_validation():
    assert competition.validate_member_handle("  Anne D  ") == "Anne D"
    assert competition.validate_member_handle("   ") is None
    assert competition.validate_member_handle("") is None
    assert competition.validate_member_handle("x" * 61) is None


def test_member_cap_and_helper(store, tmp_path):
    comp = competition.create_competition(
        store, slug="capped", name="Capped", scenario_name="TestTeam",
        scenario_version=1, max_players=4, duration_s=3600,
        max_team_members=2)
    store.start_competition(comp.id)
    comp = store.get_competition(comp.id)
    player, _ = _seat(store, comp)
    assert competition.team_roster_full(store, comp, player) is False
    store.add_team_member(player.player_id, "anne")
    store.add_team_member(player.player_id, "bob")
    assert competition.team_roster_full(store, comp, player) is True
    # A seat without members is never full, whatever the cap arithmetic.
    other, _ = _seat(store, comp, "Bravo")
    assert competition.team_roster_full(store, comp, other) is False


def test_competition_member_cap_defaults_and_validation(store):
    # The default cap needs no argument and lands on the record.
    comp = competition.create_competition(
        store, slug="default-cap", name="D", scenario_name="TestTeam",
        scenario_version=1, max_players=2, duration_s=3600)
    assert comp.max_team_members == 10
    with pytest.raises(ValueError):
        competition.create_competition(
            store, slug="bad-cap", name="B", scenario_name="TestTeam",
            scenario_version=1, max_players=2, duration_s=3600,
            max_team_members=0)


def test_team_does_not_touch_the_seat_lifecycle(store, comp):
    # A team link is orthogonal to the clock/box binding: minting one must not
    # start a clock, bind a box, or change status.
    player, _ = _seat(store, comp)
    before = dataclass_snapshot(player)
    after = dataclass_snapshot(store.get_player(player.player_id))
    # The only fields the team work is allowed to add are the token pair;
    # everything that governs the run stays as the join left it.
    for field in ("status", "box_id", "started_at", "ends_at", "finished_at",
                  "competition_id", "display_name"):
        assert before[field] == after[field]


def dataclass_snapshot(p):
    return {f.name: getattr(p, f.name) for f in p.__dataclass_fields__.values()}
