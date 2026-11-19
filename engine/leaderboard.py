"""GET /leaderboard aggregation. See architecture.md §11.4.

The original endpoint is scenario-wide: it was written for honor boxes, which
have no competition. With several competitions live at once, a scenario-wide
board would mix them, so a competition can be selected explicitly (and an
ambiguous scenario is refused rather than silently merged).
"""
from engine import competition as competition_mod
from engine.store import Store


def get_leaderboard(store: Store, scenario_name: str) -> list:
    """Returns store.get_scores(scenario_name) as JSON-serializable dicts,
    ranked descending by total."""
    rows = store.get_scores(scenario_name)
    return [
        {
            "rank": idx + 1,
            "box_id": row.box_id,
            "scenario_name": row.scenario_name,
            "total": row.total,
            "updated_at": row.updated_at,
        }
        for idx, row in enumerate(rows)
    ]


def competitions_for_scenario(store: Store, scenario_name: str) -> list:
    """Competitions that can own a board for this scenario (live or ended).

    Drafts have no players, so they never make a scenario-wide board
    ambiguous.
    """
    return [c for c in store.list_competitions()
            if c.scenario_name == scenario_name and c.status in ("live", "ended")]


def get_competition_leaderboard(store: Store, comp) -> list:
    """A competition's board in the legacy ``/leaderboard`` row shape.

    Equal totals share a rank, matching the competition pages (standard
    competition ranking: 1, 2, 2, 4).
    """
    board = competition_mod.leaderboard_payload(store, comp)["leaderboard"]
    by_player = {p.player_id: p for p in store.list_players(comp.id)}
    rows = []
    for row in board:
        player = by_player.get(row["player_id"])
        rows.append({
            "rank": row["rank"],
            "player_id": row["player_id"],
            "player_name": row["name"],
            "box_id": player.box_id if player is not None else None,
            "scenario_name": comp.scenario_name,
            "competition_id": comp.id,
            "competition_slug": comp.slug,
            "total": row["total"],
            "hardening_points": row["hardening_points"],
            "service_points": row["service_points"],
            "forensics_points": row["forensics_points"],
            "updated_at": row["last_checkin"],
            "status": row["status"],
        })
    return rows
