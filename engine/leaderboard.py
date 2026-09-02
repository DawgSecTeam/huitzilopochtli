"""GET /leaderboard aggregation. See architecture.md §11.4."""
from engine.store import Store


def get_leaderboard(store: Store, scenario_name: str) -> list:
    """Returns store.get_scores(scenario_name) as JSON-serializable dicts,
    ranked descending by total."""
    rows = store.get_scores(scenario_name)
    return [
        {
            "rank": idx + 1,
            "scenario_name": row.scenario_name,
            "total": row.total,
            "updated_at": row.updated_at,
        }
        for idx, row in enumerate(rows)
    ]
