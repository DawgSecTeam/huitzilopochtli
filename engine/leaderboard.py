"""GET /leaderboard aggregation. See architecture.md §11.4.

PHASE 1 TASK: implement. Depends only on engine.store.Store's signature.
"""
from engine.store import Store


def get_leaderboard(store: Store, scenario_name: str) -> list:
    """Returns store.get_scores(scenario_name) as JSON-serializable dicts,
    ranked descending by total."""
    raise NotImplementedError
