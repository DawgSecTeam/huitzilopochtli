"""Engine-side adversary scheduler. See architecture.md §12.1.

PHASE 1 TASK: implement. Depends only on engine.store.Store's signature.
"""
from common.schema import Directive
from engine.store import Store


def due_directives(store: Store, box_id: str, server_secret: bytes,
                    event_pool: list, t0: float, received_at: float) -> list:
    """Derive a deterministic RNG from (server_secret, box_id); for each event
    in event_pool pick (once, reproducibly) a concrete fire_time within its
    window_s, anchored to t0. For any event whose fire_time <= received_at and
    whose event_id is not already in store.get_issued_event_ids(box_id):
    log it via store.log_adversary_event and include it in the returned
    list[Directive]. Already-issued events are never re-issued.
    """
    raise NotImplementedError
