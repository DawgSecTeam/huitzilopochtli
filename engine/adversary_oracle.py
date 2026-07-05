"""Engine-side adversary scheduler. See architecture.md §12.1.

PHASE 1 TASK: implement. Depends only on engine.store.Store's signature.
"""
import hashlib
import random

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
    seed_material = server_secret + box_id.encode()
    seed = int.from_bytes(hashlib.sha256(seed_material).digest(), "big")
    rng = random.Random(seed)

    issued = store.get_issued_event_ids(box_id)
    directives = []

    for index, event in enumerate(event_pool):
        event_id = f"e{index}"
        window_s = event["window_s"]
        offset = rng.uniform(window_s[0], window_s[1])
        fire_time = t0 + offset

        if event_id in issued:
            continue
        if received_at >= fire_time:
            action = event["action"]
            params = event.get("params", {})
            store.log_adversary_event(box_id, event_id, action, received_at, params)
            directives.append(Directive(event_id=event_id, action=action, params=params))

    return directives
