"""Engine-side adversary scheduler. See architecture.md §12.1."""
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
    # CAUTION: fire times are *derived*, not stored. Rotating
    # HUITZILOPOCHTLI_SERVER_SECRET silently re-schedules every box's events
    # while adversary_log (already-issued ids) persists, so some events may
    # fire immediately on the next check-in or never. Rotate the secret only
    # when wiping the store.
    # CAUTION: fire times are *derived*, not stored. Rotating
    # HUITZILOPOCHTLI_SERVER_SECRET silently re-schedules every box's events
    # while adversary_log (already-issued ids) persists, so some events may
    # fire immediately on the next check-in or never. Rotate the secret only
    # when wiping the store.

    issued = store.get_issued_event_ids(box_id)
    directives = []

    for index, event in enumerate(event_pool):
        if not isinstance(event, dict):
            continue

        event_id = str(event.get("id", f"e{index}"))

        window_s = event.get("window_s")
        if (not isinstance(window_s, (list, tuple)) or len(window_s) != 2
                or not all(isinstance(b, (int, float)) and not isinstance(b, bool)
                            for b in window_s)
                or window_s[0] > window_s[1]):
            continue
        action = event.get("action")
        if not isinstance(action, str) or not action:
            continue

        offset = rng.uniform(window_s[0], window_s[1])
        fire_time = t0 + offset

        if event_id in issued:
            continue
        if received_at >= fire_time:
            params = event.get("params", {})
            if store.log_adversary_event(box_id, event_id, action, received_at, params):
                directives.append(
                    Directive(event_id=event_id, action=action, params=params)
                )

    return directives
