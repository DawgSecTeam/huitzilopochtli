"""Tests for engine.adversary_oracle.due_directives.

Covers: deterministic per-(server_secret, box_id) scheduling, correct
withholding of not-yet-due events, no re-issuance of already-fired events,
per-box schedule independence, and stable/distinct event_ids derived from
event_pool position.
"""
import hashlib
import os
import random
import tempfile

import pytest

from engine.adversary_oracle import due_directives
from engine.store import Store


def _expected_fire_time(server_secret: bytes, box_id: str, event_pool: list,
                         t0: float, index: int) -> float:
    """Replicates the internal RNG derivation in adversary_oracle.due_directives
    so tests can compute, ahead of time, the exact fire_time a given event in
    the pool will be assigned -- without needing to binary search for it.
    """
    seed_material = server_secret + box_id.encode()
    seed = int.from_bytes(hashlib.sha256(seed_material).digest(), "big")
    rng = random.Random(seed)
    fire_time = None
    for i, event in enumerate(event_pool):
        window_s = event["window_s"]
        offset = rng.uniform(window_s[0], window_s[1])
        if i == index:
            fire_time = t0 + offset
    return fire_time


@pytest.fixture
def make_store(tmp_path):
    """Factory fixture: each call returns a fresh Store backed by its own
    temp sqlite file."""
    counter = {"n": 0}

    def _make():
        counter["n"] += 1
        db_path = str(tmp_path / f"store_{counter['n']}.db")
        return Store(db_path)

    return _make


SECRET = b"super-secret-server-key"
T0 = 1_000_000.0
POOL = [
    {"action": "rotate_creds", "window_s": (100, 200), "params": {"foo": "bar"}},
]


def test_determinism_same_event_fires_at_same_threshold_across_stores(make_store):
    """The same server_secret + box_id + event_pool must derive the exact
    same fire_time in two entirely separate Store instances (separate temp
    DBs). We confirm this by checking the event is withheld at fire_time - 1
    and fires at fire_time, identically in both stores.
    """
    box_id = "box-alpha"
    fire_time = _expected_fire_time(SECRET, box_id, POOL, T0, index=0)

    for _ in range(2):
        store = make_store()

        # Not yet due.
        directives = due_directives(store, box_id, SECRET, POOL, T0,
                                     received_at=fire_time - 1)
        assert directives == []
        assert store.get_issued_event_ids(box_id) == set()

        # Due now.
        directives = due_directives(store, box_id, SECRET, POOL, T0,
                                     received_at=fire_time)
        assert len(directives) == 1
        assert directives[0].event_id == "e0"
        assert directives[0].action == "rotate_creds"
        assert store.get_issued_event_ids(box_id) == {"e0"}


def test_future_event_is_withheld_and_not_logged(make_store):
    """An event whose derived fire_time is after received_at must not be
    returned, and must not be recorded as issued."""
    store = make_store()
    box_id = "box-beta"
    fire_time = _expected_fire_time(SECRET, box_id, POOL, T0, index=0)
    assert fire_time > T0  # window_s starts at 100, so always in the future of t0

    directives = due_directives(store, box_id, SECRET, POOL, T0,
                                 received_at=T0)
    assert directives == []
    assert store.get_issued_event_ids(box_id) == set()


def test_fired_event_is_not_reissued_later(make_store):
    """Once an event has fired (returned + logged), a later call -- even much
    later -- must not return it again, though get_issued_event_ids must still
    report it as issued."""
    store = make_store()
    box_id = "box-gamma"
    fire_time = _expected_fire_time(SECRET, box_id, POOL, T0, index=0)

    first = due_directives(store, box_id, SECRET, POOL, T0,
                            received_at=fire_time)
    assert len(first) == 1
    assert store.get_issued_event_ids(box_id) == {"e0"}

    much_later = fire_time + 10_000_000
    second = due_directives(store, box_id, SECRET, POOL, T0,
                             received_at=much_later)
    assert second == []
    # Still recorded as issued -- not forgotten.
    assert store.get_issued_event_ids(box_id) == {"e0"}


def test_schedule_is_per_box_not_global(make_store):
    """Different box_id values against the same server_secret + event_pool
    must be able to derive different fire times -- i.e. the RNG seed
    incorporates box_id, so the schedule is per-box."""
    wide_pool = [
        {"action": "noisy_scan", "window_s": (0, 1_000_000), "params": {}},
    ]
    fire_a = _expected_fire_time(SECRET, "box-one", wide_pool, T0, index=0)
    fire_b = _expected_fire_time(SECRET, "box-two", wide_pool, T0, index=0)

    assert fire_a != fire_b

    # Cross-check against the real due_directives behavior: box-one should
    # be due at fire_a but box-two (fresh store) should not yet be due at
    # that same received_at, since its own derived fire time differs.
    store_a = make_store()
    store_b = make_store()

    directives_a = due_directives(store_a, "box-one", SECRET, wide_pool, T0,
                                   received_at=fire_a)
    assert len(directives_a) == 1

    later_of_the_two_only_a = min(fire_a, fire_b) if fire_a != fire_b else fire_a
    # Use whichever timestamp is strictly before box-two's own fire time to
    # prove box-two's schedule doesn't fire in lockstep with box-one's.
    if fire_a < fire_b:
        directives_b = due_directives(store_b, "box-two", SECRET, wide_pool, T0,
                                       received_at=fire_a)
        assert directives_b == []


def test_event_ids_are_stable_and_distinct_across_pool(make_store):
    """Each event in event_pool gets a stable, distinct event_id derived from
    its position (e0, e1, e2, ...), so re-running against the same pool
    doesn't collide ids across different events."""
    store = make_store()
    box_id = "box-delta"
    pool = [
        {"action": "action_zero", "window_s": (1, 2), "params": {}},
        {"action": "action_one", "window_s": (1, 2), "params": {}},
        {"action": "action_two", "window_s": (1, 2), "params": {}},
    ]
    # received_at far beyond t0 + max possible offset so all three fire.
    directives = due_directives(store, box_id, SECRET, pool, T0,
                                 received_at=T0 + 1000)

    assert len(directives) == 3
    ids = {d.event_id for d in directives}
    assert ids == {"e0", "e1", "e2"}
    actions_by_id = {d.event_id: d.action for d in directives}
    assert actions_by_id["e0"] == "action_zero"
    assert actions_by_id["e1"] == "action_one"
    assert actions_by_id["e2"] == "action_two"

    assert store.get_issued_event_ids(box_id) == {"e0", "e1", "e2"}

    # Re-running against the same pool/box must not re-issue or collide ids.
    directives_again = due_directives(store, box_id, SECRET, pool, T0,
                                       received_at=T0 + 2000)
    assert directives_again == []
    assert store.get_issued_event_ids(box_id) == {"e0", "e1", "e2"}
