"""POST /checkin handler logic. See architecture.md §14.2."""
import base64
import dataclasses
import json
import sqlite3
import time

import engine.sla as sla
import engine.adversary_oracle as adversary_oracle
from common import canon
from common.crypto import signing
from common.evaluator import evaluate
from common.matchers import evaluate_matcher
from common.schema import (
    Bundle, CheckinResponse, CollectorStatus, Rubric, SCHEMA_VERSION, SlaStatus,
)
from common.version import AGENT_VERSION
from engine.store import Store


class CheckinError(Exception):
    """Raised by handle_checkin() on any fail-closed verification step.

    The HTTP layer is expected to catch this and map status_code/message
    (and last_seq, when present) onto the wire response.
    """

    def __init__(self, status_code, message, last_seq=None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.last_seq = last_seq


def _agent_version_compatible(agent_version: str) -> bool:
    """§14.3: the bundle's major agent version must match the engine's;
    minor/patch drift is tolerated."""
    if not isinstance(agent_version, str) or not agent_version:
        return False
    try:
        return agent_version.split(".")[0] == AGENT_VERSION.split(".")[0]
    except Exception:
        return False


def _agent_version_compatible(agent_version: str) -> bool:
    """§14.3: the bundle's major agent version must match the engine's;
    minor/patch drift is tolerated."""
    if not isinstance(agent_version, str) or not agent_version:
        return False
    try:
        return agent_version.split(".")[0] == AGENT_VERSION.split(".")[0]
    except Exception:
        return False


class _Clock:
    """Trivial Clock (see common.evaluator.Clock protocol) fixed to the
    engine's authoritative received_at for this check-in."""

    def __init__(self, received_at: float):
        self._received_at = received_at

    def now(self) -> float:
        return self._received_at


def handle_checkin(store: Store, bundle: Bundle, sig: bytes, rubric: Rubric,
                    server_secret: bytes, event_pool: list) -> CheckinResponse:
    """Fail-closed handler order (§14.2):
      1. Look up box_id -> public key. Unknown box -> 403.
      2. Verify signature over the canonical body. Bad signature -> 403.
      3. Reject seq <= last_seq (replay/dedup) -> 409 with last_seq.
      4. Stamp received_at = engine_now(). First check-in for this box sets T0.
      5. Persist the check-in (audit log) via store.save_checkin.
      6. Evaluate point-in-time evidence against the engine-held rubric
         (common.evaluator.evaluate).
      7. Update SLA ledger (engine.sla).
      8. Run adversary scheduler; collect any due directives (engine.adversary_oracle).
      9. Update scores.total (store.upsert_score); return the CheckinResponse.
    """
    # 1. Look up box_id -> public key. Unknown box -> 403.
    box = store.get_box(bundle.box_id)
    if box is None:
        raise CheckinError(403, "unknown box")

    # Protocol-version checks (§14.3) come before signature verification:
    # they are cheap and leak no enrollment information, and rejecting an
    # incompatible wire format before parsing/signature work is fail-closed.
    if bundle.schema_version != SCHEMA_VERSION:
        raise CheckinError(
            400,
            f"incompatible bundle schema_version {bundle.schema_version!r} "
            f"(engine supports {SCHEMA_VERSION!r})",
        )
    if not _agent_version_compatible(bundle.agent_version):
        raise CheckinError(
            400,
            f"incompatible agent_version {bundle.agent_version!r} "
            f"(engine expects major version {AGENT_VERSION.split('.')[0]})",
        )

    # Protocol-version checks (§14.3) come before signature verification:
    # they are cheap and leak no enrollment information, and rejecting an
    # incompatible wire format before parsing/signature work is fail-closed.
    if bundle.schema_version != SCHEMA_VERSION:
        raise CheckinError(
            400,
            f"incompatible bundle schema_version {bundle.schema_version!r} "
            f"(engine supports {SCHEMA_VERSION!r})",
        )
    if not _agent_version_compatible(bundle.agent_version):
        raise CheckinError(
            400,
            f"incompatible agent_version {bundle.agent_version!r} "
            f"(engine expects major version {AGENT_VERSION.split('.')[0]})",
        )

    # Verify signature before scenario checks to avoid leaking enrollment info.
    canonical_bytes = canon.canonicalize(dataclasses.asdict(bundle))
    public_key = base64.b64decode(box.public_key)
    if not signing.verify(public_key, canonical_bytes, sig):
        raise CheckinError(403, "bad signature")

    if box.scenario_name != bundle.scenario_name:
        raise CheckinError(400, "scenario_name does not match the box's enrolled scenario")

    if box.scenario_version != bundle.scenario_version:
        raise CheckinError(409, "scenario_version does not match the box's enrolled version")

    # 3. Reject seq <= last_seq (replay/dedup) -> 409 with last_seq.
    if bundle.seq <= box.last_seq:
        raise CheckinError(409, "replay/stale seq", last_seq=box.last_seq)

    # 4. Stamp received_at = engine_now(). First check-in for this box sets T0.
    received_at = time.time()
    if box.t0 is None:
        store.set_t0_if_unset(bundle.box_id, received_at)
        t0_to_use = received_at
    else:
        t0_to_use = box.t0

    if not store.update_box_seq(bundle.box_id, bundle.seq, bundle.boot_id):
        fresh = store.get_box(bundle.box_id)
        last = fresh.last_seq if fresh is not None else box.last_seq
        raise CheckinError(409, "replay/stale seq", last_seq=last)

    try:
        store.save_checkin(
            bundle.box_id,
            bundle.seq,
            received_at,
            json.dumps(dataclasses.asdict(bundle), default=str),
        )
    except sqlite3.IntegrityError:
        fresh = store.get_box(bundle.box_id)
        last = fresh.last_seq if fresh is not None else box.last_seq
        raise CheckinError(409, "replay/stale seq", last_seq=last)

    # 6. Evaluate point-in-time evidence against the engine-held rubric.
    clock = _Clock(received_at)
    score = evaluate(bundle.evidence, rubric, clock)

    # 7. Update SLA ledger (§11.3) for every rubric entry that has SLA params.
    evidence_by_check_id = {e.check_id: e for e in bundle.evidence}
    sla_statuses = []
    sla_accrued_total = 0
    for entry in rubric.entries:
        if entry.sla is None:
            continue
        ev = evidence_by_check_id.get(entry.check_id)
        # Missing or failed SLA evidence counts as a DOWN observation: the
        # hysteresis counters must keep advancing (a box whose SLA collection
        # is broken cannot hold its prior UP state indefinitely).
        if ev is not None and ev.status == CollectorStatus.OK:
            is_up, _reason = evaluate_matcher(entry.matcher, ev.raw)
        else:
            is_up = False
        sla_rec = sla.update_sla(
            store, bundle.box_id, entry.check_id, entry.sla, is_up, received_at
        )
        sla_statuses.append(
            SlaStatus(
                check_id=sla_rec.check_id,
                state=sla_rec.state,
                accrued_points=sla_rec.accrued_points,
            )
        )
        sla_accrued_total += sla_rec.accrued_points
    score.sla_status = sla_statuses

    # 8. Run adversary scheduler; collect any due directives (§12.1).
    directives = adversary_oracle.due_directives(
        store, bundle.box_id, server_secret, event_pool, t0_to_use, received_at
    )

    final_total = score.total + sla_accrued_total
    score.total = final_total

    store.upsert_score(bundle.box_id, rubric.scenario_name, final_total)

    min_sla_interval = min(
        (entry.sla.interval_s for entry in rubric.entries if entry.sla is not None),
        default=60,
    )
    return CheckinResponse(
        server_time=received_at,
        score=score,
        directives=directives,
        next_checkin_s=min_sla_interval,
        last_seq=bundle.seq,
    )
