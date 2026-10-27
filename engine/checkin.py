"""POST /checkin handler logic. See architecture.md §14.2."""
import base64
import dataclasses
import json
import sqlite3
import time
from typing import Optional

import engine.sla as sla
import engine.adversary_oracle as adversary_oracle
import engine.competition as competition
from common import canon
from common.evaluator import evaluate
from common.matchers import evaluate_matcher
from common.schema import (
    Bundle, CheckinResponse, CollectorStatus, Directive, Rubric, SCHEMA_VERSION,
    SLA_HISTORY_MAX, ScoreBreakdown, SlaStatus,
)
from common.version import AGENT_VERSION
from engine import scenario as scenario_mod
from engine import verify_gate
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


def _redact_for_box(score, evidence_by_check_id: dict) -> None:
    """Replace each CheckResult.reason (built by common.matchers from the
    rubric's expected values) with the box's own evidence reason."""
    for result in score.results:
        ev = evidence_by_check_id.get(result.check_id)
        result.reason = ev.reason if ev is not None and ev.reason else ""


def _entry_matcher(rubric: Rubric, check_id: str) -> dict:
    for entry in rubric.entries:
        if entry.check_id == check_id:
            return entry.matcher
    return {"tag": "equals", "value": None}


class _Clock:
    """Trivial Clock (see common.evaluator.Clock protocol) fixed to the
    engine's authoritative received_at for this check-in."""

    def __init__(self, received_at: float):
        self._received_at = received_at

    def now(self) -> float:
        return self._received_at


def _stored_sla_status(data: dict) -> list:
    """Rehydrate the safe part of a stored score for a finished run.

    The stored score_json still contains matcher reasons (the answer key), so
    point-in-time results must not be replayed to the box. Service state,
    accrual and the tick history carry no expected values, and keeping them
    means the ranked report's uptime tab stays populated after the run ends.
    """
    out = []
    for entry in data.get("sla_status") or []:
        if not isinstance(entry, dict):
            continue
        check_id = entry.get("check_id")
        if not isinstance(check_id, str) or not check_id:
            continue
        try:
            accrued = int(entry.get("accrued_points", 0) or 0)
        except (TypeError, ValueError):
            accrued = 0
        history = [
            str(state).upper() for state in (entry.get("history") or [])
            if str(state).upper() in ("UP", "DOWN")
        ][-SLA_HISTORY_MAX:]
        out.append(SlaStatus(
            check_id=check_id,
            state=str(entry.get("state", "") or "").upper(),
            accrued_points=accrued,
            history=history,
        ))
    return out


def _frozen_score(store: Store, box_id: str, scenario_name: str,
                  scenario_version: int, received_at: float) -> ScoreBreakdown:
    """Return the last stored authoritative score, or a zero placeholder."""
    stored = store.get_score(box_id)
    if stored and stored.get("score_json"):
        try:
            data = json.loads(stored["score_json"])
            return ScoreBreakdown(
                scenario_name=data.get("scenario_name", scenario_name),
                scenario_version=data.get("scenario_version", scenario_version),
                total=int(data.get("total", stored["total"])),
                results=[], sla_status=_stored_sla_status(data),
                computed_at=float(data.get("computed_at", received_at)),
            )
        except (ValueError, TypeError, KeyError):
            pass
    return ScoreBreakdown(
        scenario_name=scenario_name, scenario_version=scenario_version,
        total=int(stored["total"]) if stored else 0,
        results=[], sla_status=[], computed_at=received_at,
    )


def handle_checkin(store: Store, bundle: Bundle, sig: bytes,
                    rubric: Optional[Rubric] = None,
                    server_secret: bytes = b"", event_pool: Optional[list] = None,
                    next_checkin_s: int = 60) -> CheckinResponse:
    """Fail-closed handler order (§14.2):
      1. Look up box_id -> public key. Unknown box -> 403.
      2. Reject an incompatible schema_version / agent major version -> 400,
         then verify the signature over the canonical body -> 403, then
         check scenario_name (400) and scenario_version (409 with last_seq).
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

    # Verify signature before scenario checks to avoid leaking enrollment info.
    canonical_bytes = canon.canonicalize(dataclasses.asdict(bundle))
    public_key = base64.b64decode(box.public_key)
    verified = verify_gate.verify(public_key, canonical_bytes, sig)
    if verified is None:
        raise CheckinError(503, "engine busy verifying signatures; retry")
    if not verified:
        raise CheckinError(403, "bad signature")

    if box.scenario_name != bundle.scenario_name:
        raise CheckinError(400, "scenario_name does not match the box's enrolled scenario")

    if box.scenario_version != bundle.scenario_version:
        # §14.2: every 409 carries the authoritative last_seq.
        raise CheckinError(409, "scenario_version does not match the box's enrolled version",
                           last_seq=box.last_seq)

    # Ranked competition state (additive; legacy boxes have no player row and
    # keep the pre-competition behavior).
    player = store.get_player_by_box(bundle.box_id)
    comp = store.get_competition(player.competition_id) if player else None
    now_for_run = time.time()
    finished = False
    run_status = "running"
    run_ends_at = player.ends_at if player is not None else None
    if player is not None:
        if player.status in ("disqualified", "removed"):
            finished, run_status = True, "disqualified"
        elif comp is not None and comp.status == "ended":
            finished, run_status = True, "ended"
        elif player.status == "finished":
            finished, run_status = True, "finished"
        elif player.ends_at is not None and now_for_run >= player.ends_at:
            finished, run_status = True, "finished"
        elif comp is not None and comp.status != "live":
            finished, run_status = True, "ended"

    # Load the rubric only after signature verification: an unauthenticated
    # caller must not learn whether a scenario exists or force a JSON parse of
    # the stored record. The record is keyed by the *enrolled* version, so a
    # v2 upload cannot silently rescore a v1 box.
    if rubric is None:
        try:
            rubric, event_pool = scenario_mod.load_scenario(
                store, box.scenario_name, box.scenario_version)
        except scenario_mod.ScenarioNotFound:
            raise CheckinError(
                409,
                f"no engine record for scenario {box.scenario_name!r} "
                f"version {box.scenario_version}",
                last_seq=box.last_seq,
            )
        except scenario_mod.ScenarioError:
            raise CheckinError(
                500, "stored scenario record is invalid", last_seq=box.last_seq
            )
    if event_pool is None:
        event_pool = []

    # 3. Reject seq <= last_seq (replay/dedup) -> 409 with last_seq.
    if bundle.seq <= box.last_seq:
        raise CheckinError(409, "replay/stale seq", last_seq=box.last_seq)

    if finished:
        # Accept the bundle so the agent's seq stays contiguous, but do not
        # score it: the run is over. The agent stops on the returned status.
        if (player is not None and run_status == "finished"
                and player.status == "running"):
            store.update_player(player.player_id, status="finished",
                                finished_at=now_for_run)
        with store.atomic():
            if not store.update_box_seq(bundle.box_id, bundle.seq, bundle.boot_id):
                fresh = store.get_box(bundle.box_id)
                last = fresh.last_seq if fresh is not None else box.last_seq
                raise CheckinError(409, "replay/stale seq", last_seq=last)
            store.save_checkin(
                bundle.box_id, bundle.seq, now_for_run,
                json.dumps(dataclasses.asdict(bundle), default=str),
            )
        frozen = _frozen_score(store, bundle.box_id, box.scenario_name,
                               box.scenario_version, now_for_run)
        rank, rank_total = competition.rank_for_player(
            store, comp, player, now_for_run)
        return CheckinResponse(
            server_time=now_for_run,
            score=frozen,
            directives=[],
            next_checkin_s=max(1, int(next_checkin_s)),
            last_seq=bundle.seq,
            issued_directives=[],
            run_status=run_status,
            run_ends_at=run_ends_at,
            player_name=player.display_name if player is not None else None,
            competition_name=comp.name if comp is not None else None,
            rank=rank,
            rank_total=rank_total,
        )

    # Steps 4-9 are one transaction (§14.2): a failure part-way (e.g. a
    # malformed stored matcher) rolls back the seq advance, audit row, SLA
    # ledger and adversary log together, so the agent's retry of this same
    # bundle is scored instead of 409-rejected as a replay.
    with store.atomic():
        # 4. Stamp received_at = engine_now(). First check-in for this box sets T0.
        received_at = time.time()
        if player is not None and player.started_at is not None:
            t0_to_use = player.started_at
            store.set_t0_if_unset(bundle.box_id, t0_to_use)
        else:
            t0_to_use = store.get_or_set_t0(bundle.box_id, received_at)

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
        evidence_by_check_id = {e.check_id: e for e in bundle.evidence}

        # 7. Run the adversary scheduler before the SLA ledger so a directive
        # issued by *this* check-in can dock the mapped SLA immediately (§12.1).
        directives = adversary_oracle.due_directives(
            store, bundle.box_id, server_secret, event_pool, t0_to_use, received_at
        )

        # The engine caused the disruption, so it knows the outage floor: from
        # the check-in after issuance until the box reports the affected check
        # healthy again, force that SLA DOWN. Evidence collected by the same
        # check-in that receives a directive predates execution, so it cannot
        # count as restoration.
        sla_ids = {e.check_id for e in rubric.entries if e.sla is not None}
        forced_down = set()
        for effect in store.get_active_adversary_effects(bundle.box_id, received_at):
            check_id = effect["affects_check"]
            if check_id not in sla_ids:
                continue
            ev = evidence_by_check_id.get(check_id)
            currently_up = False
            if ev is not None and ev.status == CollectorStatus.OK:
                currently_up, _reason = evaluate_matcher(
                    _entry_matcher(rubric, check_id), ev.raw)
            if (currently_up
                    and float(effect["issued_at"] or 0) < received_at):
                store.mark_adversary_restored(
                    bundle.box_id, effect["event_id"], received_at)
            else:
                forced_down.add(check_id)

        # 8. Update SLA ledger (§11.3) for every rubric entry that has SLA params.
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
                store, bundle.box_id, entry.check_id, entry.sla, is_up,
                received_at, force_down=entry.check_id in forced_down,
            )
            sla_statuses.append(
                SlaStatus(
                    check_id=sla_rec.check_id,
                    state=sla_rec.state,
                    accrued_points=sla_rec.accrued_points,
                    history=list(sla_rec.history),
                )
            )
            sla_accrued_total += sla_rec.accrued_points
        score.sla_status = sla_statuses

        # At-least-once delivery: re-send everything issued so far (this
        # check-in's included), so a response lost after commit -- or dropped
        # by the agent while flushing its queue -- can't lose a directive.
        issued_directives = [
            Directive(event_id=d["event_id"], action=d["action"], params=d["params"])
            for d in store.get_issued_directives(bundle.box_id)
        ]

        hardening_total = score.total
        final_total = hardening_total + sla_accrued_total
        score.total = final_total

        store.upsert_score(
            bundle.box_id, rubric.scenario_name, final_total,
            hardening_points=hardening_total,
            service_points=sla_accrued_total,
            score_json=json.dumps(dataclasses.asdict(score), default=str),
        )

    # §2.4: matcher reasons embed expected values (the answer key); the box
    # only gets its own evidence reason alongside pass/points.
    _redact_for_box(score, evidence_by_check_id)

    # Scoreboard position is a presentation fact, not a scoring input: derive
    # it after the score write so it reflects this check-in, including ties.
    rank, rank_total = competition.rank_for_player(
        store, comp, player, received_at)

    # The check-in cadence is the engine's poll interval (how often the box
    # should collect + report), NOT the SLA granularity: SLA accrual is
    # elapsed-based and capped per check-in, so it works at any cadence.
    # Deriving the cadence from min SLA interval_s made 1s-interval rubrics
    # spin the box (seconds of Ed25519 per cycle) and 3600s-interval rubrics
    # freeze scoreboard updates for an hour.
    return CheckinResponse(
        server_time=received_at,
        score=score,
        directives=directives,
        next_checkin_s=max(1, int(next_checkin_s)),
        last_seq=bundle.seq,
        issued_directives=issued_directives,
        run_status=run_status,
        run_ends_at=run_ends_at,
        player_name=player.display_name if player is not None else None,
        competition_name=comp.name if comp is not None else None,
        rank=rank,
        rank_total=rank_total,
    )
