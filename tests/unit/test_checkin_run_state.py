"""Unit pins for engine/checkin.py::run_state_for (§7.1, boss directive).

A disqualified player keeps playing their full clock: the check-in keeps
``run_status == "running"`` (the agent loop never stops on a DQ) and the
exclusion happens on the board, not in the run. The removed tombstone is
the one status that stops a box on sight; the run's own clock and the
competition ending still stop every run, disqualified or not.
"""
from types import SimpleNamespace

from engine.checkin import run_state_for

NOW = 1_000_000.0


def _player(status="running", ends_at=NOW + 3600):
    return SimpleNamespace(status=status, ends_at=ends_at)


def _comp(status="live", scheduled_end_at=None):
    return SimpleNamespace(status=status, scheduled_end_at=scheduled_end_at)


def test_disqualified_run_keeps_playing():
    assert run_state_for(_player("disqualified"), _comp(), NOW) == (False, "running")


def test_disqualified_run_still_ends_when_its_clock_runs_out():
    assert run_state_for(_player("disqualified", ends_at=NOW - 1), _comp(), NOW) \
        == (True, "finished")


def test_disqualified_run_ends_when_the_competition_ends():
    assert run_state_for(_player("disqualified"), _comp("ended"), NOW) == (True, "ended")


def test_running_player_within_clock_keeps_playing():
    assert run_state_for(_player("running"), _comp(), NOW) == (False, "running")


def test_finished_player_stays_finished():
    assert run_state_for(_player("finished"), _comp(), NOW) == (True, "finished")


def test_removed_player_is_stopped_on_sight():
    # A tombstone owns no box: the run stops with the terminal status the
    # agent already treats as final.
    assert run_state_for(_player("removed"), _comp(), NOW) == (True, "disqualified")


def test_paused_or_draft_competition_holds_no_run_open():
    # Comp not live (draft/paused/ended paths): runs stop, even a DQ one.
    assert run_state_for(_player("disqualified"), _comp("draft"), NOW) == (True, "ended")


def test_no_competition_legacy_honor_box_keeps_playing():
    assert run_state_for(_player("running"), None, NOW) == (False, "running")


def test_scheduled_end_before_the_sweep_stops_the_run():
    # The clock is the truth: between the scheduled moment and the sweeper's
    # next tick a check-in is already stopped (and not scored). "ended", not
    # "finished": the whole competition is over, so no per-run access window.
    assert run_state_for(_player(), _comp(scheduled_end_at=NOW - 1), NOW) \
        == (True, "ended")


def test_scheduled_end_in_the_future_keeps_the_run_running():
    assert run_state_for(_player(), _comp(scheduled_end_at=NOW + 60), NOW) \
        == (False, "running")


def test_run_owns_clock_loses_to_scheduled_end_only_when_later():
    # A run whose own clock expired first is still the ordinary "finished"
    # (wall + access window); the scheduled end only caps later runs.
    assert run_state_for(_player(ends_at=NOW - 2),
                         _comp(scheduled_end_at=NOW - 1), NOW) \
        == (True, "finished")


def test_scheduled_end_ignored_on_ended_or_draft_competition():
    # Those paths already stop the run as "ended"; the schedule adds nothing.
    assert run_state_for(_player(), _comp("ended", scheduled_end_at=NOW - 1), NOW) \
        == (True, "ended")
    assert run_state_for(_player(), _comp("draft", scheduled_end_at=NOW - 1), NOW) \
        == (True, "ended")
