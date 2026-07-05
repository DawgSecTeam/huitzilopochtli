"""Static HTML report renderer. See architecture.md §13.

FROZEN signature; body is a PHASE 1 TASK. Pure function — no I/O; caller
writes the returned HTML string to report_path.
"""
from common.schema import Mode, ScoreBreakdown


def render_report(score: ScoreBreakdown, mode: Mode,
                   last_confirmed_at: float | None) -> str:
    """Render ScoreBreakdown to a self-contained HTML string.

    Includes a <meta http-equiv="refresh" content="N"> tag (display cadence
    only, never a scoring input). Dashboard elements: cumulative total; table
    of point-in-time results (category, awarded, reason); SLA status table
    (state UP/DOWN, accrued); and, in ranked mode, a "last confirmed by
    engine at <last_confirmed_at>" stamp. In ranked mode before the first
    engine response, last_confirmed_at is None and the report should show
    "submitted — awaiting engine" instead of a score.
    """
    raise NotImplementedError
