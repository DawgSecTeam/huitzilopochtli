"""Unit tests for the huitz CLI surface (agent/cli.py) and the modules it
renders from: agent/answers.py, agent/board.py, agent/snapshot.py,
agent/term.py.

The CLI reads snapshots and renders — it never scores — so these tests
drive it with synthetic snapshot dicts built the same way the agent builds
them (agent.snapshot.build_snapshot over synthetic schema objects).
"""
import io
import json
import os
import sys

import pytest

from agent import answers
from agent import board as board_mod
from agent import cli
from agent import snapshot
from agent import term
from common.schema import (
    Category,
    CheckResult,
    CheckSpec,
    ForensicsQuestion,
    Manifest,
    Mode,
    ScoreBreakdown,
)


# --- fixtures -----------------------------------------------------------------

class _FakeStream(io.StringIO):
    def __init__(self, tty=False):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


def _manifest(**overrides):
    forensics_path = overrides.pop("forensics_path", "/tmp/FQ.txt")
    checks = overrides.pop("checks", [
        CheckSpec(id="c1", type="file_regex", category=Category.VULN,
                  host_id="localhost", collect_params={},
                  display_title="SSH root login disabled", display_max_points=10),
        CheckSpec(id="c2", type="file_regex", category=Category.VULN,
                  host_id="localhost", collect_params={},
                  display_title="Guest account removed", display_max_points=10),
        CheckSpec(id="p1", type="permission", category=Category.PENALTY,
                  host_id="localhost", collect_params={},
                  display_title="Firewall still enabled", display_max_points=5),
        CheckSpec(id="f1", type="forensics_answer", category=Category.VULN,
                  host_id="localhost",
                  collect_params={"ordinal": 1, "path": forensics_path},
                  display_title="Which account did the attacker create?",
                  display_max_points=20),
    ])
    base = dict(
        schema_version=1, scenario_name="Test Box", scenario_version=3,
        mode=Mode.HONOR, engine_url=None, hosts=["localhost"],
        theme={"title": "Opochtli Landing", "organization": "Harbor Port Authority",
               "accent": "#0a7ea4"},
        checks=checks,
        forensics=[ForensicsQuestion(
            id="f1", question="Which account did the attacker create?",
            max_points=20)],
    )
    base.update(overrides)
    return Manifest(**base)


def _score(**overrides):
    base = dict(
        scenario_name="Test Box", scenario_version=3, total=30,
        results=[
            CheckResult(check_id="c1", category=Category.VULN, awarded_points=10,
                        passed=True, reason="equals FOUND"),
            CheckResult(check_id="c2", category=Category.VULN, awarded_points=0,
                        passed=False, reason="equals removed expected yes"),
            CheckResult(check_id="p1", category=Category.PENALTY, awarded_points=-5,
                        passed=False, reason="firewall active"),
            CheckResult(check_id="f1", category=Category.VULN, awarded_points=20,
                        passed=True, reason="answer recorded"),
        ],
        sla_status=[], computed_at=1700000000.0,
    )
    base.update(overrides)
    return ScoreBreakdown(**base)


def _honor_snapshot(tmp_path, **kw):
    report = tmp_path / "report.html"
    snap = snapshot.build_snapshot(
        kw.pop("score", _score()), kw.pop("manifest", _manifest()),
        mode="honor", agent_version="test", delta=kw.pop("delta", 0),
        computed_at=1700000000.0,
    )
    snapshot.write(str(report), snap)
    return str(tmp_path / "report.json"), snap


# --- answers ------------------------------------------------------------------

class TestAnswers:
    TEMPLATE = answers.render_template([(1, "Who?"), (2, "What?")])

    def test_extract_blank_placeholder_reads_unanswered(self):
        # Placeholder semantics match the collector exactly: the raw
        # underscores come back (not None); the check module and the
        # answer_equals matcher treat them as unanswered.
        answer, found = answers.extract_answer(self.TEMPLATE, 1)
        assert found and answers.ANSWER_PLACEHOLDER_RE.match(answer)

    def test_extract_filled_answer(self):
        content = self.TEMPLATE.replace(
            answers.blank_line(), "Answer: hal9000", 1)
        answer, found = answers.extract_answer(content, 1)
        assert found and answer == "hal9000"
        # the other question is untouched (still the placeholder)
        answer2, found2 = answers.extract_answer(content, 2)
        assert found2 and answers.ANSWER_PLACEHOLDER_RE.match(answer2)

    def test_extract_missing_ordinal(self):
        answer, found = answers.extract_answer(self.TEMPLATE, 7)
        assert not found and answer is None

    def test_extract_answer_line_is_case_insensitive(self):
        content = self.TEMPLATE.replace("Answer:", "answer:", 1)
        answer, found = answers.extract_answer(content, 1)
        assert found and answers.ANSWER_PLACEHOLDER_RE.match(answer)

    def test_set_answer_preserves_everything_else(self):
        new, found = answers.set_answer(self.TEMPLATE, 2, "203.0.113.7")
        assert found
        assert "Answer: 203.0.113.7" in new
        # Q1's block is byte-identical
        assert "Q1: Who?" in new and "Answer: " + "_" * 44 in new
        assert "Q2: What?" in new

    def test_set_answer_empty_restores_placeholder(self):
        filled = self.TEMPLATE.replace(answers.blank_line(), "Answer: x", 1)
        new, _ = answers.set_answer(filled, 1, "")
        assert answers.blank_line() in new

    def test_set_answer_repairs_deleted_answer_line(self):
        stripped = "\n".join(
            l for l in self.TEMPLATE.splitlines() if l.strip() != "Answer:") + "\n"
        new, found = answers.set_answer(stripped, 1, "repaired")
        assert found
        # re-inserted under Q1, before Q2
        assert new.index("Answer: repaired") < new.index("Q2:")

    def test_set_answer_preserves_trailing_newline_state(self):
        assert answers.set_answer(self.TEMPLATE, 1, "x")[0].endswith("\n")
        no_final_newline = self.TEMPLATE.rstrip("\n")
        assert not answers.set_answer(no_final_newline, 1, "x")[0].endswith("\n")


# --- board ---------------------------------------------------------------------

class TestBoard:
    def test_fixed_and_penalties_and_spoilers(self):
        b = board_mod.build_board(_score(), _manifest())
        assert [v.title for v in b.fixed] == ["SSH root login disabled"]
        assert [p.title for p in b.penalties] == ["Firewall still enabled"]
        assert b.total == 30

    def test_forensics_excluded_from_fixed_and_max(self):
        b = board_mod.build_board(_score(), _manifest())
        assert all("attacker" not in v.title for v in b.fixed)
        assert b.vulns_total == 2          # c1, c2 — f1 is forensics
        assert b.max_possible == 20        # 10 + 10, forensics' 20 excluded
        assert b.forensics_earned == 1
        assert b.forensics[0].ordinal == 1
        assert b.forensics[0].answers_path == "/tmp/FQ.txt"

    def test_progress_by_points_and_count_fallback(self):
        b = board_mod.build_board(_score(), _manifest())
        assert b.progress_pct == 50        # 10 earned / 20 max
        only_failed = _score(results=[
            CheckResult(check_id="c2", category=Category.VULN, awarded_points=0,
                        passed=False, reason="x"),
        ])
        b2 = board_mod.build_board(only_failed, _manifest())
        assert b2.progress_pct == 0 and b2.remaining == 2

    def test_all_fixed_and_remaining(self):
        b = board_mod.build_board(_score(), _manifest())
        assert not b.all_fixed and b.remaining == 1
        full = _score(results=[
            CheckResult(check_id="c1", category=Category.VULN, awarded_points=10,
                        passed=True, reason="ok"),
            CheckResult(check_id="c2", category=Category.VULN, awarded_points=10,
                        passed=True, reason="ok"),
            CheckResult(check_id="f1", category=Category.VULN, awarded_points=20,
                        passed=True, reason="ok"),
        ])
        b2 = board_mod.build_board(full, _manifest())
        assert b2.all_fixed and b2.remaining == 0

    def test_invalid_accent_dropped(self):
        m = _manifest(theme={"title": "X", "accent": "red; } body {"})
        assert board_mod.build_board(_score(), m).accent is None

    def test_dict_manifest_form(self):
        # engine-side callers may hold parsed JSON, not dataclasses
        m = _manifest()
        d = {
            "scenario_name": m.scenario_name, "theme": {"title": "Dict Title"},
            "checks": [
                {"id": "c1", "type": "file_regex", "category": "vuln",
                 "display_title": "T1", "display_max_points": 10, "is_sla": False,
                 "collect_params": {}},
            ],
            "forensics": [],
        }
        score = _score(results=[
            CheckResult(check_id="c1", category=Category.VULN, awarded_points=10,
                        passed=True, reason="ok")], total=10)
        b = board_mod.build_board(score, d)
        assert b.title == "Dict Title" and b.vulns_total == 1


# --- snapshot -------------------------------------------------------------------

class TestSnapshot:
    def test_honor_snapshot_has_no_results(self):
        snap = snapshot.build_snapshot(
            _score(), _manifest(), mode="honor", agent_version="t",
            delta=-5, computed_at=100.0)
        assert "results" not in snap, "honor snapshot must not spoil failed checks"
        assert snap["delta"] == -5
        assert snap["next_event_at"] == 170.0   # computed_at + 70s timer estimate
        assert snap["last_confirmed_at"] is None
        assert snap["total"] == 30

    def test_ranked_snapshot_carries_diagnostics(self):
        score = _score(sla_status=[
            __import__("common.schema", fromlist=["SlaStatus"]).SlaStatus(
                check_id="web", state="UP", accrued_points=3)])
        snap = snapshot.build_snapshot(
            score, _manifest(), mode="ranked", agent_version="t", delta=0,
            computed_at=100.0, server_time=500.0, next_checkin_s=60)
        assert [r["check_id"] for r in snap["results"]] == ["c1", "c2", "p1", "f1"]
        assert snap["sla_status"][0]["state"] == "UP"
        assert snap["last_confirmed_at"] == 500.0
        assert snap["next_event_at"] == 560.0

    def test_awaiting_engine_total_is_null(self):
        snap = snapshot.build_snapshot(
            _score(total=0, results=[]), _manifest(), mode="ranked",
            agent_version="t", delta=None, computed_at=100.0,
            awaiting_engine=True)
        assert snap["awaiting_engine"] is True
        assert snap["total"] is None

    def test_write_read_round_trip(self, tmp_path):
        path, snap = _honor_snapshot(tmp_path)
        loaded = snapshot.read(path)
        assert loaded == snap
        assert os.path.basename(path) == "report.json"
        assert os.stat(path).st_mode & 0o004, \
            "snapshot must be world-readable (Desktop-mirrored)"

    def test_read_refuses_corrupt_and_newer(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        with pytest.raises(snapshot.SnapshotError):
            snapshot.read(str(bad))
        future = tmp_path / "future.json"
        future.write_text(json.dumps({"snapshot_version": 999}))
        with pytest.raises(snapshot.SnapshotError, match="v999"):
            snapshot.read(str(future))
        versionless = tmp_path / "v.json"
        versionless.write_text(json.dumps({"total": 1}))
        with pytest.raises(snapshot.SnapshotError):
            snapshot.read(str(versionless))


# --- term ------------------------------------------------------------------------

class TestTerm:
    @pytest.mark.parametrize("env,expected", [
        ({"NO_COLOR": "1"}, term.NONE),
        ({"TERM": "dumb"}, term.NONE),
        ({"TERM": "xterm-256color"}, term.C256),
    ])
    def test_detect_depth_tty_auto(self, monkeypatch, env, expected):
        for name in ("NO_COLOR", "FORCE_COLOR", "TERM", "COLORTERM"):
            monkeypatch.delenv(name, raising=False)
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        assert term.detect_depth(_FakeStream(True), "auto") == expected

    def test_detect_depth_never_and_forced(self, monkeypatch):
        for name in ("NO_COLOR", "FORCE_COLOR", "TERM", "COLORTERM"):
            monkeypatch.delenv(name, raising=False)
        assert term.detect_depth(_FakeStream(True), "never") == term.NONE
        monkeypatch.setenv("NO_COLOR", "1")
        # NO_COLOR wins on auto even for a TTY...
        assert term.detect_depth(_FakeStream(True), "auto") == term.NONE
        # ...but an explicit always beats it.
        assert term.detect_depth(_FakeStream(True), "always") == term.C16
        # FORCE_COLOR re-enables color for piped output under NO_COLOR.
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert term.detect_depth(_FakeStream(False), "auto") == term.C16

    def test_detect_truecolor(self, monkeypatch):
        for name in ("NO_COLOR", "FORCE_COLOR", "TERM"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("COLORTERM", "truecolor")
        assert term.detect_depth(_FakeStream(True), "auto") == term.TRUECOLOR

    def test_non_tty_is_plain_without_force(self, monkeypatch):
        for name in ("NO_COLOR", "FORCE_COLOR", "TERM", "COLORTERM"):
            monkeypatch.delenv(name, raising=False)
        assert term.detect_depth(_FakeStream(False), "auto") == term.NONE

    def test_style_none_passes_through(self):
        sty = term.Style(term.NONE)
        assert sty.color("x", "ok") == "x"
        assert sty.bold("x") == "x"

    def test_accent_maps_into_palette(self):
        sty = term.Style(term.C256, accent="#ff0000")
        out = sty.color("x", "accent")
        assert "\x1b[38;5;9m" in out  # xterm 9 = bright red
        sty16 = term.Style(term.C16, accent="#ff0000")
        assert "\x1b[38;5;" in sty16.color("x", "accent")

    def test_visible_len_and_truncate_ansi(self):
        sty = term.Style(term.C16)
        styled = sty.color("hello", "ok", 1)
        assert term.visible_len(styled) == 5
        cut = term.truncate_ansi(styled + " world", 5)
        assert term.visible_len(cut) == 5
        assert not cut.endswith("m world")  # escape not split mid-sequence
        assert term.truncate_ansi("plain", 10) == "plain"

    def test_fmt_mmss(self):
        assert term.fmt_mmss(42) == "00:42"
        assert term.fmt_mmss(61) == "01:01"
        assert term.fmt_mmss(3600) == "1:00:00"
        assert term.fmt_mmss(-5) == "00:00"

    def test_progress_bar_bounds(self):
        sym = term.Symbols(False)
        assert term.progress_bar(0, 10, sym) == "[--------]"
        assert term.progress_bar(100, 10, sym) == "[########]"
        assert term.progress_bar(140, 10, sym) == "[########]"

    def test_ascii_symbols_when_not_utf8(self):
        sym = term.Symbols(False)
        assert sym.check == "+" and sym.block == "#"
        assert term.Symbols(True).check == "✓"

    def test_wrap_ansi_respects_width(self):
        out = term.wrap_ansi("aaa bbb ccc ddd eee", 10, subsequent_indent="  ")
        for line in out.splitlines():
            assert term.visible_len(line) <= 10
        assert out.splitlines()[1].startswith("  ")  # hanging indent

    def test_wrap_ansi_styled_span_flows_across_wrap(self):
        sty = term.Style(term.C256, accent="#0a7ea4")
        wrapped = term.wrap_ansi(sty.bold("alpha beta gamma delta"), 11)
        for line in wrapped.splitlines():
            assert term.visible_len(line) <= 11
        assert wrapped.count("\x1b[1m") == 1  # style opens once...
        assert wrapped.endswith("\x1b[0m")    # ...and closes at the very end

    def test_wrap_ansi_hard_splits_unbreakable(self):
        out = term.wrap_ansi("abcdefghijklm", 5)
        assert all(term.visible_len(l) <= 5 for l in out.splitlines())

    def test_detect_height_floor(self):
        assert term.detect_height(_FakeStream()) >= 4


# --- cli rendering ---------------------------------------------------------------

class TestRenderScorecard:
    def _render(self, snap, width=80, tty=False, **kw):
        sty = term.Style.detect(_FakeStream(tty), "never")
        return cli.render_scorecard(snap, sty, term.Symbols(True), width, **kw)

    def test_honor_board_plain(self, tmp_path):
        _, snap = _honor_snapshot(tmp_path)
        out = self._render(snap)
        assert "Opochtli Landing" in out
        assert "honor mode" in out
        assert "30 pts" in out
        assert "VULNERABILITIES FIXED — 1 of 2" in out
        assert "SSH root login disabled" in out and "+10" in out
        assert "PENALTIES — 1" in out and "Firewall still enabled" in out and "-5" in out
        assert "FORENSICS — 1 of 1" in out
        assert "Q1 Which account did the attacker create?" in out
        # spoilers never render
        assert "Guest account removed" not in out
        assert "equals FOUND" not in out and "c2" not in out

    def test_delta_banner_one_run_semantics(self, tmp_path):
        _, up = _honor_snapshot(tmp_path / "a")
        assert "+7 pts since the last grading pass" in self._render(
            {**up, "delta": 7})
        _, down = _honor_snapshot(tmp_path / "b")
        down_text = self._render({**down, "delta": -9})
        assert "▼ -9 pts" in down_text and "penalty" in down_text
        assert "since the last grading pass" not in self._render({**down, "delta": 0})

    def test_awaiting_engine_view(self, tmp_path):
        snap = snapshot.build_snapshot(
            _score(total=0, results=[]), _manifest(), mode="ranked",
            agent_version="t", delta=None, computed_at=100.0,
            awaiting_engine=True)
        out = self._render(snap)
        assert "submitted — awaiting engine" in out
        assert "30 pts" not in out  # no score exists yet; nothing to show

    def test_ranked_diagnostic_view(self):
        from common.schema import SlaStatus
        snap = snapshot.build_snapshot(
            _score(sla_status=[SlaStatus(check_id="web", state="UP",
                                         accrued_points=3)]),
            _manifest(), mode="ranked", agent_version="t", delta=0,
            computed_at=100.0, server_time=500.0, next_checkin_s=60)
        out = self._render(snap)
        assert "CHECK RESULTS" in out
        assert "c1" in out and "equals FOUND" in out  # safe: rubric is off-box
        assert "authoritative score" in out
        assert "SLA STATUS" in out and "UP" in out

    def test_narrow_width_does_not_spill(self, tmp_path):
        _, snap = _honor_snapshot(tmp_path)
        out = self._render(snap, width=44)
        for line in out.splitlines():
            assert term.visible_len(line) <= 44

    def test_countdown_states(self, tmp_path):
        _, snap = _honor_snapshot(tmp_path)
        now = 1700000000.0 + 10
        text = self._render(snap, now=now)
        assert "next re-grade ~01:00" in text
        late = self._render(snap, now=1700000000.0 + 100)  # 40s overdue: calm
        assert "next re-grade due now" in late
        stalled = self._render(snap, now=1700000000.0 + 3600)  # ~1h: name it
        assert "next re-grade overdue by 58:50 (timer stalled?)" in stalled


# --- cli commands ------------------------------------------------------------------

class TestCliCommands:
    def test_score_renders_and_json(self, tmp_path, monkeypatch):
        path, snap = _honor_snapshot(tmp_path)
        out = _FakeStream()
        assert cli.main(["score", "--report", path], outstream=out) == 0
        text = out.getvalue()
        assert "VULNERABILITIES FIXED" in text
        assert "try: huitz watch" in text  # one-shot shows hints

        out2 = _FakeStream()
        assert cli.main(["score", "--json", "--report", path],
                        outstream=out2) == 0
        assert json.loads(out2.getvalue()) == snap

    def test_score_plain_when_no_color(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        path, _ = _honor_snapshot(tmp_path)
        out = _FakeStream(tty=True)
        assert cli.main(["score", "--report", path], outstream=out) == 0
        assert "\x1b[" not in out.getvalue()

    def test_no_snapshot_anywhere_is_a_friendly_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv(cli.ENV_REPORT, raising=False)
        monkeypatch.setattr(cli, "_report_json_from_config",
                            lambda p: str(tmp_path / "nope.json"))
        monkeypatch.setattr(cli, "_desktop_report_paths", lambda: [])
        with pytest.raises(cli.CliError, match="no grade found"):
            cli._load_snapshot(None)

    def test_discovery_precedence(self, tmp_path, monkeypatch):
        env_p, install_p, desktop_p = (tmp_path / n for n in
                                       ("env.json", "install.json", "desktop.json"))
        for p in (env_p, install_p, desktop_p):
            p.write_text(json.dumps({"snapshot_version": 1}))
        monkeypatch.delenv(cli.ENV_REPORT, raising=False)
        monkeypatch.setattr(cli, "_report_json_from_config",
                            lambda p: str(install_p))
        monkeypatch.setattr(cli, "_desktop_report_paths",
                            lambda: [str(desktop_p)])

        found, _ = cli.locate_snapshot()
        assert found == str(install_p)

        monkeypatch.setenv(cli.ENV_REPORT, str(env_p))
        found, _ = cli.locate_snapshot()
        assert found == str(env_p)

        monkeypatch.delenv(cli.ENV_REPORT)
        found, _ = cli.locate_snapshot(str(desktop_p))
        assert found == str(desktop_p)
        found, searched = cli.locate_snapshot(str(tmp_path / "missing.json"))
        assert found is None and searched == [str(tmp_path / "missing.json")]

    def test_usage_errors_exit_2(self, tmp_path):
        path, _ = _honor_snapshot(tmp_path)
        assert cli.main(["score", "--nope", "--report", path]) == 2
        assert cli.main(["score", "extra", "--report", path]) == 2
        assert cli.main(["frobnicate"]) == 2
        assert cli.main(["forensics", "abc", "--report", path]) == 2

    def test_help_and_bare_invocation(self):
        assert cli.main(["help"], outstream=_FakeStream()) == 0
        assert cli.main([], outstream=_FakeStream()) == 0

    def test_forensics_set_clear_and_prompt(self, tmp_path, monkeypatch):
        answers_path = tmp_path / "Forensics-Questions.txt"
        answers_path.write_text(
            answers.render_template([(1, "Who?"), (2, "What?")]),
            encoding="utf-8")
        # A scenario with TWO questions, sharing one answers file.
        two_questions = _manifest(
            forensics_path=str(answers_path),
            checks=[
                CheckSpec(id="c1", type="file_regex", category=Category.VULN,
                          host_id="localhost", collect_params={},
                          display_title="SSH root login disabled",
                          display_max_points=10),
                CheckSpec(id="f1", type="forensics_answer", category=Category.VULN,
                          host_id="localhost",
                          collect_params={"ordinal": 1, "path": str(answers_path)},
                          display_title="Who?", display_max_points=20),
                CheckSpec(id="f2", type="forensics_answer", category=Category.VULN,
                          host_id="localhost",
                          collect_params={"ordinal": 2, "path": str(answers_path)},
                          display_title="What?", display_max_points=20),
            ],
            forensics=[
                ForensicsQuestion(id="f1", question="Who?", max_points=20),
                ForensicsQuestion(id="f2", question="What?", max_points=20),
            ],
        )
        snap = snapshot.build_snapshot(
            _score(), two_questions, mode="honor", agent_version="t",
            delta=0, computed_at=100.0)

        # scripted answer
        out = _FakeStream()
        rc = cli.set_forensics_answer(snap, 2, "203.0.113.7", None,
                                      _FakeStream(), out)
        assert rc == 0
        content = answers_path.read_text(encoding="utf-8")
        assert "Answer: 203.0.113.7" in content
        assert "Q1: Who?" in content
        assert "scores on the next re-grade" in out.getvalue()

        # interactive prompt (forced tty-ish via monkeypatched is_interactive)
        monkeypatch.setattr(term, "is_interactive", lambda s: True)
        out = _FakeStream()
        rc = cli.set_forensics_answer(snap, 1, None, None,
                                      io.StringIO("hal\n"), out)
        assert rc == 0
        assert "Answer: hal" in answers_path.read_text(encoding="utf-8")

        # '-' clears back to the placeholder
        cli.set_forensics_answer(snap, 1, "-", None, _FakeStream(), _FakeStream())
        assert answers.blank_line() in answers_path.read_text(encoding="utf-8")

    def test_forensics_prompt_requires_text_when_not_interactive(self, tmp_path):
        answers_path = tmp_path / "FQ.txt"
        snap = snapshot.build_snapshot(
            _score(), _manifest(forensics_path=str(answers_path)),
            mode="honor", agent_version="t", delta=0, computed_at=100.0)
        with pytest.raises(cli.CliError, match="pass it instead"):
            cli.set_forensics_answer(snap, 1, None, None,
                                     _FakeStream(), _FakeStream())

    def test_forensics_unknown_ordinal(self, tmp_path):
        snap = snapshot.build_snapshot(
            _score(), _manifest(forensics_path=str(tmp_path / "FQ.txt")),
            mode="honor", agent_version="t", delta=0, computed_at=100.0)
        with pytest.raises(cli.CliError, match="no forensics question 9"):
            cli.set_forensics_answer(snap, 9, "x", None, _FakeStream(),
                                     _FakeStream())

    def test_forensics_listing_shows_recorded_answers(self, tmp_path):
        answers_path = tmp_path / "Forensics-Questions.txt"
        answers_path.write_text(
            answers.render_template([(1, "Who?")]).replace(
                answers.blank_line(), "Answer: hal", 1), encoding="utf-8")
        report = tmp_path / "report.html"
        snap = snapshot.build_snapshot(
            _score(), _manifest(forensics_path=str(answers_path)),
            mode="honor", agent_version="t", delta=0, computed_at=100.0)
        snapshot.write(str(report), snap)
        out = _FakeStream()
        assert cli.main(["forensics", "--report", str(tmp_path / "report.json")],
                        outstream=out) == 0
        text = out.getvalue()
        assert "your answer:" in text and '"hal"' in text
        assert "set an answer" in text

    def test_watch_once_renders_frame(self, tmp_path):
        path, _ = _honor_snapshot(tmp_path)
        out = _FakeStream()
        assert cli.main(["watch", "--once", "--report", path],
                        outstream=out, instream=_FakeStream()) == 0
        assert "Opochtli Landing" in out.getvalue()

    def test_watch_once_missing_snapshot_errors(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cli, "_report_json_from_config",
                            lambda p: str(tmp_path / "nope.json"))
        monkeypatch.setattr(cli, "_desktop_report_paths", lambda: [])
        monkeypatch.delenv(cli.ENV_REPORT, raising=False)
        # main() converts the CliError to an exit code + stderr message
        assert cli.main(["watch", "--once"], outstream=_FakeStream(),
                        instream=_FakeStream()) == 1


# --- dispatch (agent/__main__ verb routing) ----------------------------------------

class TestDispatch:
    def test_verbs_route_to_cli(self, monkeypatch):
        import agent.__main__ as agent_main
        monkeypatch.setattr(sys, "argv", ["agent.pyz", "help"])
        with pytest.raises(SystemExit) as exc:
            agent_main.main()
        assert exc.value.code == 0

    def test_config_path_stays_classic(self, monkeypatch, tmp_path):
        # a config path must NOT be swallowed by the verb dispatcher
        import agent.__main__ as agent_main
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["agent.pyz", "not-a-config.json"])
        with pytest.raises(OSError):
            agent_main.main()

    def test_unknown_verb_is_usage(self, monkeypatch):
        import agent.__main__ as agent_main
        monkeypatch.setattr(sys, "argv", ["agent.pyz", "wibble"])
        with pytest.raises(SystemExit) as exc:
            agent_main.main()
        assert exc.value.code == 2

    def test_unknown_verb_suggests_close_match(self, capsys):
        assert cli.main(["redme"]) == 2
        assert "did you mean: huitz readme" in capsys.readouterr().err

    def test_unknown_verb_without_close_match(self, capsys):
        assert cli.main(["frobnicate"]) == 2
        assert "did you mean" not in capsys.readouterr().err


# --- readme: compile embeds, snapshot carries, CLI renders ---------------------

HANDBOOK = """# Factory Handbook

Welcome to the **factory**. Read `RULES.md` first.

## Ground rules

- Keep the **recipe vault** locked.
- See [the portal](https://example.test/portal) for scoring.

1. Fix things
2. Keep them fixed

> Hardening is a habit.

```
sudo huitz score
```
"""


def test_compile_embeds_readme_text_in_manifest(tmp_path):
    import yaml as yaml_mod
    from authoring.compile import compile_scenario
    from common.crypto.signing import keypair

    (tmp_path / "handbook.md").write_text(HANDBOOK, encoding="utf-8")
    scenario = {
        "scenario": {"name": "t", "version": 1, "mode": "honor",
                     "hosts": ["localhost"]},
        "theme": {"title": "T", "accent": "#0a7ea4",
                  "readme": str(tmp_path / "handbook.md")},
        "checks": [{
            "id": "c1", "type": "file_regex", "category": "vuln",
            "display": "D", "max_points": 5,
            "collect": {"path": str(tmp_path / "f.txt"), "extract": "x=(\\w+)"},
            "expect": {"equals": "y", "points": 5},
        }],
    }
    yaml_path = tmp_path / "scenario.yaml"
    yaml_path.write_text(yaml_mod.safe_dump(scenario), encoding="utf-8")
    (tmp_path / "f.txt").write_text("x=y", encoding="utf-8")

    priv, _pub = keypair()
    out = compile_scenario(str(yaml_path), str(tmp_path / "out"), priv)
    manifest = json.loads((tmp_path / "out" / "manifest.signed.json").read_text()
                          .replace('{"_signature"', '{"_signature"'))  # signed file parses as-is
    snap_manifest = manifest
    assert snap_manifest["theme"]["readme_text"] == HANDBOOK


def test_snapshot_carries_readme(tmp_path):
    m = _manifest(theme={"title": "X", "readme_text": HANDBOOK})
    snap = snapshot.build_snapshot(_score(), m, mode="honor",
                                   agent_version="t", delta=0,
                                   computed_at=100.0)
    assert snap["readme"] == HANDBOOK
    # and stays None when the scenario ships none
    snap2 = snapshot.build_snapshot(_score(), _manifest(), mode="honor",
                                    agent_version="t", delta=0,
                                    computed_at=100.0)
    assert snap2["readme"] is None


class TestReadme:
    def _render(self, text, width=80):
        sty = term.Style(term.NONE)
        return cli.render_readme(text, sty, term.Symbols(True), width)

    def test_structure_and_inline(self):
        out = self._render(HANDBOOK)
        lines = out.splitlines()
        assert lines[0] == "Factory Handbook"
        assert set(lines[1]) == {"─"}  # accent rule under h1
        assert "## Ground rules" not in out and "Ground rules" in out
        assert "• Keep the recipe vault locked." in out  # bold stripped, bullet kept
        assert "**" not in out and "`" not in out
        assert "See the portal <https://example.test/portal> for scoring." in out
        assert "1." in out and "Fix things" in out
        assert "> Hardening" not in out and "Hardening is a habit." in out
        assert any(l.strip() == "sudo huitz score" for l in lines)  # fence content

    def test_ascii_symbols(self):
        sty = term.Style(term.NONE)
        out = cli.render_readme("- item\n", sty, term.Symbols(False), 40)
        assert "* item" in out

    def test_command_paths(self, tmp_path):
        report = tmp_path / "report.html"
        m = _manifest(theme={"title": "X", "readme_text": HANDBOOK})
        snap = snapshot.build_snapshot(_score(), m, mode="honor",
                                       agent_version="t", delta=0,
                                       computed_at=100.0)
        snapshot.write(str(report), snap)
        path = str(tmp_path / "report.json")

        out = _FakeStream()
        assert cli.main(["readme", "--report", path], outstream=out) == 0
        assert "Factory Handbook" in out.getvalue()
        assert "Ground rules" in out.getvalue()

        raw = _FakeStream()
        assert cli.main(["readme", "--raw", "--report", path],
                        outstream=raw) == 0
        assert raw.getvalue() == HANDBOOK or raw.getvalue() == HANDBOOK + "\n"

        # no handbook in the scenario -> clean runtime error
        path2, _ = _honor_snapshot(tmp_path / "b")
        assert cli.main(["readme", "--report", path2],
                        outstream=_FakeStream()) == 1

    def test_wrapped_prose_reflows_and_never_spills(self):
        # Source hard-wraps are an authoring artifact: the renderer folds the
        # paragraph and re-wraps it to the terminal width.
        src = ("This is a long paragraph that the author hard-wrapped at\n"
               "some arbitrary column, expecting the renderer to join the\n"
               "lines back together before wrapping to the terminal.\n")
        out = self._render(src, width=40)
        for line in out.splitlines():
            assert term.visible_len(line) <= 40
        assert "hard-wrapped at some arbitrary" in out  # source break removed

    def test_multiline_emphasis_renders_without_asterisks(self):
        # The handbook hard-wraps mid-span: bold crossing a newline must still
        # render (the old per-line renderer printed the literal asterisks).
        src = ("Your job: **find and remove every way\n"
               "it comes back** in the box. *softly\n"
               "returns.*\n")
        out = self._render(src, width=60)
        assert "*" not in out
        assert "find and remove every way it comes back" in out

    def test_multiline_emphasis_carries_style(self):
        sty = term.Style(term.C16, accent="#0a7ea4")
        out = cli.render_readme("**bold across\na wrap** end",
                                sty, term.Symbols(True), 80)
        assert "\x1b[1mbold across a wrap\x1b[0m" in out
        out2 = cli.render_readme("*softly* now", sty, term.Symbols(True), 80)
        assert "\x1b[3msoftly\x1b[0m" in out2

    def test_code_spans_use_accent_not_muted(self):
        sty = term.Style(term.C16, accent="#0a7ea4")
        out = cli.render_readme("run `huitz score` now",
                                sty, term.Symbols(True), 80)
        accent_param = term._rgb_ansi((0x0a, 0x7e, 0xa4), term.C16)
        muted_param = term._rgb_ansi((0x6e, 0x73, 0x78), term.C16)
        assert accent_param in out
        assert muted_param not in out

    def test_h1_title_is_bold_ink_with_accent_rule(self):
        sty = term.Style(term.C16, accent="#0a7ea4")
        out = cli.render_readme("# Title\n", sty, term.Symbols(True), 80)
        assert "\x1b[1mTitle\x1b[0m" in out          # bold, terminal default ink
        accent_param = term._rgb_ansi((0x0a, 0x7e, 0xa4), term.C16)
        assert accent_param in out                   # the rule keeps the accent

    def test_fence_lines_wrap_never_ellipsize(self):
        long_cmd = ("openssl enc -aes-256-cbc -in secret.txt "
                    "-out secret.enc -k password123456")
        out = self._render(f"```\n{long_cmd}\n```\n", width=40)
        assert "…" not in out
        assert "password123456" in out  # the tail survives (was ellipsized away)
        for line in out.splitlines():
            assert term.visible_len(line) <= 40


class TestScorecardContrast:
    """The scoreboard meets the readme contrast standard: no SGR 2 (faint)
    anywhere — it all but vanishes on several dark terminals — and muted is
    reserved for chrome; data lines render in default ink."""

    def _styled(self, snap, width=80, **kw):
        sty = term.Style(term.C16, accent="#0a7ea4")
        return cli.render_scorecard(snap, sty, term.Symbols(True), width, **kw)

    def _accent(self):
        return term._rgb_ansi((0x0A, 0x7E, 0xA4), term.C16)

    def _muted(self):
        return term._rgb_ansi((0x6E, 0x73, 0x78), term.C16)

    def _lines_with(self, out, needle):
        return [l for l in out.splitlines() if needle in l]

    def test_no_faint_sgr_anywhere(self, tmp_path):
        _, snap = _honor_snapshot(tmp_path)
        out = self._styled(snap, hints=True)
        assert "\x1b[2m" not in out

    def test_data_lines_render_ink_not_muted(self, tmp_path):
        _, snap = _honor_snapshot(tmp_path)
        out = self._styled(snap, hints=True)
        for needle in ("scenario v3", "1 of 2 fixed", "1 issue(s) remain",
                       "last graded"):
            hits = self._lines_with(out, needle)
            assert hits, f"expected a line containing {needle!r}"
            for line in hits:
                assert self._muted() not in line, needle
        _, zero = _honor_snapshot(tmp_path / "zero",
                                  score=_score(total=0, results=[]))
        empty = self._lines_with(self._styled(zero),
                                 "no vulnerabilities fixed yet")
        assert empty and self._muted() not in empty[0]

    def test_hints_line_is_muted_not_faint(self, tmp_path):
        _, snap = _honor_snapshot(tmp_path)
        out = self._styled(snap, hints=True)
        hits = self._lines_with(out, "try: huitz watch")
        assert hits and self._muted() in hits[0]

    def test_answers_path_gets_accent(self, tmp_path):
        _, snap = _honor_snapshot(tmp_path)
        snap = {**snap, "forensics": [
            {**snap["forensics"][0],
             "answers_path": "/home/p/Desktop/Forensics-Questions.txt"}]}
        out = self._styled(snap)
        hits = self._lines_with(out, "answers: ")
        assert hits
        assert self._accent() in hits[0]   # the path is the actionable bit
        assert self._muted() in hits[0]    # the label stays chrome

    def test_countdown_note_neutral_is_ink(self):
        sty = term.Style(term.C16, accent="#0a7ea4")
        note = cli._countdown_note(
            {"mode": "honor", "next_event_at": 1700000000.0 + 60},
            1700000000.0, sty)
        assert "next re-grade in 01:00" in note
        assert self._muted() not in note
        late = cli._countdown_note(
            {"mode": "honor", "next_event_at": 1700000000.0},
            1700000000.0 + 3600, sty)
        assert "overdue" in late and "\x1b[" in late   # still escalates

    def test_watch_restyles_with_snapshot_accent(self, tmp_path, monkeypatch):
        path, _snap = _honor_snapshot(tmp_path)
        calls = []
        real = term.Style.detect.__func__

        @classmethod
        def spy(cls, stream, override="auto", accent=None):
            calls.append(accent)
            return real(cls, stream, override, accent)

        monkeypatch.setattr(term.Style, "detect", spy)
        rc = cli.cmd_watch(["--once", "--report", path],
                           _FakeStream(tty=True), _FakeStream(tty=True))
        assert rc == cli._EXIT_OK
        assert calls, "watch must create a style"
        assert calls[0] is None            # built before any snapshot exists
        assert "#0a7ea4" in calls[1:]      # restyled once the snapshot lands


class TestPaging:
    """readme/score page through less on a terminal; pipes never see a pager."""

    def _snapshot_file(self, tmp_path):
        report = tmp_path / "report.html"
        m = _manifest(theme={"title": "X", "readme_text": HANDBOOK})
        snap = snapshot.build_snapshot(_score(), m, mode="honor",
                                       agent_version="t", delta=0,
                                       computed_at=100.0)
        snapshot.write(str(report), snap)
        return str(tmp_path / "report.json")

    def _fake_popen(self, monkeypatch):
        calls = {}

        class FakeProc:
            def __init__(self, argv, **kw):
                calls["argv"] = argv

            def communicate(self, data):
                calls["data"] = data
                return None, None

            def poll(self):
                return 0

        monkeypatch.setattr(cli.subprocess, "Popen", FakeProc)
        return calls

    def test_page_skipped_when_not_tty(self, monkeypatch):
        monkeypatch.setattr(cli, "_pager_argv", lambda: ["less", "-R"])
        assert cli._page("hello\n", _FakeStream()) is False

    def test_readme_pages_on_tty(self, tmp_path, monkeypatch):
        path = self._snapshot_file(tmp_path)
        calls = self._fake_popen(monkeypatch)
        monkeypatch.setattr(cli, "_pager_argv", lambda: ["less", "-R"])
        rc = cli.main(["readme", "--report", path],
                      outstream=_FakeStream(tty=True))
        assert rc == 0
        assert calls["argv"] == ["less", "-R"]
        assert b"Factory Handbook" in calls["data"]

    def test_readme_no_pager_and_raw_print_flat(self, tmp_path, monkeypatch):
        path = self._snapshot_file(tmp_path)

        def boom(*a, **kw):
            raise AssertionError("pager must not spawn")

        monkeypatch.setattr(cli.subprocess, "Popen", boom)
        tty = _FakeStream(tty=True)
        assert cli.main(["readme", "--no-pager", "--report", path],
                        outstream=tty) == 0
        assert "Factory Handbook" in tty.getvalue()
        raw = _FakeStream(tty=True)
        assert cli.main(["readme", "--raw", "--report", path],
                        outstream=raw) == 0
        assert raw.getvalue().startswith("# Factory Handbook")

    def test_score_pages_only_when_taller_than_window(self, tmp_path, monkeypatch):
        path = self._snapshot_file(tmp_path)
        calls = self._fake_popen(monkeypatch)
        monkeypatch.setattr(cli, "_pager_argv", lambda: ["less", "-R"])
        monkeypatch.setattr(cli.agent.term, "detect_height", lambda stream: 5)
        tty = _FakeStream(tty=True)
        assert cli.main(["score", "--report", path], outstream=tty) == 0
        assert "argv" in calls and b"pts" in calls["data"]

        calls.clear()
        monkeypatch.setattr(cli.agent.term, "detect_height", lambda stream: 500)
        tty2 = _FakeStream(tty=True)
        assert cli.main(["score", "--report", path], outstream=tty2) == 0
        assert calls == {}  # short board: flat print, no pager
        assert "pts" in tty2.getvalue()

    def test_score_no_pager_flag_prints_flat(self, tmp_path, monkeypatch):
        path = self._snapshot_file(tmp_path)

        def boom(*a, **kw):
            raise AssertionError("pager must not spawn")

        monkeypatch.setattr(cli.subprocess, "Popen", boom)
        monkeypatch.setattr(cli.agent.term, "detect_height", lambda stream: 5)
        tty = _FakeStream(tty=True)
        assert cli.main(["score", "--no-pager", "--report", path],
                        outstream=tty) == 0
        assert "pts" in tty.getvalue()

    def test_pager_env_and_fallbacks(self, monkeypatch):
        monkeypatch.setenv("PAGER", "cat -s")
        assert cli._pager_argv() == ["cat", "-s"]
        monkeypatch.setenv("PAGER", "less")
        assert cli._pager_argv() == ["less", "-R"]  # -R added for a bare less
        monkeypatch.setenv("PAGER", "")
        monkeypatch.setattr(cli.shutil, "which", lambda name: False)
        assert cli._pager_argv() is None


class TestOverdueCountdown:
    SNAP = {"mode": "honor", "next_event_at": 1700000000.0}

    def _note(self, now):
        sty = term.Style(term.NONE)
        return cli._countdown_note(self.SNAP, now, sty)

    def test_within_cadence_says_checking(self):
        # 60s past due: normal cadence jitter, stays calm
        assert "checking…" in self._note(1700000060.0)
        assert "overdue" not in self._note(1700000060.0)

    def test_long_overdue_names_the_stall(self):
        note = self._note(1700000300.0)  # 5 min past due
        assert "overdue by 05:00" in note
        assert "stalled" in note

    def test_scorecard_footer_overdue(self, tmp_path):
        path, snap = _honor_snapshot(tmp_path)
        sty = term.Style(term.NONE)
        frame = cli.render_scorecard(snap, sty, term.Symbols(True), 80,
                                     now=snap["next_event_at"] + 300)
        assert "next re-grade overdue by 05:00 (timer stalled?)" in frame
