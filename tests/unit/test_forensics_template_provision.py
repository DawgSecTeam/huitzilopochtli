"""Forensics answers-file provisioning: missing dirs, stale images, sudo UX.

Rehearsal (2026-11 range campaign) found three ways real boxes broke the
forensics flow, all fixed here:
- the answer file's Desktop home (e.g. /home/stationlead/Desktop) does not
  exist on the image -> boot writer skipped, and `huitz forensics` died on a
  raw mkstemp FileNotFoundError;
- a sealed image shipped the PREVIOUS scenario's blank questions (Harborline
  clones carried Saltmarsh's file) and both writers kept it forever;
- a root-owned Desktop made a non-sudo answer a PermissionError traceback
  instead of the actionable "use sudo" line.
"""
import os
import stat
import sys
from types import SimpleNamespace

import pytest

import agent.answers
import agent.cli as cli

needs_nonroot = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="needs non-root")


def _q(pairs):
    return [{"ordinal": o, "question": t, "id": f"fq-{o}"} for o, t in pairs]


class TestStaleBlankTemplate:
    def test_blank_with_foreign_questions_is_stale(self):
        old = agent.answers.render_template([(1, "Where is the web shell?")])
        assert agent.answers.is_stale_blank_template(
            old, [(1, "Which account phoned home?")])

    def test_matching_questions_are_not_stale(self):
        good = agent.answers.render_template([(1, "Q one"), (2, "Q two")])
        assert not agent.answers.is_stale_blank_template(
            good, [(1, "Q one"), (2, "Q two")])

    def test_typed_answer_pins_even_foreign_file(self):
        foreign, _ = agent.answers.set_answer(
            agent.answers.render_template([(1, "Foreign?")]), 1, "team guess")
        assert not agent.answers.is_stale_blank_template(
            foreign, [(1, "Real question?")])

    def test_placeholder_counts_as_untouched(self):
        content = "Q1: Old thing\nAnswer: ____________\n"
        assert agent.answers.is_stale_blank_template(content, [(1, "New thing")])


class TestEnsureAnswersFile:
    def test_creates_missing_parent_dirs(self, tmp_path):
        path = tmp_path / "home" / "stationlead" / "Desktop" / "FQ.txt"
        cli._ensure_answers_file(str(path), _q([(1, "Where is the beacon?")]))
        text = path.read_text()
        assert "Where is the beacon?" in text

    def test_replaces_stale_blank_foreign_template(self, tmp_path):
        path = tmp_path / "FQ.txt"
        path.write_text(agent.answers.render_template(
            [(1, "Saltmarsh web shell?"), (2, "Saltmarsh FTP rule?")]))
        cli._ensure_answers_file(str(path), _q([(1, "Harborline GPO?")]))
        text = path.read_text()
        assert "Harborline GPO?" in text
        assert "Saltmarsh" not in text

    def test_keeps_team_answers_even_when_stale(self, tmp_path):
        path = tmp_path / "FQ.txt"
        content, _ = agent.answers.set_answer(
            agent.answers.render_template([(1, "Foreign?")]), 1, "our answer")
        path.write_text(content)
        cli._ensure_answers_file(str(path), _q([(1, "Real?")]))
        assert "our answer" in path.read_text()

    @needs_nonroot
    def test_root_owned_dir_gives_sudo_hint_not_traceback(self, tmp_path):
        ro = tmp_path / "rootdir"
        ro.mkdir(mode=0o555)
        with pytest.raises(cli.CliError) as e:
            cli._write_answers_file(str(ro / "sub" / "FQ.txt"), "x")
        assert "cannot create the answers directory" in str(e.value)
        ro.chmod(0o755)


class TestBootPrepare:
    def _manifest(self, path, pairs):
        checks = [SimpleNamespace(
            type="forensics_answer", display_title=t,
            collect_params={"path": path, "ordinal": o}) for o, t in pairs]
        return SimpleNamespace(forensics=[object()], checks=checks)

    def test_boot_writes_into_missing_scenario_home(self, tmp_path):
        import agent.__main__ as m
        path = str(tmp_path / "home" / "librarian" / "Desktop"
                   / "Forensics-Questions.txt")
        m._prepare_forensics(self._manifest(path, [(1, "Moth plugin?")]),
                             str(tmp_path / "cfg"))
        assert "Moth plugin?" in open(path).read()

    def test_boot_replaces_stale_blank_and_keeps_answers(self, tmp_path):
        import agent.__main__ as m
        path = tmp_path / "FQ.txt"
        path.write_text(agent.answers.render_template([(1, "Old scenario?")]))
        m._prepare_forensics(self._manifest(str(path), [(1, "New?")]),
                             str(tmp_path / "cfg"))
        assert "New?" in path.read_text()

        typed, _ = agent.answers.set_answer(
            agent.answers.render_template([(1, "Old scenario?")]), 1, "kept")
        path.write_text(typed)
        m._prepare_forensics(self._manifest(str(path), [(1, "New?")]),
                             str(tmp_path / "cfg"))
        text = path.read_text()
        assert "kept" in text and "New?" not in text
