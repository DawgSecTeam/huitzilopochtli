"""Unit tests for agent/notify.py: score baseline diffing + best-effort alerts.

The subprocess shell-outs are recorded via a fake agent.notify._run (never
executed), and _live_sessions is pinned so tests never touch a real desktop
session or pop a toast on the build machine.
"""
import json
import os

import pytest

from agent import notify


@pytest.fixture
def state_path(tmp_path):
    # consume_delta derives the state file from the report path; any temp
    # report path exercises that derivation.
    return notify.state_path_for(str(tmp_path / "report.html"))


# --- baseline diffing (consume_delta) ---------------------------------------

def test_first_run_returns_none_and_baselines(state_path):
    """No baseline yet -> None (silent) but the baseline must be recorded."""
    assert notify.consume_delta(state_path, 50, "v1") is None
    assert notify._load_state(state_path) == {
        "total": 50, "scenario_version": "v1",
    }


def test_gain_and_penalty_deltas(state_path):
    assert notify.consume_delta(state_path, 50, "v1") is None
    assert notify.consume_delta(state_path, 65, "v1") == 15
    assert notify.consume_delta(state_path, 60, "v1") == -5


def test_zero_delta_is_zero_not_none(state_path):
    """0 means 'compared, unchanged' (announce skips it); None means 'no
    baseline to compare against'. They are different facts."""
    notify.consume_delta(state_path, 50, "v1")
    assert notify.consume_delta(state_path, 50, "v1") == 0


def test_scenario_version_change_resets_baseline(state_path):
    """A rebuilt scenario changes the scoring surface; the first grade of the
    new scenario must not be reported as a gain/loss against the old one."""
    notify.consume_delta(state_path, 50, "v1")
    assert notify.consume_delta(state_path, 10, "v2") is None
    assert notify.consume_delta(state_path, 12, "v2") == 2


def test_corrupt_state_file_treated_as_no_baseline(state_path):
    with open(state_path, "w", encoding="utf-8") as f:
        f.write("{definitely not json")
    assert notify.consume_delta(state_path, 50, "v1") is None


def test_malformed_state_fields_treated_as_no_baseline(state_path):
    for bad in (
        {"total": "50", "scenario_version": "v1"},   # non-int total
        {"total": True, "scenario_version": "v1"},   # bool is not an int here
        {"total": 50, "scenario_version": 1},        # non-str version
        {"total": 50},                               # missing version
        [50, "v1"],                                  # wrong container
    ):
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(bad, f)
        assert notify.consume_delta(state_path, 50, "v1") is None, bad


def test_unwritable_state_dir_does_not_raise(tmp_path):
    locked = tmp_path / "ro"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        state_path = notify.state_path_for(str(locked / "report.html"))
        # Silent baseline failure, never an exception.
        assert notify.consume_delta(state_path, 50, "v1") is None
    finally:
        locked.chmod(0o700)


# --- announce (with shelled-out commands recorded, not run) ------------------

class _Recorder:
    """Stands in for agent.notify._run, recording argv instead of exec'ing."""

    def __init__(self, ok=True):
        self.calls = []
        self.ok = ok

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        return self.ok

    def wavs(self):
        return [c for c in self.calls if c[-1].endswith(".wav")]

    def toast(self):
        return next(c for c in self.calls if "notify-send" in c)


@pytest.fixture
def sessions(monkeypatch):
    users = [("sysadmin", 12345)]
    monkeypatch.setattr(notify, "_live_sessions", lambda: users)
    return users


def test_announce_gain_plays_sound_and_toast(monkeypatch, sessions):
    rec = _Recorder()
    monkeypatch.setattr(notify, "_run", rec)
    notify.announce(10, 85, title="Observatory")

    play = rec.wavs()[0]
    assert play[-1] == "/tmp/huitz-gain.wav"
    # play chain drops into the user's live session (sudo -u + session env)
    assert play[:4] == ["sudo", "-u", "sysadmin", "env"]
    assert "XDG_RUNTIME_DIR=/run/user/12345" in play
    assert "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/12345/bus" in play

    toast = rec.toast()
    ns = toast.index("notify-send")
    assert toast[toast.index("-u", ns) + 1] == "normal"
    assert "Observatory — points gained" in toast
    assert any("+10 pts" in part for part in toast)


def test_announce_penalty_uses_alarm_and_critical_urgency(monkeypatch, sessions):
    rec = _Recorder()
    monkeypatch.setattr(notify, "_run", rec)
    notify.announce(-5, 80, title="Observatory")

    assert rec.wavs()[0][-1] == "/tmp/huitz-penalty.wav"
    toast = rec.toast()
    ns = toast.index("notify-send")
    assert toast[toast.index("-u", ns) + 1] == "critical"
    assert "penalty applied" in " ".join(toast)
    assert any("a scored setting was undone" in part for part in toast)


def test_announce_extracts_the_embedded_sounds(monkeypatch, sessions):
    """The temp wav must byte-match the vendored asset and be world-readable,
    so the desktop user's player can open a root-written file."""
    import agent.sounds
    rec = _Recorder()
    monkeypatch.setattr(notify, "_run", rec)
    notify.announce(1, 2, title="T")
    path = rec.wavs()[0][-1]
    with open(path, "rb") as f:
        assert f.read() == agent.sounds.wave_bytes("gain")
    assert os.stat(path).st_mode & 0o444 == 0o444


def test_announce_dbus_send_fallback_when_notify_send_missing(
        monkeypatch, sessions):
    rec = _Recorder(ok=False)
    monkeypatch.setattr(notify, "_run", rec)
    notify.announce(-2, 20, title="T")
    fallback = next(
        c for c in rec.calls if "org.freedesktop.Notifications.Notify" in c
    )
    assert "--session" in fallback
    assert any(part == "string:T — penalty applied" for part in fallback)


def test_announce_no_session_still_falls_back_to_root_playback(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(notify, "_run", rec)
    monkeypatch.setattr(notify, "_live_sessions", lambda: [])
    notify.announce(3, 30, title="T")
    play = rec.wavs()[0]
    assert play[0] != "sudo"  # no user session to drop into
    assert not any("notify-send" in c for c in rec.calls)


def test_announce_all_tools_missing_is_silent(monkeypatch, sessions):
    rec = _Recorder(ok=False)
    monkeypatch.setattr(notify, "_run", rec)
    notify.announce(-1, 1, title="T")  # must not raise
    assert rec.calls  # it did try the whole chain


def test_announce_disabled_or_zero_is_a_noop(monkeypatch, sessions):
    rec = _Recorder()
    monkeypatch.setattr(notify, "_run", rec)
    notify.announce(10, 85, title="T", enabled=False)
    notify.announce(0, 85, title="T")
    assert rec.calls == []


def test_announce_never_raises(monkeypatch, sessions, capsys):
    def explode(cmd, timeout):
        raise RuntimeError("boom")
    monkeypatch.setattr(notify, "_run", explode)
    notify.announce(5, 55, title="T")  # §9.1: cosmetics must not stall a run
    assert "WARNING" in capsys.readouterr().err


def test_copy_fallback_title():
    summary, _, _ = notify._copy(1, 10, "")
    assert summary.startswith("Scoring engine —")
