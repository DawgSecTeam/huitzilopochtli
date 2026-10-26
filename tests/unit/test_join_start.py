"""`huitz join` must start the agent on both platforms."""
import types

import agent.join as join_mod


class _Ok:
    returncode = 0


def test_windows_join_enables_and_runs_the_scheduled_task(monkeypatch):
    calls = []
    monkeypatch.setattr(join_mod, "os", types.SimpleNamespace(name="nt"))
    monkeypatch.setattr(join_mod, "subprocess",
                        types.SimpleNamespace(run=lambda args, **kw: calls.append(args) or _Ok()))
    join_mod._start_agent()
    assert calls == [
        ["schtasks", "/Change", "/TN", "HuitzilopochtliAgent", "/ENABLE"],
        ["schtasks", "/Run", "/TN", "HuitzilopochtliAgent"],
    ]


def test_linux_join_enables_the_first_working_unit(monkeypatch):
    calls = []
    monkeypatch.setattr(join_mod, "os", types.SimpleNamespace(name="posix"))
    monkeypatch.setattr(join_mod, "subprocess",
                        types.SimpleNamespace(run=lambda args, **kw: calls.append(args) or _Ok()))
    join_mod._start_agent()
    assert calls == [["systemctl", "enable", "--now",
                      "huitzilopochtli-agent.service"]]


def test_agent_start_failures_are_not_fatal(monkeypatch):
    monkeypatch.setattr(join_mod, "os", types.SimpleNamespace(name="posix"))

    def boom(*a, **kw):
        raise OSError("no systemd here")

    monkeypatch.setattr(join_mod, "subprocess", types.SimpleNamespace(run=boom))
    join_mod._start_agent()  # must not raise
