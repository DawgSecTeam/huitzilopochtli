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


def test_agent_start_failures_are_fatal(monkeypatch):
    monkeypatch.setattr(join_mod, "os", types.SimpleNamespace(name="posix"))

    def boom(*a, **kw):
        raise OSError("no systemd here")

    monkeypatch.setattr(join_mod, "subprocess", types.SimpleNamespace(run=boom))
    try:
        join_mod._start_agent()
    except join_mod.JoinError as exc:
        assert "agent service" in str(exc)
    else:
        raise AssertionError("a failed agent start must fail the join")


def test_windows_agent_start_failure_is_fatal(monkeypatch):
    monkeypatch.setattr(join_mod, "os", types.SimpleNamespace(name="nt"))

    class _Fail:
        returncode = 1
        stdout = "ERROR: access denied"
        stderr = ""

    monkeypatch.setattr(join_mod, "subprocess",
                        types.SimpleNamespace(run=lambda *a, **kw: _Fail()))
    try:
        join_mod._start_agent()
    except join_mod.JoinError as exc:
        assert "Windows agent task" in str(exc)
    else:
        raise AssertionError("a failed schtasks call must fail the join")


def test_join_retries_a_busy_engine(monkeypatch):
    """A 503 from the verify gate is transient, not a dead player slot."""
    import io
    import urllib.error
    calls = []

    class _Resp:
        def read(self):
            return b'{"player_name": "Ada"}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, context=None, timeout=None):
        calls.append(1)
        if len(calls) < 3:
            raise urllib.error.HTTPError(
                req.full_url, 503, "busy", {},
                io.BytesIO(b'{"error": "engine busy verifying signatures; retry"}'))
        return _Resp()

    monkeypatch.setattr(join_mod.signing, "sign", lambda *a: b"sig")
    monkeypatch.setattr(join_mod.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(join_mod.time, "sleep", lambda _s: None)
    out = join_mod._post_join("http://engine", {"box_id": "b1"}, b"k" * 32)
    assert out == {"player_name": "Ada"}
    assert len(calls) == 3


def test_join_does_not_retry_a_bad_code(monkeypatch):
    import io
    import urllib.error
    calls = []

    def fake_urlopen(req, context=None, timeout=None):
        calls.append(1)
        raise urllib.error.HTTPError(
            req.full_url, 403, "forbidden", {},
            io.BytesIO(b'{"error": "invalid join code"}'))

    monkeypatch.setattr(join_mod.signing, "sign", lambda *a: b"sig")
    monkeypatch.setattr(join_mod.urllib.request, "urlopen", fake_urlopen)
    try:
        join_mod._post_join("http://engine", {"box_id": "b1"}, b"k" * 32)
    except join_mod.JoinError as exc:
        assert "invalid join code" in str(exc)
    else:
        raise AssertionError("403 should raise")
    assert len(calls) == 1
