"""Unit tests for boxbuilder.providers base + registry."""
import pytest

from boxbuilder.providers import (
    available_providers, load_provider,
)
from boxbuilder.providers.base import (
    BoxHandle, BoxProvider, ExportResult, RunResult, register_provider,
)


def test_runresult_ok():
    assert RunResult(0).ok is True
    assert RunResult(1).ok is False


def test_export_result_modes():
    wrote = ExportResult(mode="wrote", path="/x.ova", format="ova")
    assert wrote.mode == "wrote"
    manual = ExportResult(mode="manual", instructions="do it yourself")
    assert manual.path is None


def test_register_and_load():
    @register_provider
    class _TestProv(BoxProvider):
        name = "_test_tmp"

        def start(self, cfg):
            class _H(BoxHandle):
                name = "t"
                addr = "1.1.1.1"
                user = "u"
                password = "p"
                port = 22

                def run(self, cmd, *, timeout=1800, sudo=True):
                    return RunResult(0)

                def put(self, local, remote, mode=None):
                    pass

                def install_init(self, kind, mode="honor"):
                    pass

                def export(self, out_path, fmt="ova"):
                    return ExportResult(mode="manual")

            return _H()

    assert "_test_tmp" in available_providers()
    prov = load_provider("_test_tmp", {})
    handle = prov.start({})
    assert handle.run("x").ok


def test_load_unknown_provider():
    with pytest.raises(ValueError, match="unknown provider"):
        load_provider("definitely-not-real", {})


def test_register_requires_name():
    with pytest.raises(ValueError, match="no .name"):
        @register_provider
        class _NoName(BoxProvider):
            def start(self, cfg):
                pass


def test_ssh_provider_registered_without_paramiko():
    """Importing the providers package registers ssh; paramiko is only needed at
    connect() time, so this must not require paramiko installed."""
    assert "ssh" in available_providers()


def test_ssh_run_shuts_down_stdin_write_side():
    """run() must close the stdin write side after feeding the sudo password
    (and for non-sudo commands too), else a remote command that reads stdin
    hangs recv_exit_status() forever."""
    from unittest import mock

    from boxbuilder.providers.ssh import SshHandle

    handle = SshHandle(name="b", addr="1.1.1.1", user="sysadmin",
                       password="pw", port=22)

    class FakeChannel:
        def __init__(self):
            self.shutdown_write_calls = 0

        def shutdown_write(self):
            self.shutdown_write_calls += 1

        def recv_exit_status(self):
            return 0

    class FakeStream:
        def __init__(self, ch):
            self.channel = ch  # paramiko exposes channel as a property
            self._writes = []

        def write(self, data):
            self._writes.append(data)

        def flush(self):
            pass

        def read(self, *args):
            return b""

    client = mock.Mock()

    def run_with(sudo):
        ch = FakeChannel()
        stdin, stdout, stderr = FakeStream(ch), FakeStream(ch), FakeStream(ch)
        client.exec_command.return_value = (stdin, stdout, stderr)
        with mock.patch.object(handle, "_client", client):
            res = handle.run("whoami", timeout=5, sudo=sudo)
        return res, stdin, ch

    res, stdin, ch = run_with(sudo=True)
    assert res.ok
    assert stdin._writes == ["pw\n"]  # sudo password fed over stdin
    assert ch.shutdown_write_calls == 1

    res2, stdin2, ch2 = run_with(sudo=False)
    assert res2.ok
    assert stdin2._writes == []  # no password on the non-sudo path
    assert ch2.shutdown_write_calls == 1
