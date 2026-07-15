"""Tests for the closed adversary action vocabulary (architecture.md §12.2).

Covers agent/adversary/actions.py and agent/adversary/executor.py. The
security property under test: exactly 3 allowlisted actions exist
(flush_firewall, kill_service, drop_inert_artifact), none of them provide a
network-egress or shell-injection primitive, and unknown actions fail
closed (raise) rather than silently no-op.
"""
import os
import stat
import re
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from agent.adversary import actions
from agent.adversary.actions import ACTIONS
from agent.adversary import executor
from common.schema import Directive


ACTIONS_SRC = Path(actions.__file__)
EXECUTOR_SRC = Path(executor.__file__)


class FakeCtx:
    """Stand-in for agent.platform.base.PlatformContext; actions don't
    actually touch it in the current implementation."""
    pass


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------

def test_actions_registry_has_exactly_three_entries():
    assert set(ACTIONS.keys()) == {
        "flush_firewall",
        "kill_service",
        "drop_inert_artifact",
    }
    assert len(ACTIONS) == 3


# ---------------------------------------------------------------------------
# drop_inert_artifact
# ---------------------------------------------------------------------------

def test_drop_inert_artifact_writes_inert_nonexecutable_file(tmp_path, monkeypatch):
    # drop_inert_artifact confines writes under a dedicated sandbox base dir
    # (overridable via env). Point the sandbox at tmp_path and use a relative
    # path; the marker lands inside the sandbox.
    monkeypatch.setenv("HUITZILOPOCHTLI_ARTIFACT_DIR", str(tmp_path))
    target = tmp_path / "marker.txt"
    ctx = FakeCtx()

    ACTIONS["drop_inert_artifact"]({"path": "marker.txt"}, ctx)

    assert target.exists()

    content = target.read_text(encoding="utf-8")
    assert content.strip() != ""
    assert not content.startswith("#!")
    assert "\x00" not in content  # plain text, not binary/executable payload

    mode = os.stat(target).st_mode
    exec_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    assert mode & exec_bits == 0

    # Source explicitly sets 0o644.
    assert stat.S_IMODE(mode) == 0o644


def test_drop_inert_artifact_missing_path_is_noop(tmp_path):
    # No "path" key at all -> should not raise, and should not write anything.
    ctx = FakeCtx()
    ACTIONS["drop_inert_artifact"]({}, ctx)
    # Nothing to assert on disk since no path was given; just confirm no
    # exception propagated (best-effort action).


# ---------------------------------------------------------------------------
# kill_service
# ---------------------------------------------------------------------------

def test_kill_service_calls_systemctl_when_systemd_present():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.os.path.exists", return_value=True), \
         patch("agent.adversary.actions.subprocess.run") as mock_run:
        ACTIONS["kill_service"]({"service": "sshd"}, ctx)

    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    cmd = args[0]
    assert cmd == ["systemctl", "stop", "sshd"]
    assert kwargs.get("check") is False
    assert "shell" not in kwargs or kwargs["shell"] is False


def test_kill_service_calls_rc_service_when_no_systemd():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.os.path.exists", return_value=False), \
         patch("agent.adversary.actions.subprocess.run") as mock_run:
        ACTIONS["kill_service"]({"service": "cron"}, ctx)

    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    cmd = args[0]
    assert cmd == ["rc-service", "cron", "stop"]
    assert kwargs.get("check") is False


def test_kill_service_missing_service_is_noop():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.subprocess.run") as mock_run:
        ACTIONS["kill_service"]({}, ctx)
    mock_run.assert_not_called()


def test_kill_service_swallows_subprocess_exception():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.os.path.exists", return_value=True), \
         patch("agent.adversary.actions.subprocess.run",
               side_effect=OSError("boom")):
        # Must not propagate.
        ACTIONS["kill_service"]({"service": "sshd"}, ctx)


# ---------------------------------------------------------------------------
# flush_firewall
# ---------------------------------------------------------------------------

def test_flush_firewall_uses_iptables_when_present():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.shutil.which",
               side_effect=lambda tool: "/usr/sbin/iptables" if tool == "iptables" else None), \
         patch("agent.adversary.actions.subprocess.run") as mock_run:
        ACTIONS["flush_firewall"]({}, ctx)

    calls = [c.args[0] for c in mock_run.call_args_list]
    assert ["iptables", "-F"] in calls
    assert ["iptables", "-X"] in calls
    for c in mock_run.call_args_list:
        assert c.kwargs.get("check") is False
        assert "shell" not in c.kwargs or c.kwargs["shell"] is False


def test_flush_firewall_falls_back_to_nft():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.shutil.which",
               side_effect=lambda tool: "/usr/sbin/nft" if tool == "nft" else None), \
         patch("agent.adversary.actions.subprocess.run") as mock_run:
        ACTIONS["flush_firewall"]({}, ctx)

    mock_run.assert_called_once_with(
        ["nft", "flush", "ruleset"], check=False, capture_output=True, timeout=10
    )


def test_flush_firewall_noop_when_neither_tool_present():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.shutil.which", return_value=None), \
         patch("agent.adversary.actions.subprocess.run") as mock_run:
        ACTIONS["flush_firewall"]({}, ctx)
    mock_run.assert_not_called()


def test_flush_firewall_swallows_subprocess_exception():
    ctx = FakeCtx()
    with patch("agent.adversary.actions.shutil.which",
               side_effect=lambda tool: "/usr/sbin/iptables" if tool == "iptables" else None), \
         patch("agent.adversary.actions.subprocess.run",
               side_effect=RuntimeError("boom")):
        ACTIONS["flush_firewall"]({}, ctx)


# ---------------------------------------------------------------------------
# executor.execute dispatch
# ---------------------------------------------------------------------------

def test_execute_dispatches_to_correct_action():
    ctx = FakeCtx()
    directive = Directive(event_id="e1", action="drop_inert_artifact",
                            params={"path": "/tmp/whatever-not-used"})

    fake_fn = MagicMock()
    with patch.dict(executor.ACTIONS, {"drop_inert_artifact": fake_fn}):
        executor.execute(directive, ctx)

    fake_fn.assert_called_once_with(directive.params, ctx)


def test_execute_dispatches_kill_service_with_params():
    ctx = FakeCtx()
    directive = Directive(event_id="e2", action="kill_service",
                            params={"service": "nginx"})

    fake_fn = MagicMock()
    with patch.dict(executor.ACTIONS, {"kill_service": fake_fn}):
        executor.execute(directive, ctx)

    fake_fn.assert_called_once_with({"service": "nginx"}, ctx)


def test_execute_unknown_action_raises_keyerror():
    ctx = FakeCtx()
    directive = Directive(event_id="e3", action="exfiltrate_data", params={})

    with pytest.raises(KeyError):
        executor.execute(directive, ctx)


def test_execute_unknown_action_does_not_run_any_action():
    ctx = FakeCtx()
    directive = Directive(event_id="e4", action="not_a_real_action", params={})

    fakes = {name: MagicMock() for name in ACTIONS}
    with patch.dict(executor.ACTIONS, fakes, clear=True):
        with pytest.raises(KeyError):
            executor.execute(directive, ctx)
    for fn in fakes.values():
        fn.assert_not_called()


# ---------------------------------------------------------------------------
# Security-critical: no network egress / shell-injection primitives, ever.
# ---------------------------------------------------------------------------

FORBIDDEN_SUBSTRINGS = [
    "socket.socket",
    "socket.connect",
    "http.client",
    "urllib.request",
    "requests.",
    "shell=True",
]


@pytest.mark.parametrize("path", [ACTIONS_SRC, EXECUTOR_SRC])
def test_no_forbidden_network_or_shell_primitives(path):
    source = path.read_text(encoding="utf-8")
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden not in source, (
            f"forbidden substring {forbidden!r} found in {path} -- "
            "this module must never gain a network-egress or shell-injection "
            "primitive (architecture.md §12.2 / §2.7)"
        )
