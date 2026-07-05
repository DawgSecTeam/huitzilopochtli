"""Hermetic, mocked unit tests for agent/platform/{systemd,openrc,pkg,detect}.py.

All subprocess.run calls and os.path.exists / shutil.which lookups are
mocked so these tests never touch the real system's init system or package
manager and never hit a real timeout.
"""
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from agent.platform.systemd import SystemdContext
from agent.platform.openrc import OpenRCContext
from agent.platform import pkg
from agent.platform import detect as detect_module
from agent.platform.detect import detect


def _completed(stdout="", returncode=0):
    return MagicMock(stdout=stdout, returncode=returncode)


# ---------------------------------------------------------------------------
# SystemdContext
# ---------------------------------------------------------------------------

class TestSystemdServiceActive:
    def test_active_returns_true(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   return_value=_completed("active\n", 0)) as mock_run:
            assert ctx.service_active("nginx") is True
            mock_run.assert_called_once_with(
                ["systemctl", "is-active", "nginx"],
                capture_output=True, text=True, timeout=5,
            )

    def test_inactive_output_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   return_value=_completed("inactive\n", 3)):
            assert ctx.service_active("nginx") is False

    def test_empty_output_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   return_value=_completed("", 3)):
            assert ctx.service_active("nginx") is False

    def test_active_stdout_but_nonzero_returncode_returns_false(self):
        # documented contract: requires BOTH returncode == 0 and stdout == "active"
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   return_value=_completed("active\n", 1)):
            assert ctx.service_active("nginx") is False

    def test_timeout_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="systemctl", timeout=5)):
            assert ctx.service_active("nginx") is False

    def test_file_not_found_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   side_effect=FileNotFoundError()):
            assert ctx.service_active("nginx") is False


class TestSystemdServiceEnabled:
    def test_enabled_returns_true(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   return_value=_completed("enabled\n", 0)) as mock_run:
            assert ctx.service_enabled("nginx") is True
            mock_run.assert_called_once_with(
                ["systemctl", "is-enabled", "nginx"],
                capture_output=True, text=True, timeout=5,
            )

    def test_disabled_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   return_value=_completed("disabled\n", 1)):
            assert ctx.service_enabled("nginx") is False

    def test_empty_output_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   return_value=_completed("", 1)):
            assert ctx.service_enabled("nginx") is False

    def test_timeout_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="systemctl", timeout=5)):
            assert ctx.service_enabled("nginx") is False

    def test_file_not_found_returns_false(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd.subprocess.run",
                   side_effect=FileNotFoundError()):
            assert ctx.service_enabled("nginx") is False


class TestSystemdPackageInstalled:
    def test_delegates_to_pkg_package_installed(self):
        ctx = SystemdContext()
        with patch("agent.platform.systemd._package_installed",
                   return_value=(True, "1.2.3")) as mock_pkg:
            result = ctx.package_installed("nginx")
            mock_pkg.assert_called_once_with("nginx")
            assert result == (True, "1.2.3")


# ---------------------------------------------------------------------------
# OpenRCContext
# ---------------------------------------------------------------------------

class TestOpenRCServiceActive:
    def test_started_in_output_returns_true(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   return_value=_completed(" * status: started\n", 0)) as mock_run:
            assert ctx.service_active("sshd") is True
            mock_run.assert_called_once_with(
                ["rc-service", "sshd", "status"],
                capture_output=True, text=True, timeout=5,
            )

    def test_stopped_output_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   return_value=_completed(" * status: stopped\n", 0)):
            assert ctx.service_active("sshd") is False

    def test_empty_output_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   return_value=_completed("", 1)):
            assert ctx.service_active("sshd") is False

    def test_timeout_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="rc-service", timeout=5)):
            assert ctx.service_active("sshd") is False

    def test_file_not_found_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   side_effect=FileNotFoundError()):
            assert ctx.service_active("sshd") is False


class TestOpenRCServiceEnabled:
    def test_name_present_in_show_output_returns_true(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   return_value=_completed("sshd | default\ncron | default\n", 0)) as mock_run:
            assert ctx.service_enabled("sshd") is True
            mock_run.assert_called_once_with(
                ["rc-update", "show"],
                capture_output=True, text=True, timeout=5,
            )

    def test_name_absent_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   return_value=_completed("cron | default\n", 0)):
            assert ctx.service_enabled("sshd") is False

    def test_empty_output_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   return_value=_completed("", 0)):
            assert ctx.service_enabled("sshd") is False

    def test_timeout_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="rc-update", timeout=5)):
            assert ctx.service_enabled("sshd") is False

    def test_file_not_found_returns_false(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc.subprocess.run",
                   side_effect=FileNotFoundError()):
            assert ctx.service_enabled("sshd") is False


class TestOpenRCPackageInstalled:
    def test_delegates_to_pkg_package_installed(self):
        ctx = OpenRCContext()
        with patch("agent.platform.openrc._package_installed",
                   return_value=(True, "4.5.6")) as mock_pkg:
            result = ctx.package_installed("openssh")
            mock_pkg.assert_called_once_with("openssh")
            assert result == (True, "4.5.6")


# ---------------------------------------------------------------------------
# pkg.package_installed
# ---------------------------------------------------------------------------

def _which_side_effect(present: str):
    """Return a side_effect function for shutil.which that reports only
    `present` ("dpkg"/"rpm"/"apk") as available, everything else as None."""
    def _which(name):
        return f"/usr/bin/{name}" if name == present else None
    return _which


class TestPkgDpkg:
    def test_installed_with_version(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("dpkg")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed(
                       "Package: nginx\nStatus: install ok installed\nVersion: 1.18.0-6ubuntu14\n",
                       0)) as mock_run:
            result = pkg.package_installed("nginx")
            assert result == (True, "1.18.0-6ubuntu14")
            mock_run.assert_called_once_with(
                ["dpkg", "-s", "nginx"], capture_output=True, text=True, timeout=5,
            )

    def test_not_installed_nonzero_returncode(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("dpkg")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("", 1)):
            assert pkg.package_installed("does-not-exist") == (False, None)

    def test_installed_no_version_line(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("dpkg")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("Package: nginx\nStatus: install ok installed\n", 0)):
            assert pkg.package_installed("nginx") == (True, None)


class TestPkgRpm:
    def test_installed_with_version_stripped_prefix(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("rpm")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("httpd-2.4.37-47.el8.x86_64\n", 0)) as mock_run:
            result = pkg.package_installed("httpd")
            assert result == (True, "2.4.37-47.el8.x86_64")
            mock_run.assert_called_once_with(
                ["rpm", "-q", "httpd"], capture_output=True, text=True, timeout=5,
            )

    def test_installed_without_matching_prefix_returns_raw(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("rpm")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("some-other-output\n", 0)):
            assert pkg.package_installed("httpd") == (True, "some-other-output")

    def test_installed_empty_output_returns_none_version(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("rpm")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("", 0)):
            assert pkg.package_installed("httpd") == (True, None)

    def test_not_installed(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("rpm")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("package httpd is not installed\n", 1)):
            assert pkg.package_installed("httpd") == (False, None)


class TestPkgApk:
    def test_installed_with_version(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("apk")), \
             patch("agent.platform.pkg.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _completed("openssh-8.4_p1-r3\n", 0),  # apk info -e
                _completed("openssh-8.4_p1-r3 description ...\n", 0),  # apk info
            ]
            result = pkg.package_installed("openssh")
            assert result == (True, "openssh-8.4_p1-r3 description ...")
            assert mock_run.call_args_list[0].args == (["apk", "info", "-e", "openssh"],)
            assert mock_run.call_args_list[1].args == (["apk", "info", "openssh"],)

    def test_not_installed_empty_stdout(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("apk")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("", 0)):
            assert pkg.package_installed("openssh") == (False, None)

    def test_not_installed_nonzero_returncode(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("apk")), \
             patch("agent.platform.pkg.subprocess.run",
                   return_value=_completed("", 1)):
            assert pkg.package_installed("openssh") == (False, None)

    def test_installed_but_info_lookup_fails_version_none(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("apk")), \
             patch("agent.platform.pkg.subprocess.run") as mock_run:
            mock_run.side_effect = [
                _completed("openssh-8.4_p1-r3\n", 0),  # apk info -e succeeds
                _completed("", 1),  # apk info fails
            ]
            assert pkg.package_installed("openssh") == (True, None)


class TestPkgNoManagerPresent:
    def test_no_known_package_manager_returns_false_none(self):
        with patch("agent.platform.pkg.shutil.which", return_value=None), \
             patch("agent.platform.pkg.subprocess.run") as mock_run:
            assert pkg.package_installed("anything") == (False, None)
            mock_run.assert_not_called()


class TestPkgSubprocessFailureModes:
    def test_timeout_expired_treated_as_not_found(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("dpkg")), \
             patch("agent.platform.pkg.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="dpkg", timeout=5)):
            assert pkg.package_installed("nginx") == (False, None)

    def test_file_not_found_treated_as_not_found(self):
        with patch("agent.platform.pkg.shutil.which", side_effect=_which_side_effect("rpm")), \
             patch("agent.platform.pkg.subprocess.run",
                   side_effect=FileNotFoundError()):
            assert pkg.package_installed("httpd") == (False, None)


# ---------------------------------------------------------------------------
# detect.detect()
# ---------------------------------------------------------------------------

class TestDetect:
    def test_systemd_present_returns_systemd_context(self):
        with patch("agent.platform.detect.os.path.exists",
                   side_effect=lambda p: p == "/run/systemd/system"):
            ctx = detect()
            assert isinstance(ctx, SystemdContext)
            assert not isinstance(ctx, OpenRCContext)

    def test_systemd_absent_returns_openrc_context(self):
        with patch("agent.platform.detect.os.path.exists", return_value=False):
            ctx = detect()
            assert isinstance(ctx, OpenRCContext)
            assert not isinstance(ctx, SystemdContext)

    def test_checks_expected_path(self):
        with patch("agent.platform.detect.os.path.exists",
                   return_value=False) as mock_exists:
            detect()
            mock_exists.assert_called_once_with("/run/systemd/system")
