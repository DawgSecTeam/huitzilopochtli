"""Provider abstraction: how boxbuilder reaches a box and packages it.

This is the seam that makes the VM environment pluggable. v1 ships SshProvider
(box already running, reached over SSH). Future providers (qemu, proxmox) boot
their own VM and export an image.

Design notes:
  - A BoxHandle is the single source of truth for the box's addr/user/password.
    When boxbuilder drives `nakon deploy`, it derives a one-machine config whose
    address comes from the handle (see nakon.derive_deploy_config), NOT from the
    agent's nakon config. This keeps addresses in sync and lets dynamic-IP
    providers (qemu/proxmox) work without the agent knowing the address up front.
  - `export()` returns an ExportResult because not every provider can self-export
    (SshProvider can't snapshot a remote box it doesn't own). Those return
    mode="manual" with instructions; the caller surfaces that in --json.
"""
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RunResult:
    """Result of a remote command."""
    exit_status: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_status == 0


@dataclass
class ExportResult:
    """Result of packaging the box.

    mode == "wrote": the image at `path` is ready to distribute.
    mode == "manual": the provider can't self-export; `instructions` tells the
        operator what to do (e.g. snapshot from the hypervisor). `path` is None.
    """
    mode: str  # "wrote" | "manual"
    path: Optional[str] = None
    format: Optional[str] = None
    instructions: Optional[str] = None


class BoxHandle(ABC):
    """A live, reachable box. Closed via close()."""

    name: str
    addr: str
    user: str
    password: str
    port: int

    @abstractmethod
    def run(self, cmd: str, *, timeout: int = 1800, sudo: bool = True) -> RunResult:
        """Run a shell command on the box. sudo wraps with `sudo -S` using the
        handle's password. Returns the exit status + combined output."""

    @abstractmethod
    def put(self, local: str, remote: str, mode: Optional[int] = None) -> None:
        """Upload a local file to a remote path. If mode given, chmod it."""

    @abstractmethod
    def install_init(self, kind: str, mode: str = "honor") -> None:
        """Install + enable the huitzilopochtli-agent init unit.
        kind is one of: 'systemd', 'openrc', 'none' (none = skip, the operator
        will wire it up). Copies the template from packaging/ and runs the
        enable commands from the templates in packaging/ (huitzilopochtli-agent.*).
        mode is 'honor' or 'ranked' (BoxSpec.mode). Honor mode's agent runs
        the checks once and exits (see packaging/huitzilopochtli-agent.service's
        comments); on systemd, this also installs+enables the paired
        huitzilopochtli-agent.timer so the report re-checks periodically
        without operator action. Ranked mode's agent already loops forever
        on its own and does not need the timer."""

    @abstractmethod
    def export(self, out_path: str, fmt: str = "ova") -> ExportResult:
        """Package the box for distribution. See ExportResult."""

    def close(self) -> None:
        """Release any connection. Default no-op."""


class BoxProvider(ABC):
    """Creates a BoxHandle for a target environment."""

    name: str

    @abstractmethod
    def start(self, cfg: dict) -> BoxHandle:
        """Ensure the box is reachable and return a handle to it. `cfg` is
        provider-specific (e.g. ssh: {host,port,user,password})."""

    def stop(self, handle: BoxHandle) -> None:
        """Optional teardown. Default: just close the handle."""
        handle.close()


# --- registry -------------------------------------------------------------
# Simple name -> class registry so providers can be selected by string without
# importing every transport (which may pull heavy deps like paramiko).
_REGISTRY: dict = {}


def register_provider(cls):
    """Decorator: register a BoxProvider subclass under its .name."""
    name = getattr(cls, "name", None)
    if not name:
        raise ValueError(f"{cls.__name__} has no .name")
    _REGISTRY[name] = cls
    return cls


def load_provider(name: str, cfg: dict) -> BoxProvider:
    """Instantiate a provider by name. Raises a helpful error if unknown or
    if the provider's optional deps aren't installed."""
    if name not in _REGISTRY:
        raise ValueError(
            f"unknown provider {name!r}; available: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]()


def available_providers() -> list:
    return sorted(_REGISTRY)
