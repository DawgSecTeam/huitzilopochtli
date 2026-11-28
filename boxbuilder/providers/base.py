"""Provider abstraction: how boxbuilder reaches a box and packages it.

The BoxHandle is the single source of truth for addr/user/password: the
nakon deploy config derives its address from the handle, so dynamic-IP
providers work."""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
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
    """Packaging result: mode "wrote" -> image ready at `path`; mode
    "manual" -> the provider can't self-export, `instructions` tell the
    operator what to do, `path` is None."""
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
    def install_init(self, kind: str, mode: str = "honor",
                     start_agent: bool = True) -> None:
        """Install + enable the agent's init unit ('systemd' | 'openrc' |
        'windows' | 'none') from the packaging/ templates; honor also wires
        the paired re-grade timer. start_agent=False installs it stopped —
        a ranked competition box starts via the player's `huitz join`."""

    @abstractmethod
    def export(self, out_path: str, fmt: str = "ova") -> ExportResult:
        """Package the box for distribution. See ExportResult."""

    def close(self) -> None:
        """Release any connection. Default no-op."""


_STAGE_PREFIX = "/tmp/huitzilopochtli-stage."
_STAGE_DIR_RE = re.compile(r"^/tmp/huitzilopochtli-stage\.[A-Za-z0-9]+$")


def stage_path(handle, name: str) -> str:
    """A private remote staging path for files that root will `sudo
    install`. A fixed /tmp name would let any local account pre-create it and
    swap contents between upload and install; a per-handle mktemp -d (0700)
    closes that race."""
    stage_dir = getattr(handle, "_stage_dir", None)
    if stage_dir is None:
        res = handle.run(f"mktemp -d {_STAGE_PREFIX}XXXXXX", sudo=False)
        stage_dir = res.stdout.strip()
        if not res.ok or not _STAGE_DIR_RE.fullmatch(stage_dir):
            raise RuntimeError(
                f"could not create a private staging dir on {handle.addr}: "
                f"{(res.stderr or res.stdout).strip()}"
            )
        handle._stage_dir = stage_dir
    return f"{stage_dir}/{name}"


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
