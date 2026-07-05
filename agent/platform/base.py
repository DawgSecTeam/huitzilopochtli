"""Platform abstraction contract. See architecture.md §9.3.

FROZEN — every check that needs service/package facts (service_state.py,
package.py) and every platform strategy module builds against this ABC.
"""
from abc import ABC, abstractmethod


class PlatformContext(ABC):
    """Cached per-run, produced once by agent.platform.detect.detect() and
    passed into every Check.collect() call."""

    @abstractmethod
    def service_active(self, name: str) -> bool: ...

    @abstractmethod
    def service_enabled(self, name: str) -> bool: ...

    @abstractmethod
    def package_installed(self, name: str) -> tuple:
        """Returns (installed: bool, version: str | None)."""
        ...
