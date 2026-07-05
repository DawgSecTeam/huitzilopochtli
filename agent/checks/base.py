"""Check plugin base class + registry. See architecture.md §9.1.

FROZEN — this is the contract every check-type module builds against.
Do not change Check or the registry mechanism.
"""
from abc import ABC, abstractmethod

from common.schema import CheckSpec, Evidence


class Check(ABC):
    """One check-type implementation. A subclass is entirely self-contained:
    it must not import another check module.

    collect() must be read-only / side-effect-free with respect to the scored
    system (§9.1) — the adversary executor is the only component permitted to
    mutate system state.
    """

    type_key: str  # unique registry key, e.g. "file_regex"

    @abstractmethod
    def collect(self, spec: CheckSpec, ctx: "PlatformContext") -> Evidence: ...


CHECKS: dict = {}


def register(type_key: str):
    """Class decorator: register a Check subclass under `type_key`."""
    def deco(cls):
        CHECKS[type_key] = cls
        return cls
    return deco
