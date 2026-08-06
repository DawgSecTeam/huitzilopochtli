"""Box providers. Importing this package registers the built-in providers."""
from boxbuilder.providers.base import (
    BoxHandle, BoxProvider, ExportResult, RunResult,
    available_providers, load_provider, register_provider,
)


def _register_builtins() -> None:
    """Import each built-in provider so its @register_provider runs. Done lazily
    and guarded so a missing optional dep (e.g. paramiko) doesn't break importing
    the base abstractions."""
    try:
        from boxbuilder.providers import ssh as _ssh  # noqa: F401
    except Exception:
        # SshProvider registration doesn't import paramiko at module scope (it's
        # imported lazily in connect()), so this should never fail on import. But
        # guard anyway so a broken provider never blocks the registry.
        pass


_register_builtins()

__all__ = [
    "BoxHandle", "BoxProvider", "ExportResult", "RunResult",
    "available_providers", "load_provider", "register_provider",
]
