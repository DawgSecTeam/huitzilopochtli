"""Box providers. Importing this package registers the built-in providers."""
from boxbuilder.providers.base import (
    BoxHandle, BoxProvider, ExportResult, RunResult,
    available_providers, load_provider, register_provider,
)


def _register_builtins() -> None:
    """Import each built-in provider so its @register_provider runs; guarded
    so a missing optional dep can't break importing the base abstractions."""
    try:
        import importlib
        importlib.import_module("boxbuilder.providers.ssh")
    except Exception:
        # Importing ssh is cheap (paramiko loads in connect()); guard anyway
        # so a broken provider never blocks the registry.
        pass


_register_builtins()

__all__ = [
    "BoxHandle", "BoxProvider", "ExportResult", "RunResult",
    "available_providers", "load_provider", "register_provider",
]
