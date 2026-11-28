"""Version constants stamped on every payload. See architecture.md §14.3."""

AGENT_VERSION = "1.2.0"

from common.schema import SCHEMA_VERSION  # noqa: E402,F401  (schema.py is the source of truth)

__all__ = ["AGENT_VERSION", "SCHEMA_VERSION"]
