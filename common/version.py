"""Version constants stamped on every payload. See architecture.md §14.3."""

AGENT_VERSION = "1.0.0"

# common.schema.SCHEMA_VERSION is the source of truth for wire schema
# compatibility; re-exported here for convenience where only version.py
# is imported.
from common.schema import SCHEMA_VERSION  # noqa: E402,F401

__all__ = ["AGENT_VERSION", "SCHEMA_VERSION"]
