"""Version constants stamped on every payload. See architecture.md §14.3."""

AGENT_VERSION = "0.1.0"

# common.schema.SCHEMA_VERSION is the source of truth for wire schema
# compatibility; re-exported here for convenience where only version.py
# is imported.
from common.schema import SCHEMA_VERSION  # noqa: E402,F401
