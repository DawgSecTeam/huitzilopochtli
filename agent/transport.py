"""Push-only transport client with queue-and-forward. Ranked mode only.
See architecture.md §9.5.

FROZEN signature (agreed for parallel build); body is a PHASE 1 TASK.
"""
from common.schema import Bundle, CheckinResponse


class TransportClient:
    def __init__(self, engine_url: str, identity: "agent.identity.Identity",
                 queue_path: str):
        """queue_path is an append-only local file used to persist signed
        bundles that failed to send, preserving seq/evidence, for retry on
        the next cycle (§9.5)."""
        raise NotImplementedError

    def checkin(self, bundle: Bundle) -> CheckinResponse:
        """Sign bundle's canonical form, POST to <engine_url>/checkin over TLS.

        On success: flush any previously-queued bundles first (in seq order),
        then send `bundle`, return the parsed CheckinResponse.
        On network failure: append `bundle` to the queue file and return None.
        """
        raise NotImplementedError
