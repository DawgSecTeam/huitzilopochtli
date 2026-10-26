"""`tcp_port` check type — generic service liveness probe.

collect_params: {"host": str, "port": int}.
Evidence.raw shape: {"open": bool, "error": str | null}.
"""
import socket
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("tcp_port")
class TcpPortCheck(Check):
    type_key = "tcp_port"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        host = spec.collect_params.get("host", "127.0.0.1")
        port = spec.collect_params.get("port")
        collected_monotonic = time.monotonic()
        collected_wall_claim = time.time()
        if not isinstance(host, str) or not host:
            return Evidence(
                check_id=spec.id, check_type=self.type_key, host_id=spec.host_id,
                status=CollectorStatus.ERROR, raw={"open": False, "error": "bad host"},
                reason="collect_params.host must be a non-empty string",
                collected_monotonic=collected_monotonic,
                collected_wall_claim=collected_wall_claim,
            )
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            return Evidence(
                check_id=spec.id, check_type=self.type_key, host_id=spec.host_id,
                status=CollectorStatus.ERROR, raw={"open": False, "error": "bad port"},
                reason="collect_params.port must be an integer in 1..65535",
                collected_monotonic=collected_monotonic,
                collected_wall_claim=collected_wall_claim,
            )
        try:
            sock = socket.create_connection((host, port), timeout=spec.timeout_s)
            sock.close()
            return Evidence(
                check_id=spec.id, check_type=self.type_key, host_id=spec.host_id,
                status=CollectorStatus.OK, raw={"open": True, "error": None},
                reason=f"connected to {host}:{port}",
                collected_monotonic=collected_monotonic,
                collected_wall_claim=collected_wall_claim,
            )
        except OSError as exc:
            return Evidence(
                check_id=spec.id, check_type=self.type_key, host_id=spec.host_id,
                status=CollectorStatus.OK, raw={"open": False, "error": str(exc)},
                reason=f"connection refused to {host}:{port}: {exc}",
                collected_monotonic=collected_monotonic,
                collected_wall_claim=collected_wall_claim,
            )
        except Exception as exc:  # noqa: BLE001 - collector never raises
            return Evidence(
                check_id=spec.id, check_type=self.type_key, host_id=spec.host_id,
                status=CollectorStatus.ERROR, raw={"open": False, "error": str(exc)},
                reason=f"unexpected error probing {host}:{port}: {exc}",
                collected_monotonic=collected_monotonic,
                collected_wall_claim=collected_wall_claim,
            )
