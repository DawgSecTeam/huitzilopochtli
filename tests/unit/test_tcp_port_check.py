import socket
import threading

from agent.checks.tcp_port import TcpPortCheck
from common.schema import Category, CheckSpec, CollectorStatus


def _spec(port):
    return CheckSpec(id="svc", type="tcp_port", category=Category.VULN,
                     host_id="localhost", collect_params={"host": "127.0.0.1", "port": port},
                     display_title="svc", display_max_points=1)


def test_open_port():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    got = []
    def accept():
        try:
            c, _ = srv.accept(); got.append(c); c.close()
        except OSError:
            pass
    threading.Thread(target=accept, daemon=True).start()
    ev = TcpPortCheck().collect(_spec(port), None)
    srv.close()
    assert ev.status == CollectorStatus.OK
    assert ev.raw["open"] is True


def test_closed_port_is_ok_evidence():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    ev = TcpPortCheck().collect(_spec(port), None)
    assert ev.status == CollectorStatus.OK
    assert ev.raw["open"] is False
