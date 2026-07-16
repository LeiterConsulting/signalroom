import socket

from splunk_security_agent.main import resolve_port


def test_resolve_port_falls_forward_when_preferred_is_busy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        occupied = listener.getsockname()[1]
        assert resolve_port("127.0.0.1", occupied, scan=10) > occupied
