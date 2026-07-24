import ssl

import httpcore
import httpx

from es_mcp.transport import TunnelHTTPTransport
from es_mcp.tunnel import TunnelEndpoint


class FakeTunnel:
    def ensure(self):
        return TunnelEndpoint("127.0.0.1", 49152)


class FakeStream(httpcore.NetworkStream):
    def __init__(self):
        self.server_hostname = None
        self.writes = bytearray()
        self._response_sent = False

    def read(self, max_bytes, timeout=None):
        if self._response_sent:
            return b""
        self._response_sent = True
        return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"

    def write(self, buffer, timeout=None):
        self.writes.extend(buffer)

    def close(self):
        pass

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.server_hostname = server_hostname
        return self

    def get_extra_info(self, info):
        return None


class FakeBackend(httpcore.NetworkBackend):
    def __init__(self):
        self.connect_args = None
        self.stream = FakeStream()

    def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        self.connect_args = (host, port)
        return self.stream

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError


def test_transport_routes_tcp_locally_but_preserves_remote_origin():
    backend = FakeBackend()
    transport = TunnelHTTPTransport(
        tunnel=FakeTunnel(),
        ssl_context=ssl.create_default_context(),
        network_backend=backend,
    )
    client = httpx.Client(transport=transport)

    response = client.get("https://es.example.test/project-logs/_search")

    assert response.status_code == 200
    assert backend.connect_args == ("127.0.0.1", 49152)
    assert backend.stream.server_hostname == "es.example.test"
    assert b"Host: es.example.test" in backend.stream.writes
