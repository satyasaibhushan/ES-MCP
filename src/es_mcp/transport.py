"""HTTP transport that routes TCP through SSH while preserving the ES origin."""

from __future__ import annotations

import ssl
from typing import Any, Iterator

import httpcore
import httpx

from .tunnel import TunnelManager


class _TunnelNetworkBackend(httpcore.NetworkBackend):
    def __init__(
        self,
        tunnel: TunnelManager,
        backend: httpcore.NetworkBackend | None = None,
    ):
        self._tunnel = tunnel
        self._backend = backend or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        endpoint = self._tunnel.ensure()
        return self._backend.connect_tcp(
            endpoint.host,
            endpoint.port,
            timeout=timeout,
            local_address=None,
            socket_options=socket_options,
        )

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        raise NotImplementedError("Unix sockets are not supported")


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Iterator[bytes]):
        self._stream = stream

    def __iter__(self) -> Iterator[bytes]:
        yield from self._stream

    def close(self) -> None:
        close = getattr(self._stream, "close", None)
        if close is not None:
            close()


class TunnelHTTPTransport(httpx.BaseTransport):
    def __init__(
        self,
        *,
        tunnel: TunnelManager,
        ssl_context: ssl.SSLContext,
        max_connections: int = 10,
        max_keepalive_connections: int = 5,
        keepalive_expiry: float = 60,
        network_backend: httpcore.NetworkBackend | None = None,
    ):
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_TunnelNetworkBackend(tunnel, network_backend),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.SyncByteStream):
            raise TypeError("TunnelHTTPTransport requires a synchronous stream")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = self._pool.handle_request(core_request)
        except httpcore.TimeoutException as exc:
            raise httpx.TimeoutException(str(exc), request=request) from exc
        except (
            httpcore.NetworkError,
            httpcore.ProtocolError,
            httpcore.ProxyError,
            httpcore.UnsupportedProtocol,
        ) as exc:
            raise httpx.TransportError(str(exc), request=request) from exc
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=response.extensions,
        )

    def close(self) -> None:
        self._pool.close()
