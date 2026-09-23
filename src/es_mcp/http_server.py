"""Shared Streamable HTTP transport for one long-lived server process."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import os
import secrets
import time
from collections.abc import AsyncIterator
from pathlib import Path

import uvicorn
from mcp.server.streamable_http_manager import (
    StreamableHTTPASGIApp,
    StreamableHTTPSessionManager,
)
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .server import ESMCPServer

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7719

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def default_token_path() -> Path:
    return Path(
        os.environ.get(
            "ES_MCP_HTTP_TOKEN_FILE",
            Path.home() / ".es-access" / "http-token",
        )
    ).expanduser()


def load_or_create_token(path: Path) -> str:
    """Read the bearer token, creating it with mode 0600 on first run."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _read_token(path)
    token = secrets.token_urlsafe(32)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token + "\n")
    return token


def _read_token(path: Path) -> str:
    # O_EXCL guarantees one creator; a racing reader can still see the file
    # before that creator has written the token.
    deadline = time.monotonic() + 2
    while True:
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
        if time.monotonic() >= deadline:
            raise ValueError(f"HTTP token file is empty: {path}")
        time.sleep(0.05)


class BearerAuth:
    """Reject requests without the expected bearer token."""

    def __init__(self, app: ASGIApp, token: str):
        self.app = app
        self._expected = token.encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not self._authorized(scope):
            response = JSONResponse(
                {"error": "Unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _authorized(self, scope: Scope) -> bool:
        for key, value in scope["headers"]:
            if key != b"authorization":
                continue
            scheme, _, supplied = value.partition(b" ")
            if scheme.lower() != b"bearer":
                return False
            return hmac.compare_digest(supplied.strip(), self._expected)
        return False


def _security_settings(host: str) -> TransportSecuritySettings:
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    if host not in _LOOPBACK_HOSTS:
        hosts.append(f"{host}:*")
        origins.append(f"http://{host}:*")
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=origins,
    )


async def _health(request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})


def build_app(mcp_server: ESMCPServer, *, token: str, host: str) -> Starlette:
    """Build the ASGI app. Every request shares ``mcp_server.service``."""
    # Stateless: no Mcp-Session-Id, so any request (and any client) can land
    # on any call; plans and approval tokens live in the shared service.
    manager = StreamableHTTPSessionManager(
        app=mcp_server.server,
        json_response=True,
        stateless=True,
        security_settings=_security_settings(host),
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        try:
            async with manager.run():
                yield
        finally:
            await asyncio.to_thread(mcp_server.service.close)

    return Starlette(
        routes=[
            Route("/health", _health, methods=["GET"]),
            Route("/mcp", BearerAuth(StreamableHTTPASGIApp(manager), token)),
        ],
        lifespan=lifespan,
    )


def serve(mcp_server: ESMCPServer, *, host: str, port: int, token: str) -> None:
    # uvicorn handles SIGINT/SIGTERM by draining and running lifespan
    # shutdown, which closes the SSH tunnels.
    config = uvicorn.Config(
        build_app(mcp_server, token=token, host=host),
        host=host,
        port=port,
        lifespan="on",
        log_level="info",
    )
    uvicorn.Server(config).run()
