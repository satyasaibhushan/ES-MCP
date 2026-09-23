import asyncio
import contextlib
import os
import socket
import stat
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor

import httpx
import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from es_mcp.http_server import build_app, load_or_create_token
from es_mcp.server import ESMCPServer

from .test_server import FakeRegistry, make_service, payload

TOKEN = "test-token"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
EXPENSIVE_SEARCH = {
    "profile": "project",
    "method": "POST",
    "path": "/project-logs/_search",
    "body": {"track_total_hits": True},
}


@contextlib.asynccontextmanager
async def running_server(service) -> AsyncIterator[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    app = build_app(ESMCPServer(service), token=TOKEN, host="127.0.0.1")
    server = uvicorn.Server(uvicorn.Config(app, lifespan="on", log_level="warning"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        while not server.started:
            await asyncio.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task
        sock.close()


@contextlib.asynccontextmanager
async def mcp_client(base_url: str, mode: str) -> AsyncIterator[Client]:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with httpx2.AsyncClient(headers=headers) as http:
        transport = streamable_http_client(f"{base_url}/mcp", http_client=http)
        async with Client(transport, mode=mode) as client:
            yield client


@pytest.fixture
async def base_url(tmp_path):
    async with running_server(make_service(tmp_path)) as url:
        yield url


async def test_health_needs_no_auth(base_url):
    async with httpx.AsyncClient() as http:
        response = await http.get(f"{base_url}/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


@pytest.mark.parametrize(
    "authorization",
    [None, "Bearer wrong-token", f"Basic {TOKEN}", "Bearer"],
)
async def test_mcp_rejects_missing_or_wrong_token(base_url, authorization):
    headers = dict(MCP_HEADERS)
    if authorization is not None:
        headers["Authorization"] = authorization
    async with httpx.AsyncClient() as http:
        response = await http.post(f"{base_url}/mcp", json=INITIALIZE, headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_mcp_accepts_token_and_stays_sessionless(base_url):
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"}
    async with httpx.AsyncClient() as http:
        response = await http.post(f"{base_url}/mcp", json=INITIALIZE, headers=headers)

    assert response.status_code == 200
    assert "mcp-session-id" not in response.headers
    assert response.json()["result"]["serverInfo"]["name"] == "es-mcp"


@pytest.mark.parametrize(
    ("extra_headers", "status_code"),
    [
        ({"Host": "evil.example.test:7719"}, 421),
        ({"Host": "evil.example.test:7719", "MCP-Protocol-Version": "2026-07-28"}, 421),
        ({"Origin": "http://evil.example.test"}, 403),
        ({"Origin": "http://evil.example.test", "MCP-Protocol-Version": "2026-07-28"}, 403),
        ({"Origin": "http://localhost:7719"}, 200),
    ],
)
async def test_mcp_validates_host_and_origin(base_url, extra_headers, status_code):
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}", **extra_headers}
    async with httpx.AsyncClient() as http:
        response = await http.post(f"{base_url}/mcp", json=INITIALIZE, headers=headers)

    assert response.status_code == status_code


@pytest.mark.parametrize(
    ("mode", "expected_version"),
    [("auto", "2026-07-28"), ("legacy", "2025-11-25")],
)
async def test_client_negotiates_each_era(base_url, mode, expected_version):
    async with mcp_client(base_url, mode) as client:
        assert client.protocol_version == expected_version
        tools = await client.list_tools()
        result = await client.call_tool(
            "es_request",
            {"profile": "project", "method": "GET", "path": "/project-logs/_search"},
        )
        invalid = await client.call_tool(
            "es_request",
            {"profile": "project", "method": "PATCH", "path": "/x"},
        )

    assert len(tools.tools) == 6
    assert result.is_error is False
    assert payload(result)["status_code"] == 200
    assert invalid.is_error is True
    assert invalid.content[0].text.startswith("Input validation error:")


async def test_plan_on_one_client_executes_on_another_once(tmp_path):
    registry = FakeRegistry()
    async with running_server(make_service(tmp_path, registry)) as url:
        async with mcp_client(url, "auto") as planner:
            plan = payload(await planner.call_tool("es_plan_request", EXPENSIVE_SEARCH))
        approved = {**EXPENSIVE_SEARCH, "approval_token": plan["approval_token"]}

        async with mcp_client(url, "legacy") as executor:
            first, second = await asyncio.gather(
                executor.call_tool("es_execute_approved_request", approved),
                executor.call_tool("es_execute_approved_request", approved),
            )

    outcomes = sorted([payload(first), payload(second)], key=lambda p: "error" in p)
    assert outcomes[0]["status_code"] == 200
    assert "already-used" in outcomes[1]["error"]
    assert len(registry.executor.calls) == 1


async def test_shutdown_closes_service(tmp_path):
    class ClosingRegistry(FakeRegistry):
        closed = False

        def close(self):
            self.closed = True

    registry = ClosingRegistry()
    async with running_server(make_service(tmp_path, registry)):
        assert registry.closed is False

    assert registry.closed is True


def test_token_is_created_once_with_owner_only_mode(tmp_path):
    path = tmp_path / "access" / "http-token"

    with ThreadPoolExecutor(max_workers=8) as pool:
        tokens = set(pool.map(lambda _: load_or_create_token(path), range(8)))

    assert len(tokens) == 1
    assert path.read_text(encoding="utf-8").strip() == tokens.pop()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_existing_token_is_reused(tmp_path):
    path = tmp_path / "http-token"
    path.write_text("kept\n", encoding="utf-8")

    assert load_or_create_token(path) == "kept"
