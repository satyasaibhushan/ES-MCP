import json
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from es_mcp.actions import ActionMode, ActionTier
from es_mcp.approval import ApprovalStore
from es_mcp.audit import AuditLogger
from es_mcp.client import ElasticsearchResponse
from es_mcp.profiles import (
    AuthConfig,
    Permissions,
    Profile,
    RequestLimits,
    TLSConfig,
)
from es_mcp.server import ESMCPServer
from es_mcp.service import ESMCPService

TOOL_NAMES = {
    "es_list_profiles",
    "es_check_connection",
    "es_describe_profile",
    "es_request",
    "es_plan_request",
    "es_execute_approved_request",
}


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def execute(self, **request):
        self.calls.append(request)
        return ElasticsearchResponse(200, {"hits": {"hits": []}}, {})


class FakeRegistry:
    def __init__(self):
        self.executor = FakeExecutor()

    def get(self, profile):
        return self.executor

    def tunnel_status(self, profile):
        return {"enabled": False, "active": False}

    def check(self, profile):
        return ElasticsearchResponse(
            200,
            {
                "cluster_name": "test",
                "version": {"number": "8.0.0"},
            },
            {"x-elastic-product": "Elasticsearch"},
        )

    def close(self):
        pass


def make_service(tmp_path: Path, registry: FakeRegistry | None = None) -> ESMCPService:
    profile = Profile(
        name="project",
        url="https://es.example.test",
        auth=AuthConfig(api_key="secret"),
        tls=TLSConfig(),
        limits=RequestLimits(),
        permissions=Permissions(
            read_indices=("project-*",),
            modes={
                ActionTier.DISCOVERY: ActionMode.ALLOW,
                ActionTier.READ: ActionMode.ALLOW,
                ActionTier.EXPENSIVE_READ: ActionMode.APPROVE,
                ActionTier.DOCUMENT_WRITE: ActionMode.DENY,
                ActionTier.STRUCTURAL_WRITE: ActionMode.DENY,
                ActionTier.ADMIN: ActionMode.DENY,
            },
        ),
    )
    return ESMCPService(
        profiles={"project": profile},
        approvals=ApprovalStore(),
        audit=AuditLogger(tmp_path / "audit"),
        clients=registry or FakeRegistry(),
    )


def payload(result):
    return json.loads(result.content[0].text)


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_mcp_protocol_lists_and_calls_tools(tmp_path, mode):
    server = ESMCPServer(make_service(tmp_path)).server

    async with Client(server, mode=mode) as client:
        tools = await client.list_tools()
        assert {tool.name for tool in tools.tools} == TOOL_NAMES

        result = await client.call_tool(
            "es_request",
            {
                "profile": "project",
                "method": "GET",
                "path": "/project-logs/_search",
            },
        )

    assert result.is_error is False
    assert result.structured_content is None
    assert payload(result)["status_code"] == 200
    assert payload(result)["body"] == {"hits": {"hits": []}}


async def test_tool_failures_are_results_not_protocol_errors(tmp_path):
    server = ESMCPServer(make_service(tmp_path)).server

    async with Client(server) as client:
        invalid = await client.call_tool(
            "es_request",
            {"profile": "project", "method": "PATCH", "path": "/x"},
        )
        extra = await client.call_tool(
            "es_check_connection", {"profile": "project", "x": 1}
        )
        missing = await client.call_tool("es_describe_profile", {})
        unknown_profile = await client.call_tool(
            "es_describe_profile", {"profile": "nope"}
        )
        unknown_tool = await client.call_tool("es_nope", {})
        denied = await client.call_tool(
            "es_request",
            {"profile": "project", "method": "DELETE", "path": "/project-logs"},
        )

    assert invalid.is_error is True
    assert invalid.content[0].text.startswith("Input validation error: 'PATCH'")
    assert extra.is_error is True
    assert "Additional properties" in extra.content[0].text
    assert missing.is_error is True
    assert missing.content[0].text == (
        "Input validation error: 'profile' is a required property"
    )
    # Policy and lookup failures keep the v1 shape: a JSON error payload.
    assert unknown_profile.is_error is False
    assert "error" in payload(unknown_profile)
    assert unknown_tool.is_error is False
    assert payload(unknown_tool) == {"error": "Unknown tool: es_nope"}
    assert denied.is_error is False
    assert "error" in payload(denied)


async def test_unexpected_exception_keeps_generic_error_payload(tmp_path):
    class ExplodingRegistry(FakeRegistry):
        def check(self, profile):
            raise RuntimeError("boom")

    service = make_service(tmp_path, ExplodingRegistry())
    server = ESMCPServer(service).server

    async with Client(server) as client:
        result = await client.call_tool("es_check_connection", {"profile": "project"})

    assert result.is_error is False
    assert payload(result) == {"error": "Unexpected server error (RuntimeError)"}


@pytest.mark.parametrize(
    ("mode", "expected_version"),
    [("auto", "2026-07-28"), ("legacy", "2025-11-25")],
)
async def test_stdio_serves_both_eras(tmp_path, mode, expected_version):
    # No cluster is contacted: only config-backed tools are called.
    profiles = tmp_path / "profiles.yaml"
    profiles.write_text(
        "profiles:\n"
        "  project:\n"
        "    url: http://127.0.0.1:9\n"
        "    auth:\n"
        "      none: true\n"
        "    permissions:\n"
        "      reads:\n"
        "        indices: [project-*]\n",
        encoding="utf-8",
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "es_mcp.server", "--profiles", str(profiles)],
        env={"ES_MCP_AUDIT_DIR": str(tmp_path / "audit")},
    )

    async with Client(params, mode=mode) as client:
        assert client.protocol_version == expected_version
        tools = await client.list_tools()
        described = await client.call_tool("es_describe_profile", {"profile": "project"})

    assert {tool.name for tool in tools.tools} == TOOL_NAMES
    assert described.is_error is False
    assert payload(described)["name"] == "project"
