import json

from mcp.shared.memory import create_connected_server_and_client_session

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


class FakeExecutor:
    def execute(self, **request):
        return ElasticsearchResponse(200, {"hits": {"hits": []}}, {})


class FakeRegistry:
    def get(self, profile):
        return FakeExecutor()


async def test_mcp_protocol_lists_and_calls_tools(tmp_path):
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
                ActionTier.EXPENSIVE_READ: ActionMode.DENY,
                ActionTier.DOCUMENT_WRITE: ActionMode.DENY,
                ActionTier.STRUCTURAL_WRITE: ActionMode.DENY,
                ActionTier.ADMIN: ActionMode.DENY,
            },
        ),
    )
    service = ESMCPService(
        profiles={"project": profile},
        approvals=ApprovalStore(),
        audit=AuditLogger(tmp_path / "audit"),
        clients=FakeRegistry(),
    )
    server = ESMCPServer(service).server

    async with create_connected_server_and_client_session(server) as session:
        tools = await session.list_tools()
        assert {tool.name for tool in tools.tools} == {
            "es_list_profiles",
            "es_describe_profile",
            "es_request",
            "es_plan_request",
            "es_execute_approved_request",
        }

        result = await session.call_tool(
            "es_request",
            {
                "profile": "project",
                "method": "GET",
                "path": "/project-logs/_search",
            },
        )

    payload = json.loads(result.content[0].text)
    assert payload["status_code"] == 200
    assert payload["body"] == {"hits": {"hits": []}}

