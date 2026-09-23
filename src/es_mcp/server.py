"""MCP server entry point (stdio by default, Streamable HTTP with --http)."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

import jsonschema
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
    ToolAnnotations,
)

from . import __version__
from .approval import ApprovalError, ApprovalStore
from .audit import AuditLogger, default_audit_dir
from .client import ElasticsearchError
from .profiles import ProfileError, default_profiles_path, load_profiles
from .service import ESMCPService


def _text(value: Any) -> list[TextContent]:
    return [
        TextContent(
            type="text",
            text=json.dumps(value, indent=2, ensure_ascii=False, default=str),
        )
    ]


def _error(message: str) -> list[TextContent]:
    return _text({"error": message})


_REQUEST_PROPERTIES: dict[str, Any] = {
    "profile": {"type": "string"},
    "method": {
        "type": "string",
        "enum": ["GET", "HEAD", "POST", "PUT", "DELETE"],
    },
    "path": {"type": "string", "pattern": "^/"},
    "body": {},
    "params": {
        "type": "object",
        "additionalProperties": {
            "type": ["string", "number", "integer", "boolean", "array"]
        },
    },
}


def _tools() -> list[Tool]:
    request_schema = {
        "type": "object",
        "properties": _REQUEST_PROPERTIES,
        "required": ["profile", "method", "path"],
        "additionalProperties": False,
    }
    approved_schema = {
        "type": "object",
        "properties": {
            **_REQUEST_PROPERTIES,
            "approval_token": {"type": "string"},
        },
        "required": [
            "profile",
            "method",
            "path",
            "approval_token",
        ],
        "additionalProperties": False,
    }
    return [
        Tool(
            name="es_list_profiles",
            description=(
                "List configured Elasticsearch profiles and sanitized "
                "capabilities. Never exposes credentials."
            ),
            input_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=False,
            ),
        ),
        Tool(
            name="es_check_connection",
            description=(
                "Open the configured SSH tunnel if needed and perform a "
                "sanitized Elasticsearch reachability/version check."
            ),
            input_schema={
                "type": "object",
                "properties": {"profile": {"type": "string"}},
                "required": ["profile"],
                "additionalProperties": False,
            },
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=True,
            ),
        ),
        Tool(
            name="es_describe_profile",
            description=(
                "Describe one profile's index scopes, action modes, and limits. "
                "Never exposes credentials."
            ),
            input_schema={
                "type": "object",
                "properties": {"profile": {"type": "string"}},
                "required": ["profile"],
                "additionalProperties": False,
            },
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=False,
            ),
        ),
        Tool(
            name="es_request",
            description=(
                "Execute an automatically allowed Elasticsearch request. "
                "The server classifies method, path, parameters, and JSON body; "
                "unknown, denied, or approval-required requests are rejected."
            ),
            input_schema=request_schema,
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=True,
                open_world_hint=True,
            ),
        ),
        Tool(
            name="es_plan_request",
            description=(
                "Validate an approval-required request without executing it. "
                "Returns a short-lived, single-use token bound to the exact request."
            ),
            input_schema=request_schema,
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                idempotent_hint=False,
                open_world_hint=False,
            ),
        ),
        Tool(
            name="es_execute_approved_request",
            description=(
                "Execute the exact request previously planned, only after explicit "
                "user approval. The token is consumed before execution."
            ),
            input_schema=approved_schema,
            annotations=ToolAnnotations(
                read_only_hint=False,
                destructive_hint=True,
                idempotent_hint=False,
                open_world_hint=True,
            ),
        ),
    ]


def _result(content: list[TextContent], *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=content, is_error=is_error)


class ESMCPServer:
    def __init__(self, service: ESMCPService):
        self.service = service
        self._tools = {tool.name: tool for tool in _tools()}
        self.server: Server = Server(
            "es-mcp",
            version=__version__,
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )

    async def _list_tools(
        self,
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        return ListToolsResult(tools=list(self._tools.values()))

    async def _call_tool(
        self,
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        # Validation failures and escaped exceptions are tool errors, not
        # protocol errors, so the calling model sees the message.
        name = params.name
        arguments = params.arguments or {}
        try:
            tool = self._tools.get(name)
            if tool is not None:
                try:
                    jsonschema.validate(instance=arguments, schema=tool.input_schema)
                except jsonschema.ValidationError as exc:
                    return _result(
                        [
                            TextContent(
                                type="text",
                                text=f"Input validation error: {exc.message}",
                            )
                        ],
                        is_error=True,
                    )
            return _result(await self._dispatch(name, arguments))
        except Exception as exc:
            return _result([TextContent(type="text", text=str(exc))], is_error=True)

    async def _dispatch(
        self, name: str, arguments: dict[str, Any]
    ) -> list[TextContent]:
        # Service calls run in worker threads: they block on the network and on
        # the tunnel lock, which is held for the whole SSH handshake.
        try:
            if name == "es_list_profiles":
                return _text(await asyncio.to_thread(self.service.list_profiles))
            if name == "es_describe_profile":
                return _text(
                    await asyncio.to_thread(
                        self.service.describe_profile,
                        arguments["profile"],
                    )
                )
            if name == "es_check_connection":
                return _text(
                    await asyncio.to_thread(
                        self.service.check_connection,
                        arguments["profile"],
                    )
                )
            if name == "es_request":
                result = await asyncio.to_thread(
                    self.service.execute_allowed,
                    profile_name=arguments["profile"],
                    method=arguments["method"],
                    path=arguments["path"],
                    body=arguments.get("body"),
                    params=arguments.get("params"),
                )
                return _text(result)
            if name == "es_plan_request":
                result = await asyncio.to_thread(
                    self.service.plan,
                    profile_name=arguments["profile"],
                    method=arguments["method"],
                    path=arguments["path"],
                    body=arguments.get("body"),
                    params=arguments.get("params"),
                )
                return _text(result)
            if name == "es_execute_approved_request":
                result = await asyncio.to_thread(
                    self.service.execute_approved,
                    profile_name=arguments["profile"],
                    method=arguments["method"],
                    path=arguments["path"],
                    body=arguments.get("body"),
                    params=arguments.get("params"),
                    approval_token=arguments["approval_token"],
                )
                return _text(result)
            return _error(f"Unknown tool: {name}")
        except (
            ApprovalError,
            ElasticsearchError,
            PermissionError,
            ProfileError,
            ValueError,
        ) as exc:
            return _error(str(exc))
        except Exception as exc:
            return _error(f"Unexpected server error ({type(exc).__name__})")

    async def run(self) -> None:
        try:
            async with stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options(),
                )
        finally:
            self.service.close()


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip("'\"")


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the policy-enforced Elasticsearch MCP server."
    )
    parser.add_argument(
        "--profiles",
        type=Path,
        help="Path to profiles YAML (default: ES_MCP_PROFILES or ~/.es-access/profiles.yaml)",
    )
    parser.add_argument(
        "--check-connections",
        action="store_true",
        help="Open configured tunnels, check every endpoint, print results, and exit.",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration, print sanitized capabilities, and exit.",
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Serve Streamable HTTP at /mcp instead of stdio.",
    )
    parser.add_argument(
        "--host",
        help="HTTP bind address (default: ES_MCP_HTTP_HOST or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="HTTP port (default: ES_MCP_HTTP_PORT or 7719)",
    )
    return parser


def main() -> None:
    arguments = _argument_parser().parse_args()
    profiles_path = (arguments.profiles or default_profiles_path()).expanduser()
    secrets_path = Path(
        os.environ.get(
            "ES_MCP_SECRETS",
            profiles_path.parent / "secrets.env",
        )
    ).expanduser()
    _load_env_file(secrets_path)
    profiles = load_profiles(profiles_path)
    if arguments.check_config:
        summaries = [
            profile.capability_summary() for profile in profiles.values()
        ]
        print(json.dumps(summaries, indent=2, ensure_ascii=False))
        return
    service = ESMCPService(
        profiles=profiles,
        approvals=ApprovalStore(ttl_seconds=300),
        audit=AuditLogger(default_audit_dir()),
    )
    if arguments.check_connections:
        results: list[dict[str, Any]] = []
        failed = False
        try:
            for name in profiles:
                try:
                    result = service.check_connection(name)
                except Exception as exc:
                    result = {
                        "profile": name,
                        "reachable": False,
                        "ok": False,
                        "error": str(exc),
                    }
                results.append(result)
                failed = failed or not result["ok"]
        finally:
            service.close()
        print(json.dumps(results, indent=2, ensure_ascii=False))
        if failed:
            raise SystemExit(1)
        return
    if arguments.http:
        from . import http_server

        host = arguments.host or os.environ.get(
            "ES_MCP_HTTP_HOST", http_server.DEFAULT_HOST
        )
        port = arguments.port or int(
            os.environ.get("ES_MCP_HTTP_PORT", http_server.DEFAULT_PORT)
        )
        token = http_server.load_or_create_token(http_server.default_token_path())
        http_server.serve(ESMCPServer(service), host=host, port=port, token=token)
        return
    asyncio.run(ESMCPServer(service).run())


if __name__ == "__main__":
    main()
