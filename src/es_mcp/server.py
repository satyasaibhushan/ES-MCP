"""MCP stdio server entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool, ToolAnnotations

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


class ESMCPServer:
    def __init__(self, service: ESMCPService):
        self.service = service
        self.server: Server = Server("es-mcp")
        self._register()

    def _register(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
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
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                    annotations=ToolAnnotations(
                        readOnlyHint=True,
                        destructiveHint=False,
                        idempotentHint=True,
                        openWorldHint=False,
                    ),
                ),
                Tool(
                    name="es_describe_profile",
                    description=(
                        "Describe one profile's index scopes, action modes, and limits. "
                        "Never exposes credentials."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {"profile": {"type": "string"}},
                        "required": ["profile"],
                        "additionalProperties": False,
                    },
                    annotations=ToolAnnotations(
                        readOnlyHint=True,
                        destructiveHint=False,
                        idempotentHint=True,
                        openWorldHint=False,
                    ),
                ),
                Tool(
                    name="es_request",
                    description=(
                        "Execute an automatically allowed Elasticsearch request. "
                        "The server classifies method, path, parameters, and JSON body; "
                        "unknown, denied, or approval-required requests are rejected."
                    ),
                    inputSchema=request_schema,
                    annotations=ToolAnnotations(
                        readOnlyHint=True,
                        destructiveHint=False,
                        idempotentHint=True,
                        openWorldHint=True,
                    ),
                ),
                Tool(
                    name="es_plan_request",
                    description=(
                        "Validate an approval-required request without executing it. "
                        "Returns a short-lived, single-use token bound to the exact request."
                    ),
                    inputSchema=request_schema,
                    annotations=ToolAnnotations(
                        readOnlyHint=True,
                        destructiveHint=False,
                        idempotentHint=False,
                        openWorldHint=False,
                    ),
                ),
                Tool(
                    name="es_execute_approved_request",
                    description=(
                        "Execute the exact request previously planned, only after explicit "
                        "user approval. The token is consumed before execution."
                    ),
                    inputSchema=approved_schema,
                    annotations=ToolAnnotations(
                        readOnlyHint=False,
                        destructiveHint=True,
                        idempotentHint=False,
                        openWorldHint=True,
                    ),
                ),
            ]

        @self.server.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any]
        ) -> list[TextContent]:
            try:
                if name == "es_list_profiles":
                    return _text(self.service.list_profiles())
                if name == "es_describe_profile":
                    return _text(
                        self.service.describe_profile(arguments["profile"])
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
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


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
        "--check-config",
        action="store_true",
        help="Validate configuration, print sanitized capabilities, and exit.",
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
    asyncio.run(ESMCPServer(service).run())


if __name__ == "__main__":
    main()
