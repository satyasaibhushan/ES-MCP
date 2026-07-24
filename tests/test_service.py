from pathlib import Path
from typing import Any

import pytest

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
from es_mcp.service import ESMCPService


class FakeExecutor:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    def execute(self, **request: Any) -> ElasticsearchResponse:
        self.calls.append(request)
        return ElasticsearchResponse(200, {"ok": True}, {})


class FakeRegistry:
    def __init__(self, executor: FakeExecutor):
        self.executor = executor

    def get(self, profile: Profile) -> FakeExecutor:
        return self.executor

    def check(self, profile: Profile) -> ElasticsearchResponse:
        return ElasticsearchResponse(
            200,
            {
                "cluster_name": "project-uat",
                "version": {"number": "6.8.23"},
                "tagline": "You Know, for Search",
            },
            {},
        )

    def tunnel_status(self, profile: Profile) -> dict[str, Any]:
        return {"enabled": profile.ssh.enabled, "active": profile.ssh.enabled}

    def close(self) -> None:
        pass


def _service(tmp_path: Path) -> tuple[ESMCPService, FakeExecutor]:
    profile = Profile(
        name="project",
        url="https://es.example.test",
        auth=AuthConfig(api_key="secret"),
        tls=TLSConfig(),
        limits=RequestLimits(),
        permissions=Permissions(
            read_indices=("project-*",),
            write_indices={"project-events": frozenset({"UPDATE"})},
            modes={
                ActionTier.DISCOVERY: ActionMode.ALLOW,
                ActionTier.READ: ActionMode.ALLOW,
                ActionTier.EXPENSIVE_READ: ActionMode.DENY,
                ActionTier.DOCUMENT_WRITE: ActionMode.APPROVE,
                ActionTier.STRUCTURAL_WRITE: ActionMode.DENY,
                ActionTier.ADMIN: ActionMode.DENY,
            },
        ),
    )
    executor = FakeExecutor()
    service = ESMCPService(
        profiles={"project": profile},
        approvals=ApprovalStore(),
        audit=AuditLogger(tmp_path / "audit"),
        clients=FakeRegistry(executor),
    )
    return service, executor


def test_allowed_read_executes(tmp_path):
    service, executor = _service(tmp_path)

    result = service.execute_allowed(
        profile_name="project",
        method="GET",
        path="/project-logs/_search",
    )

    assert result["status_code"] == 200
    assert len(executor.calls) == 1


def test_write_requires_plan_and_exact_approval(tmp_path):
    service, executor = _service(tmp_path)
    request = {
        "profile_name": "project",
        "method": "POST",
        "path": "/project-events/_update/1",
        "body": {"doc": {"status": "done"}},
    }

    with pytest.raises(PermissionError, match="requires approval"):
        service.execute_allowed(**request)

    plan = service.plan(**request)
    result = service.execute_approved(
        **request, approval_token=plan["approval_token"]
    )

    assert result["body"] == {"ok": True}
    assert len(executor.calls) == 1


def test_changed_approved_request_is_rejected_and_consumed(tmp_path):
    service, executor = _service(tmp_path)
    request = {
        "profile_name": "project",
        "method": "POST",
        "path": "/project-events/_update/1",
        "body": {"doc": {"status": "done"}},
    }
    plan = service.plan(**request)

    with pytest.raises(Exception, match="does not match"):
        service.execute_approved(
            **{**request, "body": {"doc": {"status": "other"}}},
            approval_token=plan["approval_token"],
        )

    with pytest.raises(Exception, match="already-used"):
        service.execute_approved(
            **request, approval_token=plan["approval_token"]
        )
    assert executor.calls == []


def test_connection_check_returns_sanitized_version(tmp_path):
    service, executor = _service(tmp_path)

    result = service.check_connection("project")

    assert result == {
        "profile": "project",
        "reachable": True,
        "ok": True,
        "status_code": 200,
        "cluster_name": "project-uat",
        "version": "6.8.23",
        "distribution": "elasticsearch",
        "product": None,
        "tunnel": {"enabled": False, "active": False},
    }
    assert executor.calls == []
