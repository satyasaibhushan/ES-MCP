"""Application service joining classification, policy, approval, audit, and HTTP."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .actions import (
    ActionMode,
    ActionTier,
    ClassifiedRequest,
    RequestClassificationError,
    classify_request,
)
from .approval import ApprovalError, ApprovalStore
from .audit import AuditLogger
from .client import ClientRegistry, ElasticsearchResponse
from .policy import Allow, Deny, check_request
from .profiles import Profile, ProfileError


class Executor(Protocol):
    def execute(
        self, *, method: str, path: str, body: Any, params: dict[str, Any]
    ) -> ElasticsearchResponse: ...


class Registry(Protocol):
    def get(self, profile: Profile) -> Executor: ...


@dataclass(frozen=True)
class PreparedRequest:
    profile: Profile
    classified: ClassifiedRequest
    body: Any
    params: dict[str, Any]
    mode: ActionMode
    canonical: str
    request_hash: str


def canonical_request(
    *, method: str, path: str, body: Any, params: dict[str, Any]
) -> str:
    try:
        return json.dumps(
            {
                "method": method,
                "path": path,
                "params": params,
                "body": body,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise RequestClassificationError("Request is not valid JSON") from exc


class ESMCPService:
    def __init__(
        self,
        *,
        profiles: dict[str, Profile],
        approvals: ApprovalStore,
        audit: AuditLogger,
        clients: Registry | None = None,
    ):
        self.profiles = profiles
        self.approvals = approvals
        self.audit = audit
        self.clients: Registry = clients or ClientRegistry()

    def get_profile(self, name: str) -> Profile:
        try:
            return self.profiles[name]
        except KeyError as exc:
            raise ProfileError(f"Unknown profile: {name!r}") from exc

    def list_profiles(self) -> list[dict[str, Any]]:
        return [
            {
                "name": profile.name,
                "read_indices": list(profile.permissions.read_indices),
                "write_capability": (
                    "configured"
                    if profile.permissions.write_indices
                    else "none"
                ),
                "expensive_reads": profile.permissions.mode_for(
                    ActionTier.EXPENSIVE_READ
                ).value,
            }
            for profile in self.profiles.values()
        ]

    def describe_profile(self, name: str) -> dict[str, Any]:
        profile = self.get_profile(name)
        detail = profile.capability_summary()
        detail["limits"] = {
            "timeout_seconds": profile.limits.timeout_seconds,
            "max_hits": profile.limits.max_hits,
            "max_from": profile.limits.max_from,
            "max_aggregation_size": profile.limits.max_aggregation_size,
            "max_request_bytes": profile.limits.max_request_bytes,
            "max_response_bytes": profile.limits.max_response_bytes,
            "allow_scripts": profile.limits.allow_scripts,
        }
        detail["tls_verification"] = profile.tls.verify
        return detail

    def _prepare(
        self,
        *,
        profile_name: str,
        method: str,
        path: str,
        body: Any,
        params: dict[str, Any] | None,
    ) -> PreparedRequest:
        profile = self.get_profile(profile_name)
        classified = classify_request(method, path, body, params)
        decision = check_request(profile, classified, body, params)
        if isinstance(decision, Deny):
            request_hash = hashlib.sha256(
                canonical_request(
                    method=classified.method,
                    path=classified.path,
                    body=body,
                    params=params or {},
                ).encode()
            ).hexdigest()
            self.audit.log(
                profile=profile.name,
                method=classified.method,
                path=classified.path,
                operation=classified.operation,
                tier=classified.tier.name.lower(),
                targets=classified.targets,
                request_hash=request_hash,
                decision="rejected",
                error=decision.reason,
            )
            raise PermissionError(decision.reason)
        canonical = canonical_request(
            method=classified.method,
            path=classified.path,
            body=decision.body,
            params=decision.params,
        )
        return PreparedRequest(
            profile=profile,
            classified=classified,
            body=decision.body,
            params=decision.params,
            mode=decision.mode,
            canonical=canonical,
            request_hash=hashlib.sha256(canonical.encode()).hexdigest(),
        )

    def execute_allowed(
        self,
        *,
        profile_name: str,
        method: str,
        path: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prepared = self._prepare(
            profile_name=profile_name,
            method=method,
            path=path,
            body=body,
            params=params,
        )
        if prepared.mode != ActionMode.ALLOW:
            self.audit.log(
                profile=prepared.profile.name,
                method=prepared.classified.method,
                path=prepared.classified.path,
                operation=prepared.classified.operation,
                tier=prepared.classified.tier.name.lower(),
                targets=prepared.classified.targets,
                request_hash=prepared.request_hash,
                decision="approval_required",
            )
            raise PermissionError(
                "This request requires approval; use es_plan_request and "
                "es_execute_approved_request"
            )
        return self._execute(prepared)

    def plan(
        self,
        *,
        profile_name: str,
        method: str,
        path: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prepared = self._prepare(
            profile_name=profile_name,
            method=method,
            path=path,
            body=body,
            params=params,
        )
        if prepared.mode != ActionMode.APPROVE:
            if prepared.mode == ActionMode.ALLOW:
                raise PermissionError(
                    "This request does not require approval; use es_request"
                )
            raise PermissionError("This request is denied")
        record = self.approvals.issue(
            profile=prepared.profile.name,
            canonical_request=prepared.canonical,
            operation=prepared.classified.operation,
            targets=prepared.classified.targets,
        )
        self.audit.log(
            profile=prepared.profile.name,
            method=prepared.classified.method,
            path=prepared.classified.path,
            operation=prepared.classified.operation,
            tier=prepared.classified.tier.name.lower(),
            targets=prepared.classified.targets,
            request_hash=prepared.request_hash,
            decision="planned",
            approval_token=record.token,
        )
        return {
            "allowed": True,
            "requires_user_approval": True,
            "profile": prepared.profile.name,
            "method": prepared.classified.method,
            "path": prepared.classified.path,
            "operation": prepared.classified.operation,
            "tier": prepared.classified.tier.name.lower(),
            "targets": list(prepared.classified.targets),
            "request_hash": prepared.request_hash,
            "approval_token": record.token,
            "expires_at_epoch": record.expires_at,
            "note": (
                "Single-use. After explicit user approval, submit the same request "
                "to es_execute_approved_request."
            ),
        }

    def execute_approved(
        self,
        *,
        profile_name: str,
        method: str,
        path: str,
        approval_token: str,
        body: Any = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prepared = self._prepare(
            profile_name=profile_name,
            method=method,
            path=path,
            body=body,
            params=params,
        )
        if prepared.mode != ActionMode.APPROVE:
            raise PermissionError("The current policy does not approve this request")
        try:
            self.approvals.consume(
                token=approval_token,
                profile=prepared.profile.name,
                canonical_request=prepared.canonical,
            )
        except ApprovalError as exc:
            self.audit.log(
                profile=prepared.profile.name,
                method=prepared.classified.method,
                path=prepared.classified.path,
                operation=prepared.classified.operation,
                tier=prepared.classified.tier.name.lower(),
                targets=prepared.classified.targets,
                request_hash=prepared.request_hash,
                decision="approval_rejected",
                approval_token=approval_token,
                error=str(exc),
            )
            raise
        return self._execute(prepared, approval_token=approval_token)

    def _execute(
        self, prepared: PreparedRequest, approval_token: str | None = None
    ) -> dict[str, Any]:
        start = time.monotonic()
        try:
            response = self.clients.get(prepared.profile).execute(
                method=prepared.classified.method,
                path=prepared.classified.path,
                body=prepared.body,
                params=prepared.params,
            )
        except Exception as exc:
            self.audit.log(
                profile=prepared.profile.name,
                method=prepared.classified.method,
                path=prepared.classified.path,
                operation=prepared.classified.operation,
                tier=prepared.classified.tier.name.lower(),
                targets=prepared.classified.targets,
                request_hash=prepared.request_hash,
                decision="execution_failed",
                approval_token=approval_token,
                error=str(exc),
                elapsed_ms=(time.monotonic() - start) * 1_000,
            )
            raise
        self.audit.log(
            profile=prepared.profile.name,
            method=prepared.classified.method,
            path=prepared.classified.path,
            operation=prepared.classified.operation,
            tier=prepared.classified.tier.name.lower(),
            targets=prepared.classified.targets,
            request_hash=prepared.request_hash,
            decision="executed",
            status_code=response.status_code,
            approval_token=approval_token,
            elapsed_ms=(time.monotonic() - start) * 1_000,
        )
        return {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body,
        }
