"""Project scoping and request limit enforcement."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from typing import Any

from .actions import ActionMode, ActionTier, ClassifiedRequest
from .profiles import Profile


_SCRIPT_KEYS = frozenset(
    {"script", "script_fields", "script_score", "runtime_mappings"}
)
_SAFE_PARAMS = frozenset(
    {
        "allow_no_indices",
        "allow_partial_search_results",
        "expand_wildcards",
        "fields",
        "filter_path",
        "human",
        "ignore_unavailable",
        "include_unmapped",
        "local",
        "master_timeout",
        "min_score",
        "preference",
        "pretty",
        "request_cache",
        "routing",
        "search_type",
        "terminate_after",
        "timeout",
        "track_total_hits",
    }
)
_DURATION_RE = re.compile(r"^(?P<value>\d+)(?P<unit>ms|s|m|h|d)$")
_DURATION_MULTIPLIERS = {
    "ms": 0.001,
    "s": 1,
    "m": 60,
    "h": 3_600,
    "d": 86_400,
}


@dataclass(frozen=True)
class Allow:
    mode: ActionMode
    body: Any
    params: dict[str, Any]


@dataclass(frozen=True)
class Deny:
    reason: str


PolicyDecision = Allow | Deny


def _split_targets(expressions: tuple[str, ...]) -> tuple[str, ...]:
    targets: list[str] = []
    for expression in expressions:
        targets.extend(part.strip() for part in expression.split(","))
    return tuple(targets)


def _allowed_by_pattern(target: str, allowed: str) -> bool:
    if "*" not in allowed:
        return target == allowed
    allowed_prefix = allowed[:-1]
    if "*" not in target:
        return target.startswith(allowed_prefix)
    if target.count("*") != 1 or not target.endswith("*"):
        return False
    return target[:-1].startswith(allowed_prefix)


def _validate_target(target: str, profile: Profile) -> str | None:
    if not target:
        return "Empty index target is not allowed"
    if target in {"*", "_all"} or target.startswith("-"):
        return f"Index target {target!r} is not allowed"
    if ":" in target:
        return "Cross-cluster targets are not allowed"
    if any(char in target for char in "?[]"):
        return "Only exact index names or a trailing '*' are supported"
    if "*" in target and (target.count("*") != 1 or not target.endswith("*")):
        return "Only exact index names or a trailing '*' are supported"
    if target.startswith(".") and not profile.permissions.allow_system_indices:
        return "System and hidden indices are not allowed"
    return None


def _contains_key(value: Any, keys: frozenset[str]) -> bool:
    if isinstance(value, dict):
        return any(key in keys or _contains_key(child, keys) for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_key(child, keys) for child in value)
    return False


def _contains_external_index_reference(value: Any) -> bool:
    if isinstance(value, dict):
        if {"index", "id", "path"} <= set(value):
            return True
        return any(_contains_external_index_reference(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_external_index_reference(child) for child in value)
    return False


def _int_at_least_zero(value: Any, label: str) -> tuple[int | None, str | None]:
    if isinstance(value, bool):
        return None, f"{label} must be a non-negative integer"
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None, f"{label} must be a non-negative integer"
    if parsed < 0:
        return None, f"{label} must be a non-negative integer"
    return parsed, None


def _check_aggregation_sizes(value: Any, maximum: int) -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"terms", "multi_terms", "composite", "significant_terms"}:
                if isinstance(child, dict) and "size" in child:
                    size, error = _int_at_least_zero(child["size"], f"{key}.size")
                    if error:
                        return error
                    if size is not None and size > maximum:
                        return f"{key}.size exceeds max_aggregation_size {maximum}"
            error = _check_aggregation_sizes(child, maximum)
            if error:
                return error
    elif isinstance(value, list):
        for child in value:
            error = _check_aggregation_sizes(child, maximum)
            if error:
                return error
    return None


def _duration_seconds(value: Any, label: str) -> tuple[float | None, str | None]:
    if not isinstance(value, str):
        return None, f"{label} must be an Elasticsearch duration such as '10s'"
    match = _DURATION_RE.fullmatch(value.strip())
    if not match:
        return None, f"{label} must be an Elasticsearch duration such as '10s'"
    seconds = int(match.group("value")) * _DURATION_MULTIPLIERS[match.group("unit")]
    return seconds, None


def _check_params(profile: Profile, params: dict[str, Any]) -> str | None:
    unknown = sorted(set(params) - _SAFE_PARAMS)
    if unknown:
        return f"Unsupported query parameter(s): {', '.join(unknown)}"
    expand = str(params.get("expand_wildcards", "open")).lower()
    values = {part.strip() for part in expand.split(",")}
    if values - {"open"}:
        return "expand_wildcards may only target open, non-hidden indices"
    if "scroll" in params:
        return "Scroll requests are not supported"
    for name in ("timeout", "master_timeout"):
        if name in params:
            seconds, error = _duration_seconds(params[name], name)
            if error:
                return error
            if seconds is not None and seconds > profile.limits.timeout_seconds:
                return f"{name} exceeds timeout_seconds {profile.limits.timeout_seconds}"
    return None


def _prepare_body(profile: Profile, classified: ClassifiedRequest, body: Any) -> PolicyDecision:
    copied = copy.deepcopy(body)
    if copied is not None and not isinstance(copied, (dict, list)):
        return Deny("body must be a JSON object, array, or null")
    encoded = json.dumps(copied, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > profile.limits.max_request_bytes:
        return Deny(
            f"Request body exceeds max_request_bytes {profile.limits.max_request_bytes}"
        )
    if _contains_key(copied, _SCRIPT_KEYS) and not profile.limits.allow_scripts:
        return Deny("Scripts and runtime mappings are disabled for this profile")
    if classified.operation == "MULTI_GET" and isinstance(copied, dict):
        docs = copied.get("docs")
        if isinstance(docs, list) and any(
            isinstance(document, dict) and "_index" in document
            for document in docs
        ):
            return Deny("Per-document _index overrides are not allowed")
    if (
        classified.operation in {"SEARCH", "COUNT", "VALIDATE_QUERY"}
        and _contains_external_index_reference(copied)
    ):
        return Deny("Queries that reference another index are not allowed")

    if classified.operation == "SEARCH" and isinstance(copied, dict):
        if "size" in copied:
            size, error = _int_at_least_zero(copied["size"], "size")
            if error:
                return Deny(error)
            if size is not None and size > profile.limits.max_hits:
                return Deny(f"size exceeds max_hits {profile.limits.max_hits}")
        else:
            copied["size"] = min(10, profile.limits.max_hits)
        if "from" in copied:
            offset, error = _int_at_least_zero(copied["from"], "from")
            if error:
                return Deny(error)
            if offset is not None and offset > profile.limits.max_from:
                return Deny(f"from exceeds max_from {profile.limits.max_from}")
        aggregation_error = _check_aggregation_sizes(
            copied.get("aggs", copied.get("aggregations")),
            profile.limits.max_aggregation_size,
        )
        if aggregation_error:
            return Deny(aggregation_error)
        if "timeout" in copied:
            seconds, error = _duration_seconds(copied["timeout"], "timeout")
            if error:
                return Deny(error)
            if seconds is not None and seconds > profile.limits.timeout_seconds:
                return Deny(
                    "timeout exceeds timeout_seconds "
                    f"{profile.limits.timeout_seconds}"
                )
        else:
            copied["timeout"] = f"{profile.limits.timeout_seconds}s"

    return Allow(ActionMode.ALLOW, copied, {})


def check_request(
    profile: Profile,
    classified: ClassifiedRequest,
    body: Any = None,
    params: dict[str, Any] | None = None,
) -> PolicyDecision:
    if not classified.supported:
        return Deny(f"Endpoint is not supported: {classified.operation}")

    mode = profile.permissions.mode_for(classified.tier)
    if mode == ActionMode.DENY:
        return Deny(f"{classified.tier.name.lower()} actions are denied for this profile")

    targets = _split_targets(classified.targets)
    if not targets:
        return Deny("Could not determine the request's index targets")

    for target in targets:
        error = _validate_target(target, profile)
        if error:
            return Deny(error)

    if classified.tier <= ActionTier.EXPENSIVE_READ:
        for target in targets:
            if not any(
                _allowed_by_pattern(target, allowed)
                for allowed in profile.permissions.read_indices
            ):
                return Deny(f"Index target {target!r} is not read-allowed")
    elif classified.tier == ActionTier.DOCUMENT_WRITE:
        for target in targets:
            matching_ops = [
                operations
                for pattern, operations in profile.permissions.write_indices.items()
                if _allowed_by_pattern(target, pattern)
            ]
            if not matching_ops or not any(
                classified.operation in operations for operations in matching_ops
            ):
                return Deny(
                    f"Index target {target!r} is not write-allowed for "
                    f"{classified.operation}"
                )

    request_params = copy.deepcopy(params or {})
    params_error = _check_params(profile, request_params)
    if params_error:
        return Deny(params_error)
    request_params.setdefault("expand_wildcards", "open")

    body_decision = _prepare_body(profile, classified, body)
    if isinstance(body_decision, Deny):
        return body_decision
    return Allow(mode, body_decision.body, request_params)
