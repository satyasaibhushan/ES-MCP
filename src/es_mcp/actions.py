"""Action tiers and deterministic Elasticsearch route classification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any
from urllib.parse import unquote, urlsplit


class RequestClassificationError(ValueError):
    pass


class ActionTier(IntEnum):
    DISCOVERY = 0
    READ = 1
    EXPENSIVE_READ = 2
    DOCUMENT_WRITE = 3
    STRUCTURAL_WRITE = 4
    ADMIN = 5


class ActionMode(str, Enum):
    ALLOW = "allow"
    APPROVE = "approve"
    DENY = "deny"


@dataclass(frozen=True)
class ClassifiedRequest:
    method: str
    path: str
    operation: str
    tier: ActionTier
    targets: tuple[str, ...] = ()
    supported: bool = True


_TARGET = r"(?P<target>[^/]+)"
_DOC_ID = r"[^/]+"


def _route(pattern: str) -> re.Pattern[str]:
    return re.compile(f"^{pattern}$")


_READ_ROUTES: tuple[tuple[re.Pattern[str], frozenset[str], str], ...] = (
    (_route(rf"/{_TARGET}/_search"), frozenset({"GET", "POST"}), "SEARCH"),
    (_route(rf"/{_TARGET}/_count"), frozenset({"GET", "POST"}), "COUNT"),
    (
        _route(rf"/{_TARGET}/_field_caps"),
        frozenset({"GET", "POST"}),
        "FIELD_CAPABILITIES",
    ),
    (
        _route(rf"/{_TARGET}/_validate/query"),
        frozenset({"GET", "POST"}),
        "VALIDATE_QUERY",
    ),
    (_route(rf"/{_TARGET}/_mapping"), frozenset({"GET"}), "GET_MAPPING"),
    (_route(rf"/{_TARGET}/_mget"), frozenset({"GET", "POST"}), "MULTI_GET"),
    (
        _route(rf"/{_TARGET}/_doc/{_DOC_ID}"),
        frozenset({"GET", "HEAD"}),
        "GET_DOCUMENT",
    ),
    (
        _route(rf"/{_TARGET}/_source/{_DOC_ID}"),
        frozenset({"GET", "HEAD"}),
        "GET_SOURCE",
    ),
)

_WRITE_ROUTES: tuple[
    tuple[re.Pattern[str], frozenset[str], str], ...
] = (
    (
        _route(rf"/{_TARGET}/_create/{_DOC_ID}"),
        frozenset({"PUT", "POST"}),
        "CREATE",
    ),
    (
        _route(rf"/{_TARGET}/_update/{_DOC_ID}"),
        frozenset({"POST"}),
        "UPDATE",
    ),
    (
        _route(rf"/{_TARGET}/_doc/{_DOC_ID}"),
        frozenset({"PUT", "POST"}),
        "INDEX",
    ),
    (_route(rf"/{_TARGET}/_doc"), frozenset({"POST"}), "INDEX"),
    (
        _route(rf"/{_TARGET}/_doc/{_DOC_ID}"),
        frozenset({"DELETE"}),
        "DELETE",
    ),
)

_STRUCTURAL_MARKERS = (
    "/_bulk",
    "/_delete_by_query",
    "/_update_by_query",
    "/_reindex",
    "/_aliases",
    "/_settings",
    "/_mapping",
    "/_refresh",
    "/_flush",
    "/_forcemerge",
    "/_cache/clear",
)

_STRUCTURAL_PREFIXES = (
    "/_aliases",
    "/_reindex",
    "/_bulk",
    "/_data_stream",
    "/_index_template",
    "/_component_template",
    "/_template",
    "/_ilm",
    "/_ingest",
    "/_scripts",
)

_ADMIN_PREFIXES = (
    "/_security",
    "/_cluster",
    "/_nodes",
    "/_snapshot",
    "/_slm",
    "/_license",
    "/_watcher",
    "/_ml",
    "/_transform",
    "/_tasks",
)

_EXPENSIVE_KEYS = frozenset(
    {
        "knn",
        "profile",
        "rescore",
        "runtime_mappings",
        "script",
        "script_fields",
        "script_score",
    }
)


def _normalize_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise RequestClassificationError("path must be a non-empty string")
    split = urlsplit(path)
    if split.scheme or split.netloc:
        raise RequestClassificationError("absolute URLs are not allowed")
    if split.query or split.fragment:
        raise RequestClassificationError(
            "put query parameters in the params object, not in path"
        )
    decoded = unquote(split.path)
    if not decoded.startswith("/"):
        raise RequestClassificationError("path must start with '/'")
    if "//" in decoded or "/../" in f"{decoded}/":
        raise RequestClassificationError("path contains invalid segments")
    if any(ord(char) < 32 for char in decoded):
        raise RequestClassificationError("path contains control characters")
    if decoded != "/" and decoded.endswith("/"):
        decoded = decoded[:-1]
    return decoded


def _contains_key(value: Any, keys: frozenset[str]) -> bool:
    if isinstance(value, dict):
        return any(key in keys or _contains_key(child, keys) for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_key(child, keys) for child in value)
    return False


def _is_expensive(body: Any, params: dict[str, Any]) -> bool:
    if _contains_key(body, _EXPENSIVE_KEYS):
        return True
    if params.get("scroll") is not None:
        return True
    if params.get("search_type") == "dfs_query_then_fetch":
        return True
    if isinstance(body, dict):
        if body.get("track_total_hits") is True:
            return True
        if body.get("explain") is True:
            return True
    return False


def _target_from_match(match: re.Match[str]) -> tuple[str, ...]:
    target = match.groupdict().get("target")
    return (target,) if target else ()


def classify_request(
    method: str,
    path: str,
    body: Any = None,
    params: dict[str, Any] | None = None,
) -> ClassifiedRequest:
    """Classify by method, path and body. HTTP method alone is never trusted."""
    normalized_method = str(method).upper()
    if normalized_method not in {"GET", "HEAD", "POST", "PUT", "DELETE"}:
        raise RequestClassificationError(
            f"HTTP method {normalized_method!r} is not supported"
        )
    normalized_path = _normalize_path(path)
    request_params = params or {}

    if any(
        normalized_path == prefix or normalized_path.startswith(f"{prefix}/")
        for prefix in _ADMIN_PREFIXES
    ):
        return ClassifiedRequest(
            normalized_method,
            normalized_path,
            "ADMIN",
            ActionTier.ADMIN,
            supported=False,
        )

    if normalized_path.startswith("/_resolve/index/") and normalized_method in {
        "GET",
        "POST",
    }:
        target = normalized_path.removeprefix("/_resolve/index/")
        if not target:
            raise RequestClassificationError("resolve-index requires a target")
        return ClassifiedRequest(
            normalized_method,
            normalized_path,
            "RESOLVE_INDEX",
            ActionTier.READ,
            (target,),
        )

    for pattern, methods, operation in _READ_ROUTES:
        match = pattern.match(normalized_path)
        if match and normalized_method in methods:
            tier = (
                ActionTier.EXPENSIVE_READ
                if _is_expensive(body, request_params)
                else ActionTier.READ
            )
            return ClassifiedRequest(
                normalized_method,
                normalized_path,
                operation,
                tier,
                _target_from_match(match),
            )

    for pattern, methods, operation in _WRITE_ROUTES:
        match = pattern.match(normalized_path)
        if match and normalized_method in methods:
            return ClassifiedRequest(
                normalized_method,
                normalized_path,
                operation,
                ActionTier.DOCUMENT_WRITE,
                _target_from_match(match),
            )

    if (
        any(normalized_path.startswith(prefix) for prefix in _STRUCTURAL_PREFIXES)
        or any(marker in normalized_path for marker in _STRUCTURAL_MARKERS)
        or (
            normalized_method == "DELETE"
            and normalized_path.count("/") == 1
            and not normalized_path.startswith("/_")
        )
    ):
        target = normalized_path.split("/", 2)[1] if normalized_path.count("/") >= 1 else ""
        return ClassifiedRequest(
            normalized_method,
            normalized_path,
            "STRUCTURAL_WRITE",
            ActionTier.STRUCTURAL_WRITE,
            (target,) if target and not target.startswith("_") else (),
            supported=False,
        )

    return ClassifiedRequest(
        normalized_method,
        normalized_path,
        "UNKNOWN",
        ActionTier.ADMIN,
        supported=False,
    )

