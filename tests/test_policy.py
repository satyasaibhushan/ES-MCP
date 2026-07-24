from es_mcp.actions import ActionMode, ActionTier, classify_request
from es_mcp.policy import Allow, Deny, check_request
from es_mcp.profiles import (
    AuthConfig,
    Permissions,
    Profile,
    RequestLimits,
    TLSConfig,
)


def _profile() -> Profile:
    return Profile(
        name="project",
        url="https://es.example.test",
        auth=AuthConfig(api_key_env="TEST_ES_API_KEY"),
        tls=TLSConfig(),
        limits=RequestLimits(max_hits=50, max_from=100, max_aggregation_size=20),
        permissions=Permissions(
            read_indices=("project-logs-*", "project-events"),
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


def test_allows_narrower_trailing_wildcard():
    request = classify_request("GET", "/project-logs-2026*/_search")

    decision = check_request(_profile(), request)

    assert isinstance(decision, Allow)
    assert decision.mode == ActionMode.ALLOW


def test_denies_wider_wildcard():
    request = classify_request("GET", "/project-*/_search")

    decision = check_request(_profile(), request)

    assert isinstance(decision, Deny)
    assert "not read-allowed" in decision.reason


def test_denies_cross_cluster_and_hidden_targets():
    cross_cluster = classify_request("GET", "/remote:project-logs-*/_search")
    hidden = classify_request("GET", "/.project-secrets/_search")

    assert isinstance(check_request(_profile(), cross_cluster), Deny)
    assert isinstance(check_request(_profile(), hidden), Deny)


def test_enforces_search_limits_and_injects_defaults():
    request = classify_request("POST", "/project-logs-*/_search", {})

    decision = check_request(_profile(), request, {})

    assert isinstance(decision, Allow)
    assert decision.body["size"] == 10
    assert decision.body["timeout"] == "10s"

    too_large = check_request(_profile(), request, {"size": 51})
    assert isinstance(too_large, Deny)
    assert "max_hits" in too_large.reason

    aggregation = check_request(
        _profile(),
        request,
        {"aggs": {"services": {"terms": {"field": "service"}}}},
    )
    assert isinstance(aggregation, Allow)
    assert aggregation.body["size"] == 0


def test_denies_scripts_and_large_aggregations():
    script_request = classify_request(
        "POST",
        "/project-logs-*/_search",
        {"script_fields": {"value": {"script": "1"}}},
    )
    terms_request = classify_request(
        "POST",
        "/project-logs-*/_search",
        {"aggs": {"services": {"terms": {"field": "service", "size": 21}}}},
    )

    assert isinstance(
        check_request(_profile(), script_request, {"script_fields": {}}), Deny
    )
    assert isinstance(
        check_request(
            _profile(),
            terms_request,
            {"aggs": {"services": {"terms": {"field": "service", "size": 21}}}},
        ),
        Deny,
    )


def test_denies_long_timeouts_and_body_index_overrides():
    search = classify_request("POST", "/project-logs-*/_search", {})
    multi_get = classify_request("POST", "/project-events/_mget", {})

    assert isinstance(
        check_request(_profile(), search, {"timeout": "1m"}), Deny
    )
    assert isinstance(
        check_request(
            _profile(),
            multi_get,
            {"docs": [{"_index": "other-project", "_id": "1"}]},
        ),
        Deny,
    )


def test_denies_cross_index_terms_lookup():
    body = {
        "query": {
            "terms": {
                "user.id": {
                    "index": "other-project",
                    "id": "allowed-users",
                    "path": "ids",
                }
            }
        }
    }
    search = classify_request("POST", "/project-logs-*/_search", body)

    assert isinstance(check_request(_profile(), search, body), Deny)


def test_write_requires_approval_and_operation_allow_list():
    update = classify_request(
        "POST", "/project-events/_update/1", {"doc": {"status": "done"}}
    )
    delete = classify_request("DELETE", "/project-events/_doc/1")

    update_decision = check_request(
        _profile(), update, {"doc": {"status": "done"}}
    )
    delete_decision = check_request(_profile(), delete)

    assert isinstance(update_decision, Allow)
    assert update_decision.mode == ActionMode.APPROVE
    assert isinstance(delete_decision, Deny)
    assert "not write-allowed" in delete_decision.reason


def test_document_operations_require_exact_target_and_no_expansion_param():
    wildcard_get = classify_request("GET", "/project-logs-*/_doc/1")
    exact_get = classify_request("GET", "/project-events/_doc/1")

    assert isinstance(check_request(_profile(), wildcard_get), Deny)
    exact_decision = check_request(_profile(), exact_get)
    assert isinstance(exact_decision, Allow)
    assert "expand_wildcards" not in exact_decision.params
