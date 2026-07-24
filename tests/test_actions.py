from es_mcp.actions import ActionTier, classify_request


def test_get_and_post_search_are_reads():
    get_request = classify_request("GET", "/project-logs-*/_search")
    post_request = classify_request(
        "POST", "/project-logs-*/_search", {"query": {"match_all": {}}}
    )

    assert get_request.tier == ActionTier.READ
    assert post_request.tier == ActionTier.READ
    assert get_request.targets == ("project-logs-*",)


def test_expensive_body_changes_search_tier():
    request = classify_request(
        "POST",
        "/project-logs-*/_search",
        {"query": {"script_score": {"script": {"source": "1"}}}},
    )

    assert request.tier == ActionTier.EXPENSIVE_READ


def test_exact_total_hits_parameter_is_expensive():
    request = classify_request(
        "GET",
        "/project-logs-*/_search",
        params={"track_total_hits": "true"},
    )

    assert request.tier == ActionTier.EXPENSIVE_READ


def test_document_write_is_classified_by_route_and_method():
    request = classify_request(
        "POST", "/project-events/_update/123", {"doc": {"status": "done"}}
    )

    assert request.tier == ActionTier.DOCUMENT_WRITE
    assert request.operation == "UPDATE"


def test_get_security_endpoint_is_admin():
    request = classify_request("GET", "/_security/user")

    assert request.tier == ActionTier.ADMIN
    assert request.supported is False


def test_delete_by_query_is_structural():
    request = classify_request(
        "POST", "/project-events/_delete_by_query", {"query": {"match_all": {}}}
    )

    assert request.tier == ActionTier.STRUCTURAL_WRITE
    assert request.supported is False
