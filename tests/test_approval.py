import pytest

from es_mcp.approval import ApprovalError, ApprovalStore


def test_token_is_bound_and_single_use():
    store = ApprovalStore()
    record = store.issue(
        profile="project",
        canonical_request='{"method":"POST"}',
        operation="UPDATE",
        targets=("project-events",),
    )

    with pytest.raises(ApprovalError, match="does not match"):
        store.consume(
            token=record.token,
            profile="other",
            canonical_request='{"method":"POST"}',
        )

    with pytest.raises(ApprovalError, match="already-used"):
        store.consume(
            token=record.token,
            profile="project",
            canonical_request='{"method":"POST"}',
        )


def test_matching_token_can_be_consumed_once():
    store = ApprovalStore()
    record = store.issue(
        profile="project",
        canonical_request="request",
        operation="UPDATE",
        targets=("project-events",),
    )

    consumed = store.consume(
        token=record.token,
        profile="project",
        canonical_request="request",
    )

    assert consumed.operation == "UPDATE"
    with pytest.raises(ApprovalError, match="already-used"):
        store.consume(
            token=record.token,
            profile="project",
            canonical_request="request",
        )

