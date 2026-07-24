import json

import httpx
import pytest

from es_mcp.client import ElasticsearchClient, ResponseTooLargeError
from es_mcp.profiles import (
    AuthConfig,
    Permissions,
    Profile,
    RequestLimits,
    TLSConfig,
)


def _profile(max_response_bytes: int = 1_000) -> Profile:
    return Profile(
        name="project",
        url="https://es.example.test",
        auth=AuthConfig(api_key="secret"),
        tls=TLSConfig(),
        limits=RequestLimits(max_response_bytes=max_response_bytes),
        permissions=Permissions(read_indices=("project-*",)),
    )


def test_executes_with_api_key_and_parses_json():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "ApiKey secret"
        assert request.url.path == "/project-logs/_search"
        assert json.loads(request.content)["size"] == 10
        return httpx.Response(
            200,
            json={"hits": {"hits": []}},
            headers={"X-Elastic-Product": "Elasticsearch"},
        )

    client = ElasticsearchClient(_profile(), httpx.MockTransport(handler))

    response = client.execute(
        method="POST",
        path="/project-logs/_search",
        body={"size": 10},
        params={"expand_wildcards": "open"},
    )

    assert response.status_code == 200
    assert response.body == {"hits": {"hits": []}}
    assert response.headers["x-elastic-product"] == "Elasticsearch"


def test_aborts_oversized_response():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"x" * 11)
    )
    client = ElasticsearchClient(_profile(max_response_bytes=10), transport)

    with pytest.raises(ResponseTooLargeError):
        client.execute(
            method="GET",
            path="/project-logs/_search",
            body=None,
            params={},
        )

