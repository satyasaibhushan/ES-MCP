"""Bounded Elasticsearch HTTP execution."""

from __future__ import annotations

import json
import ssl
import threading
from dataclasses import dataclass
from typing import Any

import httpx

from . import __version__
from .profiles import Profile
from .transport import TunnelHTTPTransport
from .tunnel import TunnelError, TunnelManager


class ElasticsearchError(RuntimeError):
    pass


class ResponseTooLargeError(ElasticsearchError):
    pass


@dataclass(frozen=True)
class ElasticsearchResponse:
    status_code: int
    body: Any
    headers: dict[str, str]


class ElasticsearchClient:
    def __init__(
        self,
        profile: Profile,
        transport: httpx.BaseTransport | None = None,
    ):
        self.profile = profile
        kind, credentials = profile.auth.credentials()
        headers = {
            "Accept": "application/json",
            "User-Agent": f"es-mcp/{__version__}",
        }
        auth: httpx.Auth | None = None
        if kind == "none":
            pass
        elif kind == "api_key":
            headers["Authorization"] = f"ApiKey {credentials}"
        elif kind == "bearer":
            headers["Authorization"] = f"Bearer {credentials}"
        else:
            if not isinstance(credentials, tuple):
                raise ElasticsearchError("Invalid basic authentication configuration")
            auth = httpx.BasicAuth(*credentials)

        verify: bool | ssl.SSLContext = profile.tls.verify
        if profile.tls.ca_cert:
            if not profile.tls.verify:
                raise ElasticsearchError("ca_cert cannot be used when TLS verification is off")
            verify = ssl.create_default_context(cafile=profile.tls.ca_cert)

        self._tunnel = TunnelManager(profile) if profile.ssh.enabled else None
        effective_transport = transport
        if self._tunnel is not None and effective_transport is None:
            if isinstance(verify, ssl.SSLContext):
                ssl_context = verify
            elif verify:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            effective_transport = TunnelHTTPTransport(
                tunnel=self._tunnel,
                ssl_context=ssl_context,
            )

        self._client = httpx.Client(
            auth=auth,
            headers=headers,
            timeout=httpx.Timeout(profile.limits.timeout_seconds),
            verify=verify,
            follow_redirects=False,
            transport=effective_transport,
        )

    def execute(
        self,
        *,
        method: str,
        path: str,
        body: Any,
        params: dict[str, Any],
    ) -> ElasticsearchResponse:
        url = f"{self.profile.url}{path}"
        request_kwargs: dict[str, Any] = {"params": params}
        if body is not None:
            request_kwargs["json"] = body

        try:
            with self._client.stream(method, url, **request_kwargs) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > self.profile.limits.max_response_bytes:
                        raise ResponseTooLargeError(
                            "Elasticsearch response exceeded max_response_bytes "
                            f"{self.profile.limits.max_response_bytes}"
                        )
                raw = bytes(content)
                if not raw:
                    parsed: Any = None
                else:
                    try:
                        parsed = json.loads(raw)
                    except json.JSONDecodeError:
                        parsed = raw.decode("utf-8", errors="replace")
                safe_headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                    if key.lower() in {"content-type", "warning", "x-elastic-product"}
                }
                return ElasticsearchResponse(
                    status_code=response.status_code,
                    body=parsed,
                    headers=safe_headers,
                )
        except ResponseTooLargeError:
            raise
        except TunnelError as exc:
            raise ElasticsearchError(str(exc)) from exc
        except httpx.TimeoutException as exc:
            raise ElasticsearchError("Elasticsearch request timed out") from exc
        except httpx.HTTPError as exc:
            raise ElasticsearchError(
                f"Elasticsearch request failed ({type(exc).__name__})"
            ) from exc

    def close(self) -> None:
        try:
            self._client.close()
        finally:
            if self._tunnel is not None:
                self._tunnel.close()

    def tunnel_status(self) -> dict[str, Any]:
        if self._tunnel is None:
            return {"enabled": False, "active": False}
        return self._tunnel.status()


class ClientRegistry:
    def __init__(self):
        self._clients: dict[str, ElasticsearchClient] = {}
        self._lock = threading.Lock()

    def get(self, profile: Profile) -> ElasticsearchClient:
        with self._lock:
            client = self._clients.get(profile.name)
            if client is None:
                client = ElasticsearchClient(profile)
                self._clients[profile.name] = client
            return client

    def check(self, profile: Profile) -> ElasticsearchResponse:
        return self.get(profile).execute(
            method="GET",
            path="/",
            body=None,
            params={},
        )

    def tunnel_status(self, profile: Profile) -> dict[str, Any]:
        with self._lock:
            client = self._clients.get(profile.name)
        if client is None:
            return {
                "enabled": profile.ssh.enabled,
                "active": False,
                "remote_host": (
                    profile.ssh.remote_host if profile.ssh.enabled else None
                ),
                "remote_port": (
                    profile.ssh.remote_port if profile.ssh.enabled else None
                ),
            }
        return client.tunnel_status()

    def close(self) -> None:
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            client.close()
