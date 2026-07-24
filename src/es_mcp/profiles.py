"""Load named Elasticsearch connection and policy profiles."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from .actions import ActionMode, ActionTier


class ProfileError(ValueError):
    pass


@dataclass(frozen=True)
class AuthConfig:
    none: bool = False
    direct: bool = False
    api_key: str | None = None
    api_key_env: str | None = None
    bearer_token: str | None = None
    bearer_token_env: str | None = None
    username: str | None = None
    password: str | None = None
    password_env: str | None = None

    def mode(self) -> str:
        if self.none:
            return "none"
        if self.api_key is not None or self.api_key_env is not None:
            return "api_key"
        if self.bearer_token is not None or self.bearer_token_env is not None:
            return "bearer"
        if self.username is not None:
            return "basic"
        raise ProfileError("No authentication method is configured")

    def credentials(self) -> tuple[str, str | tuple[str, str] | None]:
        if self.none:
            return ("none", None)
        if self.api_key is not None:
            return ("api_key", self.api_key)
        if self.api_key_env is not None:
            value = os.environ.get(self.api_key_env)
            if value is None:
                raise ProfileError(f"Required env var {self.api_key_env!r} is not set")
            return ("api_key", value)
        if self.bearer_token is not None:
            return ("bearer", self.bearer_token)
        if self.bearer_token_env is not None:
            value = os.environ.get(self.bearer_token_env)
            if value is None:
                raise ProfileError(
                    f"Required env var {self.bearer_token_env!r} is not set"
                )
            return ("bearer", value)
        if self.username is not None:
            password = self.password
            if password is None and self.password_env is not None:
                password = os.environ.get(self.password_env)
            if password is None:
                raise ProfileError("Basic authentication password is not configured")
            return ("basic", (self.username, password))
        raise ProfileError("No authentication method is configured")


@dataclass(frozen=True)
class SSHConfig:
    enabled: bool = False
    host: str | None = None
    port: int = 22
    user: str | None = None
    key_path: str | None = None
    key_passphrase_env: str | None = None
    host_key: str | None = None
    verify_host_key: bool = True
    known_hosts_path: str = "~/.ssh/known_hosts"
    local_host: str = "127.0.0.1"
    local_port: int | None = None
    remote_host: str | None = None
    remote_port: int | None = None
    keepalive_seconds: int = 30


@dataclass(frozen=True)
class TLSConfig:
    verify: bool = True
    ca_cert: str | None = None


@dataclass(frozen=True)
class RequestLimits:
    timeout_seconds: int = 10
    max_hits: int = 200
    max_from: int = 1_000
    max_aggregation_size: int = 1_000
    max_request_bytes: int = 262_144
    max_response_bytes: int = 2_097_152
    allow_scripts: bool = False


@dataclass(frozen=True)
class Permissions:
    read_indices: tuple[str, ...]
    write_indices: dict[str, frozenset[str]] = field(default_factory=dict)
    modes: dict[ActionTier, ActionMode] = field(default_factory=dict)
    allow_system_indices: bool = False

    def mode_for(self, tier: ActionTier) -> ActionMode:
        return self.modes.get(tier, ActionMode.DENY)


@dataclass(frozen=True)
class Profile:
    name: str
    url: str
    auth: AuthConfig
    tls: TLSConfig
    limits: RequestLimits
    permissions: Permissions
    ssh: SSHConfig = field(default_factory=SSHConfig)

    def capability_summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "auth_mode": self.auth.mode(),
            "ssh": {
                "enabled": self.ssh.enabled,
                "host": self.ssh.host if self.ssh.enabled else None,
                "remote_host": self.ssh.remote_host if self.ssh.enabled else None,
                "remote_port": self.ssh.remote_port if self.ssh.enabled else None,
                "dynamic_local_port": (
                    self.ssh.local_port is None if self.ssh.enabled else None
                ),
            },
            "read_indices": list(self.permissions.read_indices),
            "write_indices": {
                pattern: sorted(operations)
                for pattern, operations in self.permissions.write_indices.items()
            },
            "actions": {
                tier.name.lower(): self.permissions.mode_for(tier).value
                for tier in ActionTier
            },
        }


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_INDEX_PATTERN_RE = re.compile(r"^[a-z0-9._+-]+\*?$")
_ACTION_NAMES = {
    "discovery": ActionTier.DISCOVERY,
    "read": ActionTier.READ,
    "expensive_read": ActionTier.EXPENSIVE_READ,
    "document_write": ActionTier.DOCUMENT_WRITE,
    "structural_write": ActionTier.STRUCTURAL_WRITE,
    "admin": ActionTier.ADMIN,
}
_DEFAULT_MODES = {
    ActionTier.DISCOVERY: ActionMode.ALLOW,
    ActionTier.READ: ActionMode.ALLOW,
    ActionTier.EXPENSIVE_READ: ActionMode.DENY,
    ActionTier.DOCUMENT_WRITE: ActionMode.DENY,
    ActionTier.STRUCTURAL_WRITE: ActionMode.DENY,
    ActionTier.ADMIN: ActionMode.DENY,
}


def _interpolate(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _interpolate(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_interpolate(child) for child in value]
    if not isinstance(value, str):
        return value

    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in os.environ:
            return os.environ[name]
        if default is not None:
            return default
        missing.append(name)
        return ""

    result = _ENV_RE.sub(replace, value)
    if missing:
        names = ", ".join(sorted(set(missing)))
        raise ProfileError(f"Required env var(s) not set: {names}")
    return result


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be an object")
    return value


def _parse_bool(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    raise ProfileError(f"{label} must be a boolean")


def _validate_pattern(pattern: Any, label: str) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ProfileError(f"{label} entries must be non-empty strings")
    if pattern in {"*", "_all"}:
        raise ProfileError(f"{label} cannot grant every index")
    if "," in pattern or ":" in pattern or pattern.startswith("-"):
        raise ProfileError(
            f"{label} entries cannot contain commas, exclusions, or remote clusters"
        )
    if any(char in pattern for char in "?[]"):
        raise ProfileError(f"{label} only supports exact names or a trailing '*'")
    if "*" in pattern and (pattern.count("*") != 1 or not pattern.endswith("*")):
        raise ProfileError(f"{label} only supports exact names or a trailing '*'")
    if not _INDEX_PATTERN_RE.fullmatch(pattern):
        raise ProfileError(
            f"{label} entries contain unsupported index-name characters"
        )
    return pattern


def _parse_auth(raw: dict[str, Any]) -> AuthConfig:
    supported = {
        "none",
        "direct",
        "api_key",
        "api_key_env",
        "bearer_token",
        "bearer_token_env",
        "username",
        "password",
        "password_env",
    }
    unknown = sorted(set(raw) - supported)
    if unknown:
        raise ProfileError(f"Unknown auth field(s): {', '.join(unknown)}")
    none = _parse_bool(raw.get("none", False), "auth.none")
    direct = _parse_bool(raw.get("direct", False), "auth.direct")
    if direct and not none:
        raise ProfileError("auth.direct is only valid together with auth.none")
    auth = AuthConfig(
        none=none,
        direct=direct,
        api_key=raw.get("api_key"),
        api_key_env=raw.get("api_key_env"),
        bearer_token=raw.get("bearer_token"),
        bearer_token_env=raw.get("bearer_token_env"),
        username=raw.get("username"),
        password=raw.get("password"),
        password_env=raw.get("password_env"),
    )
    methods = sum(
        (
            auth.none,
            auth.api_key is not None or auth.api_key_env is not None,
            auth.bearer_token is not None or auth.bearer_token_env is not None,
            auth.username is not None,
        )
    )
    if methods != 1:
        raise ProfileError("Configure exactly one authentication method")
    if auth.username is not None and auth.password is None and auth.password_env is None:
        raise ProfileError("Basic authentication requires password or password_env")
    return auth


def _optional_port(value: Any, label: str) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ProfileError(f"{label} must be a valid TCP port")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"{label} must be a valid TCP port") from exc
    if not 1 <= port <= 65_535:
        raise ProfileError(f"{label} must be between 1 and 65535")
    return port


def _parse_ssh(raw_value: Any, url: str) -> SSHConfig:
    if raw_value is None:
        return SSHConfig()
    raw = _require_mapping(raw_value, "ssh")
    supported = {
        "enabled",
        "host",
        "port",
        "user",
        "key_path",
        "key_passphrase_env",
        "host_key",
        "verify_host_key",
        "known_hosts_path",
        "local_host",
        "local_port",
        "remote_host",
        "remote_port",
        "keepalive_seconds",
    }
    unknown = sorted(set(raw) - supported)
    if unknown:
        raise ProfileError(f"Unknown ssh field(s): {', '.join(unknown)}")
    enabled = _parse_bool(raw.get("enabled", False), "ssh.enabled")
    if not enabled:
        return SSHConfig()

    split = urlsplit(url)
    host = raw.get("host")
    user = raw.get("user")
    if not isinstance(host, str) or not host.strip():
        raise ProfileError("ssh.host is required when SSH is enabled")
    if not isinstance(user, str) or not user.strip():
        raise ProfileError("ssh.user is required when SSH is enabled")
    local_host = raw.get("local_host", "127.0.0.1")
    if local_host != "127.0.0.1":
        raise ProfileError("ssh.local_host must be 127.0.0.1")
    remote_host = raw.get("remote_host", split.hostname)
    if not isinstance(remote_host, str) or not remote_host:
        raise ProfileError("ssh.remote_host could not be determined")
    if split.hostname != remote_host:
        raise ProfileError("ssh.remote_host must match the profile URL hostname")

    port = _optional_port(raw.get("port", 22), "ssh.port")
    remote_default = split.port or (443 if split.scheme == "https" else 80)
    remote_port = _optional_port(
        raw.get("remote_port", remote_default), "ssh.remote_port"
    )
    if port is None or remote_port is None:
        raise ProfileError("SSH and remote ports are required")
    keepalive = _positive_int(
        raw, "keepalive_seconds", 30, prefix="ssh"
    )
    return SSHConfig(
        enabled=True,
        host=host,
        port=port,
        user=user,
        key_path=raw.get("key_path") or None,
        key_passphrase_env=raw.get("key_passphrase_env") or None,
        host_key=raw.get("host_key") or None,
        verify_host_key=_parse_bool(
            raw.get("verify_host_key", True), "ssh.verify_host_key"
        ),
        known_hosts_path=raw.get("known_hosts_path", "~/.ssh/known_hosts"),
        local_host=local_host,
        local_port=_optional_port(raw.get("local_port"), "ssh.local_port"),
        remote_host=remote_host,
        remote_port=remote_port,
        keepalive_seconds=keepalive,
    )


def _parse_modes(raw: dict[str, Any]) -> dict[ActionTier, ActionMode]:
    modes = dict(_DEFAULT_MODES)
    for name, value in raw.items():
        if name not in _ACTION_NAMES:
            raise ProfileError(f"Unknown action tier: {name!r}")
        try:
            modes[_ACTION_NAMES[name]] = ActionMode(str(value).lower())
        except ValueError as exc:
            raise ProfileError(
                f"Action tier {name!r} must be allow, approve, or deny"
            ) from exc
    if modes[ActionTier.ADMIN] != ActionMode.DENY:
        raise ProfileError("admin actions are hard-denied in this version")
    if modes[ActionTier.STRUCTURAL_WRITE] != ActionMode.DENY:
        raise ProfileError("structural_write actions are hard-denied in this version")
    if modes[ActionTier.DOCUMENT_WRITE] == ActionMode.ALLOW:
        raise ProfileError("document_write must require approval or be denied")
    return modes


def _positive_int(
    raw: dict[str, Any], name: str, default: int, *, prefix: str = "limits"
) -> int:
    value = raw.get(name, default)
    if isinstance(value, bool):
        raise ProfileError(f"{prefix}.{name} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"{prefix}.{name} must be a positive integer") from exc
    if parsed <= 0:
        raise ProfileError(f"{prefix}.{name} must be a positive integer")
    return parsed


def _parse_profile(name: str, value: Any) -> Profile:
    raw = _require_mapping(value, f"profile {name!r}")
    url = raw.get("url")
    if not isinstance(url, str):
        raise ProfileError(f"profile {name!r} requires url")
    split = urlsplit(url)
    if split.scheme not in {"http", "https"} or not split.netloc:
        raise ProfileError(f"profile {name!r} url must be HTTP or HTTPS")
    if split.username or split.password or split.query or split.fragment:
        raise ProfileError("Credentials, query strings, and fragments are not allowed in url")

    auth = _parse_auth(_require_mapping(raw.get("auth"), f"profile {name!r}.auth"))
    ssh = _parse_ssh(raw.get("ssh"), url)
    if (
        auth.none
        and not ssh.enabled
        and not auth.direct
        and split.hostname
        not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }
    ):
        raise ProfileError(
            "auth.none requires SSH tunnelling, a loopback URL, or auth.direct "
            "for an intentionally internet-reachable endpoint"
        )
    tls_raw = _require_mapping(raw.get("tls", {}), f"profile {name!r}.tls")
    tls = TLSConfig(
        verify=_parse_bool(tls_raw.get("verify", True), "tls.verify"),
        ca_cert=tls_raw.get("ca_cert"),
    )
    if auth.direct:
        if ssh.enabled:
            raise ProfileError(
                "auth.direct and SSH tunnelling are mutually exclusive"
            )
        if split.scheme != "https":
            raise ProfileError("auth.direct requires an HTTPS url")
        if not tls.verify:
            raise ProfileError("auth.direct requires tls.verify: true")

    limits_raw = _require_mapping(raw.get("limits", {}), f"profile {name!r}.limits")
    limits = RequestLimits(
        timeout_seconds=_positive_int(limits_raw, "timeout_seconds", 10),
        max_hits=_positive_int(limits_raw, "max_hits", 200),
        max_from=_positive_int(limits_raw, "max_from", 1_000),
        max_aggregation_size=_positive_int(
            limits_raw, "max_aggregation_size", 1_000
        ),
        max_request_bytes=_positive_int(limits_raw, "max_request_bytes", 262_144),
        max_response_bytes=_positive_int(
            limits_raw, "max_response_bytes", 2_097_152
        ),
        allow_scripts=_parse_bool(
            limits_raw.get("allow_scripts", False), "limits.allow_scripts"
        ),
    )

    permissions_raw = _require_mapping(
        raw.get("permissions"), f"profile {name!r}.permissions"
    )
    reads_raw = _require_mapping(
        permissions_raw.get("reads", {}), f"profile {name!r}.permissions.reads"
    )
    read_values = reads_raw.get("indices", [])
    if not isinstance(read_values, list) or not read_values:
        raise ProfileError(f"profile {name!r} must allow at least one read index")
    read_indices = tuple(
        _validate_pattern(pattern, "permissions.reads.indices")
        for pattern in read_values
    )

    writes_raw = _require_mapping(
        permissions_raw.get("writes", {}), f"profile {name!r}.permissions.writes"
    )
    allowed_raw = _require_mapping(
        writes_raw.get("allowed", {}), f"profile {name!r}.permissions.writes.allowed"
    )
    write_indices: dict[str, frozenset[str]] = {}
    for pattern, operations in allowed_raw.items():
        validated = _validate_pattern(pattern, "permissions.writes.allowed")
        if not isinstance(operations, list) or not operations:
            raise ProfileError(f"write operations for {pattern!r} must be a list")
        normalized = frozenset(str(operation).upper() for operation in operations)
        unknown = normalized - {"CREATE", "INDEX", "UPDATE", "DELETE"}
        if unknown:
            raise ProfileError(
                f"unsupported write operation(s) for {pattern!r}: {sorted(unknown)}"
            )
        write_indices[validated] = normalized

    actions_raw = _require_mapping(
        permissions_raw.get("actions", {}), f"profile {name!r}.permissions.actions"
    )
    permissions = Permissions(
        read_indices=read_indices,
        write_indices=write_indices,
        modes=_parse_modes(actions_raw),
        allow_system_indices=_parse_bool(
            permissions_raw.get("allow_system_indices", False),
            "permissions.allow_system_indices",
        ),
    )
    if permissions.allow_system_indices:
        raise ProfileError("system and hidden indices are hard-denied in this version")
    if (
        permissions.mode_for(ActionTier.DOCUMENT_WRITE) != ActionMode.DENY
        and not write_indices
    ):
        raise ProfileError(
            "document_write is enabled but no write index operations are configured"
        )

    return Profile(
        name=name,
        url=url.rstrip("/"),
        auth=auth,
        tls=tls,
        limits=limits,
        permissions=permissions,
        ssh=ssh,
    )


def load_profiles(path: Path) -> dict[str, Profile]:
    try:
        raw_value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProfileError(f"Could not read profiles file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ProfileError(f"Invalid YAML in profiles file: {path}") from exc
    raw = _require_mapping(raw_value, "profiles file")
    profile_values = raw.get("profiles", raw)
    profile_map = _require_mapping(profile_values, "profiles")
    interpolated = _interpolate(profile_map)
    profiles = {
        name: _parse_profile(name, value) for name, value in interpolated.items()
    }
    if not profiles:
        raise ProfileError("At least one profile is required")
    return profiles


def default_profiles_path() -> Path:
    return Path(
        os.environ.get(
            "ES_MCP_PROFILES", Path.home() / ".es-access" / "profiles.yaml"
        )
    ).expanduser()
