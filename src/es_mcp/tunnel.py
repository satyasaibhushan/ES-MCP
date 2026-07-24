"""Lazy, per-profile SSH tunnel lifecycle."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko
from sshtunnel import SSHTunnelForwarder

from .profiles import Profile, SSHConfig


class TunnelError(RuntimeError):
    pass


@dataclass(frozen=True)
class TunnelEndpoint:
    host: str
    port: int


_DISABLED_PUBKEYS = ["rsa-sha2-512", "rsa-sha2-256", "ssh-dss"]
_TRANSPORT_PATCH_LOCK = threading.Lock()
_HOST_KEY_PREFERENCE = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp256",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
)


def _start_with_legacy_rsa(tunnel: SSHTunnelForwarder) -> None:
    """Match OpenSSH fallback behavior for older SSH gateways."""
    with _TRANSPORT_PATCH_LOCK:
        original_init = paramiko.Transport.__init__

        def patched(self: paramiko.Transport, *args: Any, **kwargs: Any) -> None:
            kwargs.setdefault(
                "disabled_algorithms", {"pubkeys": _DISABLED_PUBKEYS}
            )
            original_init(self, *args, **kwargs)

        paramiko.Transport.__init__ = patched  # type: ignore[method-assign]
        try:
            tunnel.start()
        finally:
            paramiko.Transport.__init__ = original_init  # type: ignore[method-assign]


def _resolve_key_path(ssh: SSHConfig) -> str | None:
    if ssh.key_path:
        path = Path(ssh.key_path).expanduser()
        if not path.exists():
            raise TunnelError(f"SSH key not found: {path}")
        return str(path)
    for name in ("id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"):
        candidate = Path.home() / ".ssh" / name
        if candidate.exists():
            return str(candidate)
    return None


def _parse_host_key(line: str) -> paramiko.PKey:
    entry = paramiko.hostkeys.HostKeyEntry.from_line(line.strip())
    if entry is None or entry.key is None:
        raise TunnelError("ssh.host_key is not a valid known_hosts entry")
    return entry.key


def _load_known_host_key(ssh: SSHConfig) -> paramiko.PKey | None:
    if not ssh.verify_host_key:
        return None
    if ssh.host_key:
        return _parse_host_key(ssh.host_key)
    if ssh.host is None:
        raise TunnelError("SSH host is not configured")
    path = Path(ssh.known_hosts_path).expanduser()
    if not path.exists():
        raise TunnelError(f"SSH known_hosts file not found: {path}")
    keys = paramiko.HostKeys()
    try:
        keys.load(str(path))
    except (OSError, paramiko.SSHException) as exc:
        raise TunnelError(f"Could not read SSH known_hosts file: {path}") from exc
    lookup_name = ssh.host if ssh.port == 22 else f"[{ssh.host}]:{ssh.port}"
    matches = keys.lookup(lookup_name)
    if not matches:
        raise TunnelError(
            f"SSH host {lookup_name!r} is not present in {path}"
        )
    for key_type in _HOST_KEY_PREFERENCE:
        if key_type in matches:
            return matches[key_type]
    return next(iter(matches.values()))


class TunnelManager:
    def __init__(self, profile: Profile):
        if not profile.ssh.enabled:
            raise ValueError("TunnelManager requires an SSH-enabled profile")
        self.profile = profile
        self._lock = threading.Lock()
        self._tunnel: SSHTunnelForwarder | None = None

    def ensure(self) -> TunnelEndpoint:
        with self._lock:
            if self._tunnel is not None and self._tunnel.is_active:
                return TunnelEndpoint(
                    self._tunnel.local_bind_host,
                    self._tunnel.local_bind_port,
                )
            self._stop_locked()
            ssh = self.profile.ssh
            if (
                ssh.host is None
                or ssh.user is None
                or ssh.remote_host is None
                or ssh.remote_port is None
            ):
                raise TunnelError("SSH profile is incomplete")
            kwargs: dict[str, Any] = {
                "ssh_username": ssh.user,
                "ssh_host_key": _load_known_host_key(ssh),
                "remote_bind_address": (ssh.remote_host, ssh.remote_port),
                "local_bind_address": (
                    ssh.local_host,
                    ssh.local_port or 0,
                ),
                "host_pkey_directories": [],
                "set_keepalive": float(ssh.keepalive_seconds),
            }
            key_path = _resolve_key_path(ssh)
            if key_path:
                kwargs["ssh_pkey"] = key_path
                kwargs["allow_agent"] = False
            else:
                kwargs["allow_agent"] = True
            if ssh.key_passphrase_env:
                passphrase = os.environ.get(ssh.key_passphrase_env)
                if passphrase:
                    kwargs["ssh_private_key_password"] = passphrase
            tunnel = SSHTunnelForwarder((ssh.host, ssh.port), **kwargs)
            try:
                _start_with_legacy_rsa(tunnel)
            except Exception as exc:
                try:
                    tunnel.stop()
                except Exception:
                    pass
                raise TunnelError(
                    f"Could not start SSH tunnel for profile {self.profile.name!r} "
                    f"({type(exc).__name__}: {exc})"
                ) from exc
            self._tunnel = tunnel
            return TunnelEndpoint(tunnel.local_bind_host, tunnel.local_bind_port)

    def status(self) -> dict[str, Any]:
        with self._lock:
            active = self._tunnel is not None and self._tunnel.is_active
            return {
                "enabled": True,
                "active": active,
                "local_host": (
                    self._tunnel.local_bind_host if active else None
                ),
                "local_port": (
                    self._tunnel.local_bind_port if active else None
                ),
                "remote_host": self.profile.ssh.remote_host,
                "remote_port": self.profile.ssh.remote_port,
            }

    def _stop_locked(self) -> None:
        if self._tunnel is not None:
            try:
                self._tunnel.stop()
            except Exception:
                pass
            self._tunnel = None

    def close(self) -> None:
        with self._lock:
            self._stop_locked()
