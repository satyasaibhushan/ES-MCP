from dataclasses import replace
from pathlib import Path

from es_mcp.profiles import (
    AuthConfig,
    Permissions,
    Profile,
    RequestLimits,
    SSHConfig,
    TLSConfig,
)
from es_mcp.tunnel import TunnelManager


def _profile(tmp_path: Path) -> Profile:
    key_path = tmp_path / "id_rsa"
    key_path.write_text("placeholder", encoding="utf-8")
    return Profile(
        name="project",
        url="https://es.example.test",
        auth=AuthConfig(none=True),
        tls=TLSConfig(),
        limits=RequestLimits(),
        permissions=Permissions(read_indices=("project-*",)),
        ssh=SSHConfig(
            enabled=True,
            host="ssh.example.test",
            user="limited-user",
            key_path=str(key_path),
            verify_host_key=False,
            remote_host="es.example.test",
            remote_port=443,
        ),
    )


def test_tunnel_is_lazy_reused_and_closed(monkeypatch, tmp_path):
    instances = []
    fake_key = object()

    class FakeForwarder:
        def __init__(self, address, **kwargs):
            self.address = address
            self.kwargs = kwargs
            self.is_active = False
            self.local_bind_host = "127.0.0.1"
            self.local_bind_port = 49152
            self.start_calls = 0
            self.stop_calls = 0
            instances.append(self)

        def start(self):
            self.start_calls += 1
            self.is_active = True

        def stop(self):
            self.stop_calls += 1
            self.is_active = False

    monkeypatch.setattr("es_mcp.tunnel.SSHTunnelForwarder", FakeForwarder)
    monkeypatch.setattr(
        "es_mcp.tunnel.paramiko.PKey.from_path",
        lambda path, passphrase=None: fake_key,
    )
    manager = TunnelManager(_profile(tmp_path))

    assert instances == []
    first = manager.ensure()
    second = manager.ensure()

    assert first == second
    assert first.host == "127.0.0.1"
    assert first.port == 49152
    assert len(instances) == 1
    assert instances[0].start_calls == 1
    assert instances[0].kwargs["local_bind_address"] == ("127.0.0.1", 0)
    assert instances[0].kwargs["remote_bind_address"] == (
        "es.example.test",
        443,
    )
    assert instances[0].kwargs["ssh_pkey"] is fake_key
    assert instances[0].kwargs["allow_agent"] is False

    manager.close()
    assert instances[0].stop_calls == 1


def test_dead_tunnel_is_replaced(monkeypatch, tmp_path):
    instances = []

    class FakeForwarder:
        def __init__(self, address, **kwargs):
            self.is_active = False
            self.local_bind_host = "127.0.0.1"
            self.local_bind_port = 49152 + len(instances)
            self.stop_calls = 0
            instances.append(self)

        def start(self):
            self.is_active = True

        def stop(self):
            self.stop_calls += 1
            self.is_active = False

    monkeypatch.setattr("es_mcp.tunnel.SSHTunnelForwarder", FakeForwarder)
    monkeypatch.setattr(
        "es_mcp.tunnel.paramiko.PKey.from_path",
        lambda path, passphrase=None: object(),
    )
    manager = TunnelManager(_profile(tmp_path))

    first = manager.ensure()
    instances[0].is_active = False
    second = manager.ensure()

    assert second.port != first.port
    assert len(instances) == 2
    assert instances[0].stop_calls == 1


def test_encrypted_key_without_passphrase_falls_back_to_agent(
    monkeypatch, tmp_path
):
    captured = {}

    class FakeForwarder:
        def __init__(self, address, **kwargs):
            captured.update(kwargs)
            self.is_active = False
            self.local_bind_host = "127.0.0.1"
            self.local_bind_port = 49152

        def start(self):
            self.is_active = True

        def stop(self):
            self.is_active = False

    monkeypatch.setattr("es_mcp.tunnel.SSHTunnelForwarder", FakeForwarder)
    from_path_calls = []
    monkeypatch.setattr(
        "es_mcp.tunnel.paramiko.PKey.from_path",
        lambda path, passphrase=None: from_path_calls.append(path),
    )
    profile = _profile(tmp_path)
    profile = replace(
        profile,
        ssh=replace(
            profile.ssh,
            key_passphrase_env="MISSING_TEST_KEY_PASSPHRASE",
        ),
    )

    TunnelManager(profile).ensure()

    assert captured["allow_agent"] is True
    assert "ssh_pkey" not in captured
    assert from_path_calls == []
