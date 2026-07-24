from pathlib import Path

import pytest

from es_mcp.actions import ActionMode, ActionTier
from es_mcp.profiles import ProfileError, load_profiles


def _write_profile(path: Path, extra: str = "") -> None:
    path.write_text(
        f"""
profiles:
  project_uat:
    url: ${{TEST_ES_URL:-https://es.example.test}}
    auth:
      api_key_env: TEST_ES_API_KEY
    permissions:
      reads:
        indices:
          - project-logs-*
      writes:
        allowed:
          project-events:
            - UPDATE
      actions:
        document_write: approve
    {extra}
""",
        encoding="utf-8",
    )


def test_loads_profile_without_resolving_secret(tmp_path):
    path = tmp_path / "profiles.yaml"
    _write_profile(path)

    profile = load_profiles(path)["project_uat"]

    assert profile.url == "https://es.example.test"
    assert profile.permissions.read_indices == ("project-logs-*",)
    assert (
        profile.permissions.mode_for(ActionTier.DOCUMENT_WRITE)
        == ActionMode.APPROVE
    )


def test_rejects_global_index_pattern(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text(
        """
project:
  url: https://es.example.test
  auth:
    api_key_env: TEST_ES_API_KEY
  permissions:
    reads:
      indices: ["*"]
""",
        encoding="utf-8",
    )

    with pytest.raises(ProfileError, match="cannot grant every index"):
        load_profiles(path)


def test_rejects_structural_write_enablement(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text(
        """
project:
  url: https://es.example.test
  auth:
    api_key_env: TEST_ES_API_KEY
  permissions:
    reads:
      indices: ["project-*"]
    actions:
      structural_write: approve
""",
        encoding="utf-8",
    )

    with pytest.raises(ProfileError, match="hard-denied"):
        load_profiles(path)


def test_document_writes_cannot_bypass_approval(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text(
        """
project:
  url: https://es.example.test
  auth:
    api_key_env: TEST_ES_API_KEY
  permissions:
    reads:
      indices: ["project-*"]
    writes:
      allowed:
        project-events: [UPDATE]
    actions:
      document_write: allow
""",
        encoding="utf-8",
    )

    with pytest.raises(ProfileError, match="must require approval"):
        load_profiles(path)


def test_explicit_no_auth_requires_ssh_or_loopback(tmp_path):
    remote_path = tmp_path / "remote.yaml"
    remote_path.write_text(
        """
project:
  url: https://es.example.test
  auth:
    none: true
  permissions:
    reads:
      indices: ["project-*"]
""",
        encoding="utf-8",
    )
    loopback_path = tmp_path / "loopback.yaml"
    loopback_path.write_text(
        remote_path.read_text(encoding="utf-8").replace(
            "https://es.example.test", "https://127.0.0.1:9200"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ProfileError, match="requires SSH"):
        load_profiles(remote_path)
    assert load_profiles(loopback_path)["project"].auth.mode() == "none"


def test_loads_ssh_profile_with_dynamic_local_port(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text(
        """
project:
  url: https://es.example.test
  auth:
    none: true
  ssh:
    enabled: true
    host: ssh.example.test
    user: limited-user
    remote_host: es.example.test
    remote_port: 443
    local_port:
  permissions:
    reads:
      indices: ["project-*"]
""",
        encoding="utf-8",
    )

    profile = load_profiles(path)["project"]

    assert profile.ssh.enabled is True
    assert profile.ssh.local_port is None
    assert profile.ssh.remote_host == "es.example.test"
    assert profile.capability_summary()["auth_mode"] == "none"


def test_rejects_ssh_remote_host_different_from_url(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text(
        """
project:
  url: https://es.example.test
  auth:
    none: true
  ssh:
    enabled: true
    host: ssh.example.test
    user: limited-user
    remote_host: other.example.test
  permissions:
    reads:
      indices: ["project-*"]
""",
        encoding="utf-8",
    )

    with pytest.raises(ProfileError, match="must match"):
        load_profiles(path)
