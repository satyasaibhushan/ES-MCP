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
