"""Fixtures for repo-level credential-risk tests."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import pytest

from phantomcreds.models import RepoMetadata


@pytest.fixture
def repo_metadata() -> RepoMetadata:
    return RepoMetadata(
        full_name="owner/repo",
        description="Repository description",
        default_branch="main",
        stargazers_count=123,
        created_at="2026-05-01T00:00:00Z",
        pushed_at="2026-05-18T00:00:00Z",
        updated_at="2026-05-18T00:00:00Z",
        archived=False,
        fork=False,
    )
