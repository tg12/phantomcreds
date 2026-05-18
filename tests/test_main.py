"""Tests for candidate discovery and recency filtering."""

from __future__ import annotations

from datetime import UTC, datetime

from phantomcreds.main import _filter_recent_candidates, _parse_github_timestamp
from phantomcreds.models import RepoMetadata


class FakeClient:
    def __init__(self, metadata_by_repo: dict[str, RepoMetadata]) -> None:
        self.metadata_by_repo = metadata_by_repo

    def get_repo_metadata(self, repo_full_name: str) -> RepoMetadata:
        return self.metadata_by_repo[repo_full_name]


def _metadata(
    name: str,
    *,
    pushed_at: str,
    updated_at: str = "2026-05-18T00:00:00Z",
) -> RepoMetadata:
    return RepoMetadata(
        full_name=name,
        description=None,
        html_url=f"https://github.com/{name}",
        default_branch="main",
        stargazers_count=0,
        created_at="2026-05-01T00:00:00Z",
        pushed_at=pushed_at,
        updated_at=updated_at,
        archived=False,
        fork=False,
    )


def test_parse_github_timestamp_returns_utc_datetime() -> None:
    parsed = _parse_github_timestamp("2026-05-18T11:30:00Z")
    assert parsed == datetime(2026, 5, 18, 11, 30, tzinfo=UTC)


def test_filter_recent_candidates_keeps_recent_pushes_and_prefers_signal_count() -> None:
    candidate_sources = {
        "owner/stale": {"repo-query", "code-query"},
        "owner/fresh-high-signal": {"repo-query", "code-query", "code-query-2"},
        "owner/fresh-low-signal": {"repo-query"},
    }
    client = FakeClient(
        {
            "owner/stale": _metadata("owner/stale", pushed_at="2026-05-14T11:59:59Z"),
            "owner/fresh-high-signal": _metadata(
                "owner/fresh-high-signal",
                pushed_at="2026-05-18T11:30:00Z",
            ),
            "owner/fresh-low-signal": _metadata(
                "owner/fresh-low-signal",
                pushed_at="2026-05-18T11:45:00Z",
            ),
        }
    )

    candidates, metadata_by_repo = _filter_recent_candidates(
        client,
        candidate_sources,
        now=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
    )

    assert candidates == ["owner/fresh-high-signal", "owner/fresh-low-signal"]
    assert set(metadata_by_repo) == set(candidate_sources)
