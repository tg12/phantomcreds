"""Tests for candidate discovery and recency filtering."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from phantomcreds.main import (
    _candidate_score,
    _filter_recent_candidates,
    _is_text_like_path,
    _parse_github_timestamp,
    _resolve_runtime_options,
    _select_paths,
    _select_secret_sweep_paths,
    _source_family,
)
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


def test_source_family_collapses_language_suffixes() -> None:
    assert _source_family("token-persistence-go") == "token-persistence"
    assert _source_family("callback-exposure-typescript") == "callback-exposure"
    assert _source_family("shared-subscription-posture") == "shared-subscription-posture"


def test_candidate_score_penalizes_archived_and_forked_repos() -> None:
    sources = {"shared-subscription-posture", "token-persistence-go", "auth-import-typescript"}
    active_metadata = _metadata("owner/active", pushed_at="2026-05-18T11:30:00Z")
    weak_metadata = RepoMetadata(
        full_name="owner/weak",
        description=None,
        html_url="https://github.com/owner/weak",
        default_branch="main",
        stargazers_count=200,
        created_at="2026-05-01T00:00:00Z",
        pushed_at="2026-05-18T11:30:00Z",
        updated_at="2026-05-18T11:30:00Z",
        archived=True,
        fork=True,
    )

    active_score = _candidate_score("owner/active", sources, active_metadata)
    weak_score = _candidate_score("owner/weak", sources, weak_metadata)

    assert active_score > weak_score


def test_select_paths_prioritizes_secret_candidate_files() -> None:
    paths = _select_paths(
        [
            "README.md",
            "src/main.go",
            "deploy/id_rsa",
            ".env.production",
            "terraform.tfvars",
            "config.json",
            "internal/api/server.go",
        ],
        {"src/main.go"},
    )

    assert "README.md" in paths
    assert "deploy/id_rsa" in paths
    assert ".env.production" in paths
    assert "terraform.tfvars" in paths
    assert "config.json" in paths


def test_is_text_like_path_filters_binary_and_vendor_content() -> None:
    assert _is_text_like_path("src/app.py") is True
    assert _is_text_like_path("deploy/id_rsa") is True
    assert _is_text_like_path("assets/logo.png") is False
    assert _is_text_like_path("node_modules/pkg/index.js") is False


def test_select_secret_sweep_paths_collects_extra_text_files() -> None:
    sweep_paths = _select_secret_sweep_paths(
        [
            "README.md",
            "src/app.py",
            "docs/notes.txt",
            "assets/logo.png",
            "node_modules/pkg/index.js",
            "deploy/id_rsa",
        ],
        ["README.md"],
    )

    assert "src/app.py" in sweep_paths
    assert "docs/notes.txt" in sweep_paths
    assert "deploy/id_rsa" in sweep_paths
    assert "assets/logo.png" not in sweep_paths
    assert "node_modules/pkg/index.js" not in sweep_paths


def test_resolve_runtime_options_defaults_to_safe_local_mode(
    monkeypatch,
) -> None:
    monkeypatch.setenv("PHANTOMCREDS_LOCAL_MODE", "1")
    monkeypatch.delenv("PHANTOMCREDS_OUTPUT_DIR", raising=False)
    monkeypatch.delenv("PHANTOMCREDS_NOTIFY_EXTERNAL", raising=False)

    options = _resolve_runtime_options()

    assert options.reports_path == Path(".local/phantomcreds/repos.jsonl")
    assert options.findings_path == Path(".local/phantomcreds/findings.jsonl")
    assert options.readme_path is None
    assert options.notify_external is False


def test_resolve_runtime_options_supports_non_local_overrides(
    monkeypatch,
) -> None:
    monkeypatch.delenv("PHANTOMCREDS_LOCAL_MODE", raising=False)
    monkeypatch.setenv("PHANTOMCREDS_REPORTS_FILE", "/tmp/custom-repos.jsonl")
    monkeypatch.setenv("PHANTOMCREDS_FINDINGS_FILE", "/tmp/custom-findings.jsonl")
    monkeypatch.setenv("PHANTOMCREDS_ALLOWLIST_FILE", "/tmp/custom-allowlist.txt")
    monkeypatch.setenv("PHANTOMCREDS_README_PATH", "/tmp/custom-readme.md")
    monkeypatch.setenv("PHANTOMCREDS_NOTIFY_EXTERNAL", "0")
    monkeypatch.setenv("PHANTOMCREDS_UPDATE_README", "1")

    options = _resolve_runtime_options()

    assert options.reports_path == Path("/tmp/custom-repos.jsonl")
    assert options.findings_path == Path("/tmp/custom-findings.jsonl")
    assert options.allowlist_path == Path("/tmp/custom-allowlist.txt")
    assert options.readme_path == Path("/tmp/custom-readme.md")
    assert options.notify_external is False
