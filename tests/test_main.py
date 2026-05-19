"""Tests for candidate discovery and recency filtering."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from phantomcreds.github_client import GitHubClient
from phantomcreds.main import (
    _candidate_score,
    _filter_recent_candidates,
    _is_text_like_path,
    _parse_github_timestamp,
    _process_candidates,
    _resolve_runtime_options,
    _select_paths,
    _select_secret_sweep_paths,
    _source_family,
)
from phantomcreds.models import RepoFinding, RepoMetadata, RepoReport


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


def test_rate_limit_check_does_not_sleep_for_healthy_search_bucket(
    monkeypatch,
) -> None:
    client = GitHubClient("test-token")
    response = MagicMock()
    response.headers = {
        "X-RateLimit-Resource": "search",
        "X-RateLimit-Limit": "30",
        "X-RateLimit-Remaining": "29",
        "X-RateLimit-Reset": "2000000000",
    }
    response.status_code = 200

    sleep_calls: list[int] = []
    monkeypatch.setattr("phantomcreds.github_client.time.sleep", sleep_calls.append)

    client._check_rate_limit(response)

    assert sleep_calls == []


def test_rate_limit_check_sleeps_when_code_search_bucket_is_nearly_empty(
    monkeypatch,
) -> None:
    client = GitHubClient("test-token")
    response = MagicMock()
    response.headers = {
        "X-RateLimit-Resource": "code_search",
        "X-RateLimit-Limit": "10",
        "X-RateLimit-Remaining": "1",
        "X-RateLimit-Reset": "2000000000",
    }
    response.status_code = 200

    monkeypatch.setattr("phantomcreds.github_client.time.time", lambda: 1999999990)
    sleep_calls: list[int] = []
    monkeypatch.setattr("phantomcreds.github_client.time.sleep", sleep_calls.append)

    client._check_rate_limit(response)

    assert sleep_calls == [15]


def test_process_candidates_continues_after_repo_failure(monkeypatch) -> None:
    metadata_by_repo = {
        "owner/good": _metadata("owner/good", pushed_at="2026-05-18T11:30:00Z"),
        "owner/bad": _metadata("owner/bad", pushed_at="2026-05-18T11:45:00Z"),
    }
    scanned: list[str] = []

    def fake_scan_repository(
        client,
        repo_full_name: str,
        metadata: RepoMetadata,
        code_hits: set[str],
        discovery_sources: set[str],
        scan_date: str,
    ) -> tuple[RepoReport, list[RepoFinding]]:
        scanned.append(repo_full_name)
        if repo_full_name == "owner/bad":
            raise RuntimeError("boom")
        return (
            RepoReport(
                full_name=repo_full_name,
                composite=0.7,
                classification="high_risk",
                action="file_issue",
                finding_count=1,
                issue_worthy_count=1,
                stars=metadata.stargazers_count,
                scan_date=scan_date,
                created_at=metadata.created_at,
                updated_at=metadata.updated_at,
                discovery_sources=tuple(sorted(discovery_sources)),
                finding_types=("exposed_secret",),
            ),
            [
                RepoFinding(
                    repo_full_name=repo_full_name,
                    finding_type="exposed_secret",
                    title="Secret-bearing credential material appears committed in current repository files",
                    severity="high",
                    confidence="confirmed",
                    summary="Current repository files appear to contain committed credential material.",
                    issue_worthy=True,
                    scan_date=scan_date,
                    evidence=(".env:1 - OPENAI_API_KEY=[REDACTED:sk-pro...3456]",),
                )
            ],
        )

    monkeypatch.setattr("phantomcreds.main._scan_repository", fake_scan_repository)

    reports, findings, failed_repos = _process_candidates(
        client=MagicMock(),
        candidates=["owner/good", "owner/bad"],
        metadata_by_repo=metadata_by_repo,
        code_paths={"owner/good": set(), "owner/bad": set()},
        candidate_sources={
            "owner/good": {"auth-import-posture"},
            "owner/bad": {"auth-import-posture"},
        },
        allowlist=set(),
        scan_date="2026-05-18",
    )

    assert scanned == ["owner/good", "owner/bad"]
    assert [report.full_name for report in reports] == ["owner/good"]
    assert [finding.repo_full_name for finding in findings] == ["owner/good"]
    assert failed_repos == ["owner/bad"]
