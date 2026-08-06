"""Tests for issue-creation and update etiquette."""

# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=unused-argument
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
import requests

from phantomcreds.config import MAX_ISSUES_PER_ROLLING_WINDOW, ROLLING_ISSUE_WINDOW_HOURS
from phantomcreds.models import NotificationRecord, RepoFinding, RepoReport
from phantomcreds.notifier import notify_all

SCAN_DATE = "2026-05-18"


class FakeClient:
    """Record notifier interactions for assertions."""

    def __init__(
        self,
        existing_issue: int | None = None,
        comments: list[str] | None = None,
        existing_state: str = "open",
    ) -> None:
        self.existing_issue = existing_issue
        self.existing_state = existing_state
        self.comments = comments or []
        self.created: list[tuple[str, str, str, list[str]]] = []
        self.added_comments: list[tuple[str, int, str]] = []
        self.find_calls: list[tuple[str, str, tuple[str, ...] | None]] = []

    def find_issue(
        self,
        owner_repo: str,
        title_fragment: str,
        body_markers: tuple[str, ...] | None = None,
    ) -> tuple[int, str] | None:
        """Return the configured issue number and state, if any."""
        self.find_calls.append((owner_repo, title_fragment, body_markers))
        if self.existing_issue is None:
            return None
        return self.existing_issue, self.existing_state

    def create_issue(self, owner_repo: str, title: str, body: str, labels: list[str]) -> int:
        """Record created issues and return a synthetic issue number."""
        self.created.append((owner_repo, title, body, labels))
        return 123

    def list_issue_comments(self, owner_repo: str, issue_number: int) -> list[str]:
        """Return preloaded comments for duplicate-update checks."""
        return list(self.comments)

    def add_comment(self, owner_repo: str, issue_number: int, body: str) -> None:
        """Record appended issue comments."""
        self.added_comments.append((owner_repo, issue_number, body))


def _report(action: str = "file_issue") -> RepoReport:
    """Build a report fixture with a configurable action."""
    return RepoReport(
        full_name="owner/repo",
        composite=0.85,
        classification="high_risk",
        action=action,  # type: ignore[arg-type]
        finding_count=2,
        issue_worthy_count=2,
        stars=99,
        scan_date=SCAN_DATE,
        created_at="2026-05-01T00:00:00Z",
        updated_at="2026-05-18T00:00:00Z",
        discovery_sources=("raw-auth-forwarding",),
        finding_types=("raw_auth_forwarding", "wildcard_management_cors"),
    )


def _findings() -> list[RepoFinding]:
    """Return non-secret fixable findings for notifier tests."""
    return [
        RepoFinding(
            repo_full_name="owner/repo",
            finding_type="raw_auth_forwarding",
            title="Home request logging forwards raw Authorization headers",
            severity="high",
            confidence="confirmed",
            summary="Headers appear to be forwarded without redaction.",
            issue_worthy=True,
            scan_date=SCAN_DATE,
            evidence=("internal/logging/request_logger.go:204 - Headers: cloneHeaders(headers),",),
        ),
        RepoFinding(
            repo_full_name="owner/repo",
            finding_type="wildcard_management_cors",
            title="Wildcard CORS is applied to management endpoints",
            severity="high",
            confidence="confirmed",
            summary="Management routes inherit Access-Control-Allow-Origin: *.",
            issue_worthy=True,
            scan_date=SCAN_DATE,
            evidence=(
                'internal/api/server.go:1355 - c.Header("Access-Control-Allow-Origin", "*")',
            ),
        ),
    ]


def _secret_findings() -> list[RepoFinding]:
    """Return exposed-secret findings for notifier tests."""
    return [
        RepoFinding(
            repo_full_name="owner/repo",
            finding_type="exposed_secret",
            title=(
                "Secret-bearing credential material appears committed "
                "in current repository files"
            ),
            severity="high",
            confidence="confirmed",
            summary="Current repository files appear to contain committed credential material.",
            issue_worthy=True,
            scan_date=SCAN_DATE,
            evidence=(
                ".env:1 - OPENAI_API_KEY=[REDACTED:sk-pro...3456]",
                "deploy/id_rsa:1 - [REDACTED:-----BEGIN OPENSSH PRIVATE KEY-----]",
            ),
        )
    ]


def test_create_issue_when_no_open_thread_exists() -> None:
    client = FakeClient(existing_issue=None)
    records = notify_all(client, [_report()], _findings(), allowlist=set())
    assert len(client.created) == 1
    assert [record.event for record in records] == ["created"]
    # Looked up once, then re-checked immediately before creating.
    assert (
        client.find_calls
        == [
            (
                "owner/repo",
                "[phantomcreds] Credential-handling risks detected in this repository",
                ("<!-- phantomcreds:issue -->", "<!-- phantomcreds:issue:risks -->"),
            )
        ]
        * 2
    )
    assert (
        client.created[0][1]
        == "[phantomcreds] Credential-handling risks detected in this repository"
    )
    assert "<!-- phantomcreds:issue -->" in client.created[0][2]
    assert "<!-- phantomcreds:issue:risks -->" in client.created[0][2]
    assert "<!-- phantomcreds:scan:2026-05-18 -->" in client.created[0][2]
    assert "Created by [James Sawyer](https://github.com/tg12)" in client.created[0][2]
    assert "[Project repo](https://github.com/tg12/phantomcreds)" in client.created[0][2]
    assert not client.added_comments


def test_comment_existing_issue_when_open_thread_exists() -> None:
    client = FakeClient(existing_issue=77, comments=[])
    notify_all(client, [_report()], _findings(), allowlist=set())
    assert not client.created
    assert len(client.added_comments) == 1
    assert client.added_comments[0][1] == 77
    assert "This issue remains open." in client.added_comments[0][2]
    assert (
        "Source: [phantomcreds](https://github.com/tg12/phantomcreds)"
        in client.added_comments[0][2]
    )


def test_skip_duplicate_same_day_comment() -> None:
    client = FakeClient(
        existing_issue=77,
        comments=["<!-- phantomcreds:scan:2026-05-18 -->\nprevious update"],
    )
    notify_all(client, [_report()], _findings(), allowlist=set())
    assert not client.created
    assert not client.added_comments


def _http_error(status: int) -> requests.HTTPError:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    return requests.HTTPError(response=resp)


def test_403_on_create_issue_is_skipped_not_fatal() -> None:
    """A 403 means the token has no write access to the target repo; skip it."""
    client = FakeClient(existing_issue=None)
    client.create_issue = MagicMock(side_effect=_http_error(403))  # type: ignore[method-assign]
    notify_all(client, [_report()], _findings(), allowlist=set())
    assert not client.added_comments


@pytest.mark.parametrize("status", [404, 410, 422])
def test_non_fatal_http_errors_are_skipped(status: int) -> None:
    client = FakeClient(existing_issue=None)
    client.create_issue = MagicMock(side_effect=_http_error(status))  # type: ignore[method-assign]
    notify_all(client, [_report()], _findings(), allowlist=set())
    assert not client.added_comments


def test_500_on_create_issue_propagates() -> None:
    client = FakeClient(existing_issue=None)
    client.create_issue = MagicMock(side_effect=_http_error(500))  # type: ignore[method-assign]
    with pytest.raises(requests.HTTPError):
        notify_all(client, [_report()], _findings(), allowlist=set())


def test_report_only_repo_does_not_notify() -> None:
    client = FakeClient(existing_issue=None)
    notify_all(client, [_report(action="report_only")], _findings(), allowlist=set())
    assert not client.created
    assert not client.added_comments


def test_issue_body_includes_secret_indicators_and_llm_fix_guide() -> None:
    client = FakeClient(existing_issue=None)
    notify_all(client, [_report()], _secret_findings(), allowlist=set())

    assert (
        client.find_calls
        == [
            (
                "owner/repo",
                "[phantomcreds] Exposed secrets detected in this repository",
                ("<!-- phantomcreds:issue -->", "<!-- phantomcreds:issue:secrets -->"),
            )
        ]
        * 2
    )
    assert client.created[0][1] == "[phantomcreds] Exposed secrets detected in this repository"
    body = client.created[0][2]
    assert "<!-- phantomcreds:issue:secrets -->" in body
    assert "Exposed secret indicators" in body
    assert "OPENAI_API_KEY" in body
    assert "OPENSSH PRIVATE KEY" in body
    assert "LLM Fix Guide" in body
    assert "Revoke or rotate the exposed credential" in body
    assert "current files fetched from the repository's default branch" in body


def test_issue_body_documents_how_to_opt_out() -> None:
    client = FakeClient(existing_issue=None)
    notify_all(client, [_report()], _findings(), allowlist=set())
    body = client.created[0][2]
    assert "Stop this bot contacting this repository" in body
    assert "no-phantomcreds" in body
    assert ".github/phantomcreds-opt-out" in body
    assert "closed phantomcreds issue is treated as a refusal" in body


def test_closed_prior_issue_is_never_refiled_or_commented() -> None:
    client = FakeClient(existing_issue=77, existing_state="closed")
    records = notify_all(client, [_report()], _findings(), allowlist=set())
    assert not client.created
    assert not client.added_comments
    assert [record.event for record in records] == ["skipped_closed"]


def test_allowlisted_repo_is_not_contacted_even_when_scored_file_issue() -> None:
    client = FakeClient(existing_issue=None)
    records = notify_all(client, [_report()], _findings(), allowlist={"owner/repo"})
    assert not client.created
    assert not client.added_comments
    assert [record.event for record in records] == ["blocked_allowlist"]


def test_rolling_window_ceiling_blocks_new_issues() -> None:
    now = datetime.now(UTC)
    prior = [
        NotificationRecord(
            repo_full_name=f"other/repo{index}",
            event="created",
            issue_number=index,
            title="[phantomcreds] Exposed secrets detected in this repository",
            scan_date=SCAN_DATE,
            recorded_at=(now - timedelta(hours=1)).isoformat(),
        )
        for index in range(MAX_ISSUES_PER_ROLLING_WINDOW)
    ]
    client = FakeClient(existing_issue=None)
    records = notify_all(
        client, [_report()], _findings(), allowlist=set(), prior_notifications=prior
    )
    assert not client.created
    assert [record.event for record in records] == ["blocked_rate_limit"]


def test_rolling_window_ignores_notifications_outside_the_window() -> None:
    stale = datetime.now(UTC) - timedelta(hours=ROLLING_ISSUE_WINDOW_HOURS + 1)
    prior = [
        NotificationRecord(
            repo_full_name=f"other/repo{index}",
            event="created",
            issue_number=index,
            title="[phantomcreds] Exposed secrets detected in this repository",
            scan_date=SCAN_DATE,
            recorded_at=stale.isoformat(),
        )
        for index in range(MAX_ISSUES_PER_ROLLING_WINDOW + 5)
    ]
    client = FakeClient(existing_issue=None)
    records = notify_all(
        client, [_report()], _findings(), allowlist=set(), prior_notifications=prior
    )
    assert len(client.created) == 1
    assert [record.event for record in records] == ["created"]
