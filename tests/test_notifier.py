"""Tests for issue-creation and update etiquette."""

from __future__ import annotations

from phantomcreds.models import RepoFinding, RepoReport
from phantomcreds.notifier import notify_all

SCAN_DATE = "2026-05-18"


class FakeClient:
    def __init__(
        self, existing_issue: int | None = None, comments: list[str] | None = None
    ) -> None:
        self.existing_issue = existing_issue
        self.comments = comments or []
        self.created: list[tuple[str, str, str, list[str]]] = []
        self.added_comments: list[tuple[str, int, str]] = []

    def find_open_issue(self, owner_repo: str, title_fragment: str) -> int | None:
        return self.existing_issue

    def create_issue(self, owner_repo: str, title: str, body: str, labels: list[str]) -> int:
        self.created.append((owner_repo, title, body, labels))
        return 123

    def list_issue_comments(self, owner_repo: str, issue_number: int) -> list[str]:
        return list(self.comments)

    def add_comment(self, owner_repo: str, issue_number: int, body: str) -> None:
        self.added_comments.append((owner_repo, issue_number, body))


def _report(action: str = "file_issue") -> RepoReport:
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
    return [
        RepoFinding(
            repo_full_name="owner/repo",
            finding_type="exposed_secret",
            title="Secret-bearing credential material appears committed in current repository files",
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
    notify_all(client, [_report()], _findings())
    assert len(client.created) == 1
    assert "<!-- phantomcreds:issue -->" in client.created[0][2]
    assert "<!-- phantomcreds:scan:2026-05-18 -->" in client.created[0][2]
    assert "Created by [James Sawyer](https://github.com/tg12)" in client.created[0][2]
    assert "[Project repo](https://github.com/tg12/phantomcreds)" in client.created[0][2]
    assert client.added_comments == []


def test_comment_existing_issue_when_open_thread_exists() -> None:
    client = FakeClient(existing_issue=77, comments=[])
    notify_all(client, [_report()], _findings())
    assert client.created == []
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
    notify_all(client, [_report()], _findings())
    assert client.created == []
    assert client.added_comments == []


def test_report_only_repo_does_not_notify() -> None:
    client = FakeClient(existing_issue=None)
    notify_all(client, [_report(action="report_only")], _findings())
    assert client.created == []
    assert client.added_comments == []


def test_issue_body_includes_secret_indicators_and_llm_fix_guide() -> None:
    client = FakeClient(existing_issue=None)
    notify_all(client, [_report()], _secret_findings())

    body = client.created[0][2]
    assert "Exposed secret indicators" in body
    assert "OPENAI_API_KEY" in body
    assert "OPENSSH PRIVATE KEY" in body
    assert "LLM Fix Guide" in body
    assert "Revoke or rotate the exposed credential" in body
