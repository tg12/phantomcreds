"""GitHub issue notifier for fixable credential-handling findings."""

from __future__ import annotations

import logging
from typing import Protocol

import requests

from phantomcreds.config import MAX_ISSUES_PER_SCAN
from phantomcreds.models import RepoFinding, RepoReport

_log = logging.getLogger(__name__)

_ISSUE_TITLE = "[phantomcreds] Credential-handling risks detected in this repository"
_ISSUE_MARKER = "<!-- phantomcreds:issue -->"


def _scan_marker(scan_date: str) -> str:
    return f"<!-- phantomcreds:scan:{scan_date} -->"


class IssueClient(Protocol):
    def find_open_issue(self, owner_repo: str, title_fragment: str) -> int | None: ...

    def create_issue(self, owner_repo: str, title: str, body: str, labels: list[str]) -> int: ...

    def list_issue_comments(self, owner_repo: str, issue_number: int) -> list[str]: ...

    def add_comment(self, owner_repo: str, issue_number: int, body: str) -> None: ...


def _finding_markdown(finding: RepoFinding) -> str:
    evidence = "\n".join(f"- `{ref}`" for ref in finding.evidence) or "- No evidence captured"
    return (
        f"### {finding.title}\n\n"
        f"- Severity: `{finding.severity}`\n"
        f"- Confidence: `{finding.confidence}`\n"
        f"- Summary: {finding.summary}\n\n"
        f"Evidence:\n{evidence}\n"
    )


def _issue_body(report: RepoReport, findings: list[RepoFinding]) -> str:
    finding_types = ", ".join(sorted({finding.finding_type for finding in findings}))
    sections = "\n".join(_finding_markdown(finding) for finding in findings)
    return f"""\
{_ISSUE_MARKER}
{_scan_marker(report.scan_date)}

## Credential-handling risk report for `{report.full_name}`

phantomcreds detected repo-level code or deployment patterns that warrant maintainer review.

| Metric | Value |
|--------|-------|
| Scan date | {report.scan_date} |
| Composite score | **{report.composite:.3f}** |
| Findings | {report.finding_count} |
| Issue-worthy findings | {report.issue_worthy_count} |
| Discovery sources | {", ".join(report.discovery_sources) or "--"} |

Detected finding types: `{finding_types}`

{sections}

---

This scan is evidence-first and probabilistic. It is not an accusation of malicious intent.
If any finding is incorrect or outdated, please reply with corrected context and exact file references.

Automated by [phantomcreds](https://github.com/tg12/phantomcreds).
"""


def _comment_body(report: RepoReport, findings: list[RepoFinding]) -> str:
    finding_types = ", ".join(sorted({finding.finding_type for finding in findings}))
    return (
        f"{_scan_marker(report.scan_date)}\n"
        f"### Scan update: {report.scan_date}\n\n"
        "This issue remains open. The current scan still observes credential-handling "
        "patterns that match the existing report.\n\n"
        f"- Composite score: **{report.composite:.3f}**\n"
        f"- Findings: {report.finding_count}\n"
        f"- Issue-worthy findings: {report.issue_worthy_count}\n\n"
        f"Finding types: `{finding_types}`\n\n"
        + "\n".join(f"- {finding.title}" for finding in findings)
    )


def notify_all(client: IssueClient, reports: list[RepoReport], findings: list[RepoFinding]) -> None:
    """Create or update one issue per qualifying repo."""
    eligible = [report for report in reports if report.action == "file_issue" and report.issue_worthy_count]
    if len(eligible) > MAX_ISSUES_PER_SCAN:
        _log.warning("Capping issue notifications from %d to %d", len(eligible), MAX_ISSUES_PER_SCAN)
        eligible = eligible[:MAX_ISSUES_PER_SCAN]

    for report in eligible:
        repo_findings = [
            finding
            for finding in findings
            if finding.repo_full_name == report.full_name and finding.issue_worthy
        ]
        if not repo_findings:
            continue
        try:
            existing = client.find_open_issue(report.full_name, _ISSUE_TITLE)
            if existing is None:
                number = client.create_issue(report.full_name, _ISSUE_TITLE, _issue_body(report, repo_findings), [])
                _log.info("Created issue #%d on %s", number, report.full_name)
            else:
                comments = client.list_issue_comments(report.full_name, existing)
                marker = _scan_marker(report.scan_date)
                if any(marker in comment for comment in comments):
                    _log.info(
                        "Skipping duplicate scan update for %s#%d on %s",
                        report.full_name,
                        existing,
                        report.scan_date,
                    )
                    continue
                client.add_comment(report.full_name, existing, _comment_body(report, repo_findings))
                _log.info("Commented on %s#%d", report.full_name, existing)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status in (404, 410, 422):
                _log.info("Skipping issue notification for %s (HTTP %d)", report.full_name, status)
                continue
            raise
