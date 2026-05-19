"""GitHub issue notifier for fixable credential-handling findings."""

from __future__ import annotations

import logging
from typing import Protocol

import requests

from phantomcreds.config import MAX_ISSUES_PER_SCAN
from phantomcreds.models import RepoFinding, RepoReport

_log = logging.getLogger(__name__)

_SECRETS_ISSUE_TITLE = "[phantomcreds] Exposed secrets detected in this repository"
_RISKS_ISSUE_TITLE = "[phantomcreds] Credential-handling risks detected in this repository"
_ISSUE_MARKER = "<!-- phantomcreds:issue -->"
_SECRETS_ISSUE_MARKER = "<!-- phantomcreds:issue:secrets -->"
_RISKS_ISSUE_MARKER = "<!-- phantomcreds:issue:risks -->"
_PROJECT_URL = "https://github.com/tg12/phantomcreds"
_CREATOR_NAME = "James Sawyer"
_CREATOR_URL = "https://github.com/tg12"
_CREATOR_LABS_URL = "https://labs.jamessawyer.co.uk/"


def _scan_marker(scan_date: str) -> str:
    return f"<!-- phantomcreds:scan:{scan_date} -->"


class IssueClient(Protocol):
    def find_open_issue(
        self,
        owner_repo: str,
        title_fragment: str,
        body_markers: tuple[str, ...] | None = None,
    ) -> int | None: ...

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


def _secret_indicators(findings: list[RepoFinding]) -> list[str]:
    indicators: set[str] = set()
    for finding in findings:
        if finding.finding_type != "exposed_secret":
            continue
        for ref in finding.evidence:
            if "OPENSSH PRIVATE KEY" in ref:
                indicators.add("OPENSSH PRIVATE KEY")
                continue
            if "GCP service account private key block" in ref:
                indicators.add("GCP service account private key block")
                continue
            if " - " not in ref:
                continue
            evidence_text = ref.split(" - ", 1)[1]
            if "=" in evidence_text:
                indicators.add(evidence_text.split("=", 1)[0].strip())
    return sorted(indicators)


def _llm_fix_guide(findings: list[RepoFinding]) -> str:
    indicators = _secret_indicators(findings)
    indicator_text = ", ".join(indicators) if indicators else "credential material"
    if any(finding.finding_type == "exposed_secret" for finding in findings):
        return f"""\
### LLM Fix Guide

Recommended remediation order:
1. Revoke or rotate the exposed credential(s): `{indicator_text}`.
2. Remove the committed secret material from the current default branch and replace it with environment-variable or secret-manager loading.
3. If the secret existed in prior commits, rewrite history or invalidate the old credential so historical clones are harmless.
4. Add secret-bearing files to `.gitignore` and provide a safe template file such as `.env.example` instead of live credentials.

Suggested prompt for an LLM coding assistant:

```text
Remove the exposed credential material from this repository without breaking runtime configuration.
Replace committed secrets with environment-variable loading or secret-manager integration.
Add or update ignore rules so secret-bearing files are not recommitted.
Preserve existing behavior, but migrate any checked-in .env, private-key, or service-account material to safe templates.
Assume the scanner evidence came from current files on the default branch, not from a full git-history scan.
Show the exact files changed and include a short post-fix verification checklist.
```
"""

    return """\
### LLM Fix Guide

Suggested prompt for an LLM coding assistant:

```text
Fix the credential-handling findings in this repository while preserving current behavior.
Remove unsafe header logging, tighten exposed callback or management surfaces, and stop mirroring or persisting sensitive auth material unnecessarily.
Show the exact files changed and include a short verification checklist for the maintainer.
```
"""


def _issue_title(findings: list[RepoFinding]) -> str:
    if any(finding.finding_type == "exposed_secret" for finding in findings):
        return _SECRETS_ISSUE_TITLE
    return _RISKS_ISSUE_TITLE


def _issue_markers(findings: list[RepoFinding]) -> tuple[str, str]:
    if any(finding.finding_type == "exposed_secret" for finding in findings):
        return (_ISSUE_MARKER, _SECRETS_ISSUE_MARKER)
    return (_ISSUE_MARKER, _RISKS_ISSUE_MARKER)


def _issue_body(report: RepoReport, findings: list[RepoFinding]) -> str:
    finding_types = ", ".join(sorted({finding.finding_type for finding in findings}))
    sections = "\n".join(_finding_markdown(finding) for finding in findings)
    secret_indicators = _secret_indicators(findings)
    secret_indicator_line = (
        f"| Exposed secret indicators | {', '.join(secret_indicators)} |\n"
        if secret_indicators
        else ""
    )
    return f"""\
{_ISSUE_MARKER}
{_issue_markers(findings)[1]}
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
{secret_indicator_line}

Detected finding types: `{finding_types}`

{sections}

{_llm_fix_guide(findings)}

This report is based on current files fetched from the repository's default branch at scan time.
It does not by itself prove that older commits are clean or compromised.

---

This scan is evidence-first and probabilistic. It is not an accusation of malicious intent.
If any finding is incorrect or outdated, please reply with corrected context and exact file references.

Automated by [phantomcreds](https://github.com/tg12/phantomcreds).
[Project repo]({_PROJECT_URL}) · Created by [{_CREATOR_NAME}]({_CREATOR_URL}) at [JS Labs]({_CREATOR_LABS_URL}).
"""


def _comment_body(report: RepoReport, findings: list[RepoFinding]) -> str:
    finding_types = ", ".join(sorted({finding.finding_type for finding in findings}))
    secret_indicators = _secret_indicators(findings)
    indicator_line = (
        f"- Exposed secret indicators: {', '.join(secret_indicators)}\n"
        if secret_indicators
        else ""
    )
    return (
        f"{_scan_marker(report.scan_date)}\n"
        f"### Scan update: {report.scan_date}\n\n"
        "This issue remains open. The current scan still observes credential-handling "
        "patterns that match the existing report.\n\n"
        f"- Composite score: **{report.composite:.3f}**\n"
        f"- Findings: {report.finding_count}\n"
        f"- Issue-worthy findings: {report.issue_worthy_count}\n\n"
        f"{indicator_line}"
        f"Finding types: `{finding_types}`\n\n"
        + "\n".join(f"- {finding.title}" for finding in findings)
        + (
            "\n\n"
            f"Source: [phantomcreds]({_PROJECT_URL})"
            f" by [{_CREATOR_NAME}]({_CREATOR_URL})"
            f" at [JS Labs]({_CREATOR_LABS_URL})."
        )
    )


def notify_all(client: IssueClient, reports: list[RepoReport], findings: list[RepoFinding]) -> None:
    """Create or update one issue per qualifying repo."""
    eligible = [
        report for report in reports if report.action == "file_issue" and report.issue_worthy_count
    ]
    if len(eligible) > MAX_ISSUES_PER_SCAN:
        _log.warning(
            "Capping issue notifications from %d to %d", len(eligible), MAX_ISSUES_PER_SCAN
        )
        eligible = eligible[:MAX_ISSUES_PER_SCAN]

    for report in eligible:
        repo_findings = [
            finding
            for finding in findings
            if finding.repo_full_name == report.full_name and finding.issue_worthy
        ]
        if not repo_findings:
            continue
        issue_title = _issue_title(repo_findings)
        issue_markers = _issue_markers(repo_findings)
        try:
            existing = client.find_open_issue(report.full_name, issue_title, issue_markers)
            if existing is None:
                number = client.create_issue(
                    report.full_name, issue_title, _issue_body(report, repo_findings), []
                )
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
