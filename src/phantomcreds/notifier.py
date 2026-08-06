"""GitHub issue notifier for fixable credential-handling findings."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Protocol

import requests

from phantomcreds.config import (
    MAX_ISSUES_PER_ROLLING_WINDOW,
    MAX_ISSUES_PER_SCAN,
    OPT_OUT_MARKER_PATHS,
    OPT_OUT_TOPICS,
    ROLLING_ISSUE_WINDOW_HOURS,
)
from phantomcreds.models import NotificationRecord, RepoFinding, RepoReport

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
_CREATED_EVENTS: frozenset[str] = frozenset({"created"})


def _scan_marker(scan_date: str) -> str:
    return f"<!-- phantomcreds:scan:{scan_date} -->"


class IssueClient(Protocol):
    """Minimal issue client protocol for create/update operations."""

    def find_issue(
        self,
        owner_repo: str,
        title_fragment: str,
        body_markers: tuple[str, ...] | None = None,
    ) -> tuple[int, str] | None:
        """Return the newest matching phantomcreds issue as (number, state)."""

    def create_issue(self, owner_repo: str, title: str, body: str, labels: list[str]) -> int:
        """Create a new issue and return its number."""

    def list_issue_comments(self, owner_repo: str, issue_number: int) -> list[str]:
        """Return all visible issue comments for duplicate-update checks."""

    def add_comment(self, owner_repo: str, issue_number: int, body: str) -> None:
        """Append a comment to an existing issue."""


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


def _opt_out_section() -> str:
    topics = ", ".join(f"`{topic}`" for topic in sorted(OPT_OUT_TOPICS))
    paths = ", ".join(f"`{path}`" for path in sorted(OPT_OUT_MARKER_PATHS))
    return f"""\
### Stop this bot contacting this repository

Any one of these takes effect before the next scan, and no further issue or comment
will be filed here:

- Add one of these repository topics: {topics}
- Commit an empty marker file at any of: {paths}
- Close this issue. A closed phantomcreds issue is treated as a refusal, and this
  repository will not be contacted again even if the finding persists.
- Open an issue on [the phantomcreds tracker]({_PROJECT_URL}/issues) asking for
  `{{owner}}/{{repo}}` to be added to the permanent exclusion list.
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

This is an automated report from a scanner you did not install. Nothing here is a
judgement about you or your project, and there is no obligation to reply. If this is
unwelcome, the opt-out section at the end stops it permanently.

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

{_opt_out_section()}

---

This scan is evidence-first and probabilistic. It is not an accusation of malicious intent.
If any finding is incorrect or outdated, please reply with corrected context and exact file references.

Automated by [phantomcreds](https://github.com/tg12/phantomcreds).
[Project repo]({_PROJECT_URL}) · Created by [{_CREATOR_NAME}]({_CREATOR_URL})
at [JS Labs]({_CREATOR_LABS_URL}).
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
        "patterns that match the existing report. Closing this issue stops all further "
        "updates from this scanner.\n\n"
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


def _record(
    repo_full_name: str,
    event: str,
    title: str,
    scan_date: str,
    issue_number: int | None = None,
) -> NotificationRecord:
    return NotificationRecord(
        repo_full_name=repo_full_name,
        event=event,  # type: ignore[arg-type]
        issue_number=issue_number,
        title=title,
        scan_date=scan_date,
        recorded_at=datetime.now(UTC).isoformat(),
    )


def _recent_issue_count(prior: list[NotificationRecord], now: datetime) -> int:
    """Count issues created across all repos inside the rolling window."""
    cutoff = now - timedelta(hours=ROLLING_ISSUE_WINDOW_HOURS)
    count = 0
    for record in prior:
        if record.event not in _CREATED_EVENTS:
            continue
        try:
            recorded_at = datetime.fromisoformat(record.recorded_at)
        except ValueError:
            _log.warning("Unparsable notification timestamp: %r", record.recorded_at)
            continue
        if recorded_at.tzinfo is None:
            recorded_at = recorded_at.replace(tzinfo=UTC)
        if recorded_at >= cutoff:
            count += 1
    return count


def _notify_repo(
    client: IssueClient,
    report: RepoReport,
    repo_findings: list[RepoFinding],
    budget_remaining: int,
) -> NotificationRecord:
    """Create or update one repo's issue and return what was decided."""
    issue_title = _issue_title(repo_findings)
    issue_markers = _issue_markers(repo_findings)
    existing = client.find_issue(report.full_name, issue_title, issue_markers)

    if existing is not None:
        number, state = existing
        if state != "open":
            # A maintainer closed a phantomcreds issue. That is a refusal, and refiling
            # over it is the behaviour that gets scanners blocked.
            _log.info("Skipping %s: phantomcreds issue #%d is closed", report.full_name, number)
            return _record(
                report.full_name, "skipped_closed", issue_title, report.scan_date, number
            )

        comments = client.list_issue_comments(report.full_name, number)
        marker = _scan_marker(report.scan_date)
        if any(marker in comment for comment in comments):
            _log.info(
                "Skipping duplicate scan update for %s#%d on %s",
                report.full_name,
                number,
                report.scan_date,
            )
            return _record(
                report.full_name, "skipped_duplicate", issue_title, report.scan_date, number
            )

        client.add_comment(report.full_name, number, _comment_body(report, repo_findings))
        _log.info("Commented on %s#%d", report.full_name, number)
        return _record(report.full_name, "commented", issue_title, report.scan_date, number)

    if budget_remaining <= 0:
        _log.warning(
            "Rolling %dh issue ceiling of %d reached; not filing on %s",
            ROLLING_ISSUE_WINDOW_HOURS,
            MAX_ISSUES_PER_ROLLING_WINDOW,
            report.full_name,
        )
        return _record(report.full_name, "blocked_rate_limit", issue_title, report.scan_date)

    # Re-check immediately before creating. This does not replace a lock, but it closes
    # the window between the first lookup and the write.
    if client.find_issue(report.full_name, issue_title, issue_markers) is not None:
        _log.info("Issue appeared on %s between lookup and create; skipping", report.full_name)
        return _record(report.full_name, "skipped_duplicate", issue_title, report.scan_date)

    number = client.create_issue(
        report.full_name, issue_title, _issue_body(report, repo_findings), []
    )
    _log.info("Created issue #%d on %s", number, report.full_name)
    return _record(report.full_name, "created", issue_title, report.scan_date, number)


def notify_all(
    client: IssueClient,
    reports: list[RepoReport],
    findings: list[RepoFinding],
    *,
    allowlist: set[str],
    prior_notifications: list[NotificationRecord] | None = None,
) -> list[NotificationRecord]:
    """Create or update one issue per qualifying repo and return what was decided."""
    now = datetime.now(UTC)
    prior = prior_notifications or []
    budget = MAX_ISSUES_PER_ROLLING_WINDOW - _recent_issue_count(prior, now)
    records: list[NotificationRecord] = []

    eligible = [
        report for report in reports if report.action == "file_issue" and report.issue_worthy_count
    ]
    if len(eligible) > MAX_ISSUES_PER_SCAN:
        _log.warning(
            "Capping issue notifications from %d to %d", len(eligible), MAX_ISSUES_PER_SCAN
        )
        eligible = eligible[:MAX_ISSUES_PER_SCAN]

    for report in eligible:
        # Re-checked here and not only at scan time: an allowlist entry added after a
        # scan started must still suppress external contact.
        if report.full_name.lower() in allowlist:
            _log.info("Skipping allowlisted repo at notify time: %s", report.full_name)
            records.append(_record(report.full_name, "blocked_allowlist", "", report.scan_date))
            continue

        repo_findings = [
            finding
            for finding in findings
            if finding.repo_full_name == report.full_name and finding.issue_worthy
        ]
        if not repo_findings:
            continue

        try:
            record = _notify_repo(client, report, repo_findings, budget)
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            if status in (403, 404, 410, 422):
                _log.info("Skipping issue notification for %s (HTTP %d)", report.full_name, status)
                continue
            raise

        records.append(record)
        if record.event == "created":
            budget -= 1

    return records
