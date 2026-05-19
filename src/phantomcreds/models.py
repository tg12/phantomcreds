"""Data models for repo-level credential-risk scans."""
# pylint: disable=too-many-instance-attributes

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Classification = Literal["high_risk", "watchlist", "clean"]
IssueAction = Literal["file_issue", "report_only", "watch"]
Severity = Literal["high", "medium", "low"]


def _report_row(report: "RepoReport") -> dict[str, object]:
    """Return a stable JSON-serializable row for repo reports."""
    return {
        "full_name": report.full_name,
        "composite": report.composite,
        "classification": report.classification,
        "action": report.action,
        "finding_count": report.finding_count,
        "issue_worthy_count": report.issue_worthy_count,
        "stars": report.stars,
        "scan_date": report.scan_date,
        "created_at": report.created_at,
        "updated_at": report.updated_at,
        "discovery_sources": list(report.discovery_sources),
        "finding_types": list(report.finding_types),
    }


def _finding_row(finding: "RepoFinding") -> dict[str, object]:
    """Return a stable JSON-serializable row for findings."""
    return {
        "repo_full_name": finding.repo_full_name,
        "finding_type": finding.finding_type,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "summary": finding.summary,
        "issue_worthy": finding.issue_worthy,
        "scan_date": finding.scan_date,
        "evidence": list(finding.evidence),
    }


@dataclass(frozen=True, slots=True)
class RepoMetadata:
    """Repository metadata needed for scan prioritization and analysis."""

    full_name: str
    description: str | None
    default_branch: str
    stargazers_count: int
    created_at: str
    pushed_at: str
    updated_at: str
    archived: bool
    fork: bool


@dataclass(frozen=True, slots=True)
class CodeSearchHit:
    """Single code-search hit used to seed candidate analysis."""

    repo_full_name: str
    path: str
    source_label: str


@dataclass(frozen=True, slots=True)
class RepoFinding:
    """Single finding captured for a repository scan."""

    repo_full_name: str
    finding_type: str
    title: str
    severity: Severity
    confidence: str
    summary: str
    issue_worthy: bool
    scan_date: str
    evidence: tuple[str, ...]

    def to_row(self) -> dict[str, object]:
        """Return a stable JSON-serializable representation."""
        return _finding_row(self)


@dataclass(frozen=True, slots=True)
class RepoReport:
    """Repo-level risk summary written to the append-only ledger."""

    full_name: str
    composite: float
    classification: Classification
    action: IssueAction
    finding_count: int
    issue_worthy_count: int
    stars: int
    scan_date: str
    created_at: str
    updated_at: str
    discovery_sources: tuple[str, ...]
    finding_types: tuple[str, ...]

    def to_row(self) -> dict[str, object]:
        """Return a stable JSON-serializable representation."""
        return _report_row(self)
