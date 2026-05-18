"""Data models for repo-level credential-risk scans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Classification = Literal["high_risk", "watchlist", "clean"]
IssueAction = Literal["file_issue", "report_only", "watch"]
Severity = Literal["high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class RepoMetadata:
    full_name: str
    description: str | None
    html_url: str
    default_branch: str
    stargazers_count: int
    created_at: str
    updated_at: str
    archived: bool
    fork: bool


@dataclass(frozen=True, slots=True)
class CodeSearchHit:
    repo_full_name: str
    path: str
    source_label: str


@dataclass(frozen=True, slots=True)
class RepoFinding:
    repo_full_name: str
    finding_type: str
    title: str
    severity: Severity
    confidence: str
    summary: str
    issue_worthy: bool
    scan_date: str
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RepoReport:
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
