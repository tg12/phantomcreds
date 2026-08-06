"""Append-only JSONL storage for reports and findings."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from phantomcreds.config import ALLOWLIST_FILE
from phantomcreds.models import NotificationRecord, RepoFinding, RepoReport

_log = logging.getLogger(__name__)


def load_allowlist(path: Path | None = None) -> set[str]:
    """Load lowercased allowlisted repo names."""
    target = path or ALLOWLIST_FILE
    if not target.exists():
        return set()
    repos: set[str] = set()
    for line in target.read_text(encoding="utf-8").splitlines():
        cleaned = line.strip()
        if cleaned and not cleaned.startswith("#"):
            repos.add(cleaned.lower())
    return repos


def append_reports(reports: list[RepoReport], path: Path) -> None:
    """Append repo reports to the JSONL ledger."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for report in reports:
            handle.write(json.dumps(report.to_row()) + "\n")
    _log.info("Appended %d repo report rows to %s", len(reports), path)


def append_findings(findings: list[RepoFinding], path: Path) -> None:
    """Append finding rows to the JSONL ledger."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding.to_row()) + "\n")
    _log.info("Appended %d finding rows to %s", len(findings), path)


def append_notifications(records: list[NotificationRecord], path: Path) -> None:
    """Append external-contact decisions to the notification ledger."""
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record.to_row()) + "\n")
    _log.info("Appended %d notification rows to %s", len(records), path)


def load_notifications(path: Path) -> list[NotificationRecord]:
    """Load prior notification records, skipping rows that are not well formed."""
    records: list[NotificationRecord] = []
    for row in load_all(path):
        repo_full_name = row.get("repo_full_name")
        event = row.get("event")
        recorded_at = row.get("recorded_at")
        if not isinstance(repo_full_name, str) or not isinstance(event, str):
            _log.warning("Skipping notification row without repo/event in %s", path)
            continue
        issue_number = row.get("issue_number")
        records.append(
            NotificationRecord(
                repo_full_name=repo_full_name,
                event=event,  # type: ignore[arg-type]
                issue_number=issue_number if isinstance(issue_number, int) else None,
                title=str(row.get("title", "")),
                scan_date=str(row.get("scan_date", "")),
                recorded_at=str(recorded_at) if isinstance(recorded_at, str) else "",
            )
        )
    return records


def load_all(path: Path) -> list[dict[str, object]]:
    """Load JSONL rows from path, skipping malformed lines."""
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            cleaned = line.strip()
            if not cleaned:
                continue
            try:
                value = json.loads(cleaned)
            except json.JSONDecodeError as exc:
                _log.warning("Skipping malformed JSONL at %s:%d: %s", path, lineno, exc)
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows
