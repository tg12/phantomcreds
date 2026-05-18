"""Append-only JSONL storage for reports and findings."""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

from phantomcreds.config import ALLOWLIST_FILE
from phantomcreds.models import RepoFinding, RepoReport

_log = logging.getLogger(__name__)


def load_allowlist(path: Path | None = None) -> set[str]:
    """Load lowercased allowlisted repo names."""
    target = path or Path(ALLOWLIST_FILE)
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
            handle.write(json.dumps(dataclasses.asdict(report)) + "\n")
    _log.info("Appended %d repo report rows to %s", len(reports), path)


def append_findings(findings: list[RepoFinding], path: Path) -> None:
    """Append finding rows to the JSONL ledger."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(dataclasses.asdict(finding)) + "\n")
    _log.info("Appended %d finding rows to %s", len(findings), path)


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
