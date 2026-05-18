"""README dashboard updater for phantomcreds."""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from phantomcreds.config import (
    README_END_MARKER,
    README_PATH,
    README_START_MARKER,
    REPO_STATS_END_MARKER,
    REPO_STATS_START_MARKER,
)
from phantomcreds.storage import load_all

_log = logging.getLogger(__name__)

Record = dict[str, object]

_DAILY_TABLE_HEADER = (
    "| Date | Scanned | Flagged | High Risk | Issue-Worthy | Report Only | New High Risk |\n"
    "|------|---------|---------|-----------|--------------|-------------|---------------|"
)

_REPO_TABLE_HEADER = (
    "| Repo | Score | Findings | Action | Stars | Updated |\n"
    "|------|-------|----------|--------|-------|---------|"
)


def _dedupe_records_per_repo_per_day(records: list[Record]) -> list[Record]:
    """Keep the most recent row for each repo on each scan date."""
    deduped: dict[tuple[str, str], Record] = {}
    for record in records:
        scan_date = str(record.get("scan_date", ""))
        repo_full_name = str(record.get("full_name", ""))
        if not scan_date or not repo_full_name:
            continue
        deduped[(scan_date, repo_full_name)] = record
    return list(deduped.values())


def _as_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _as_float(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _inject_block(content: str, start: str, end: str, block: str) -> str:
    if start not in content or end not in content:
        _log.warning("README markers %s / %s not found", start, end)
        return content
    start_index = content.index(start)
    end_index = content.index(end) + len(end)
    return content[:start_index] + f"{start}\n{block}\n{end}" + content[end_index:]


def _build_daily_table(records: list[Record]) -> str:
    records = _dedupe_records_per_repo_per_day(records)
    by_date: dict[str, list[Record]] = defaultdict(list)
    for record in records:
        scan_date = str(record.get("scan_date", "unknown"))
        by_date[scan_date].append(record)

    seen_high_risk: set[str] = set()
    rows: list[str] = []
    for scan_date in sorted(by_date.keys())[-30:]:
        day = by_date[scan_date]
        scanned = len(day)
        flagged = sum(1 for row in day if row.get("classification") != "clean")
        high_risk = {
            str(row.get("full_name")) for row in day if row.get("classification") == "high_risk"
        }
        issue_worthy = sum(1 for row in day if _as_int(row.get("issue_worthy_count", 0)) > 0)
        report_only = sum(1 for row in day if row.get("action") == "report_only")
        new_high_risk = len(high_risk - seen_high_risk)
        seen_high_risk.update(high_risk)
        rows.append(
            f"| {scan_date} | {scanned} | {flagged} | {len(high_risk)} | "
            f"{issue_worthy} | {report_only} | {new_high_risk} |"
        )

    rows.reverse()
    if not rows:
        return f"{_DAILY_TABLE_HEADER}\n| -- | -- | -- | -- | -- | -- | -- |"
    return f"{_DAILY_TABLE_HEADER}\n" + "\n".join(rows)


def _build_repo_table(records: list[Record]) -> str:
    records = _dedupe_records_per_repo_per_day(records)
    if not records:
        return f"{_REPO_TABLE_HEADER}\n| *No scan data yet* | -- | -- | -- | -- | -- |"

    latest_scan = max(str(record.get("scan_date", "")) for record in records)
    today = [
        record
        for record in records
        if record.get("scan_date") == latest_scan and record.get("classification") != "clean"
    ]
    if not today:
        return f"{_REPO_TABLE_HEADER}\n| *No flagged repos for {latest_scan}* | -- | -- | -- | -- | -- |"

    top = sorted(
        today,
        key=lambda row: (
            _as_float(row.get("composite", 0.0)),
            _as_int(row.get("finding_count", 0)),
        ),
        reverse=True,
    )[:25]
    rows = []
    for row in top:
        updated_at = str(row.get("updated_at", ""))[:10]
        rows.append(
            f"| {row.get('full_name')} | {_as_float(row.get('composite', 0.0)):.3f} | "
            f"{_as_int(row.get('finding_count', 0))} | {row.get('action')} | "
            f"{_as_int(row.get('stars', 0))} | {updated_at} |"
        )
    return f"{_REPO_TABLE_HEADER}\n" + "\n".join(rows)


def update_readme(reports_path: Path, readme_path: Path = README_PATH) -> None:
    """Refresh the README stats blocks from the JSONL ledger."""
    if not readme_path.exists():
        _log.warning("README not found at %s", readme_path)
        return

    content = readme_path.read_text(encoding="utf-8")
    report_records = load_all(reports_path)
    content = _inject_block(
        content,
        README_START_MARKER,
        README_END_MARKER,
        _build_daily_table(report_records),
    )
    content = _inject_block(
        content,
        REPO_STATS_START_MARKER,
        REPO_STATS_END_MARKER,
        _build_repo_table(report_records),
    )
    readme_path.write_text(content, encoding="utf-8")
    _log.info("README dashboard updated")
