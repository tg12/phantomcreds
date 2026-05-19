"""Tests for README dashboard aggregation."""
# pylint: disable=missing-function-docstring

from __future__ import annotations

from phantomcreds.reporter import _build_daily_table, _build_repo_table


def test_daily_table_dedupes_multiple_runs_for_same_repo_on_same_day() -> None:
    records = [
        {
            "full_name": "owner/repo-a",
            "scan_date": "2026-05-18",
            "classification": "high_risk",
            "issue_worthy_count": 1,
            "action": "file_issue",
        },
        {
            "full_name": "owner/repo-a",
            "scan_date": "2026-05-18",
            "classification": "high_risk",
            "issue_worthy_count": 1,
            "action": "file_issue",
        },
        {
            "full_name": "owner/repo-b",
            "scan_date": "2026-05-18",
            "classification": "watchlist",
            "issue_worthy_count": 0,
            "action": "watch",
        },
    ]

    table = _build_daily_table(records)

    assert "| 2026-05-18 | 2 | 2 | 1 | 1 | 0 | 1 |" in table


def test_repo_table_keeps_latest_row_per_repo_for_latest_scan_date() -> None:
    records = [
        {
            "full_name": "owner/repo-a",
            "scan_date": "2026-05-18",
            "classification": "high_risk",
            "composite": 0.9,
            "finding_count": 3,
            "action": "watch",
            "stars": 10,
            "updated_at": "2026-05-18T09:00:00Z",
        },
        {
            "full_name": "owner/repo-a",
            "scan_date": "2026-05-18",
            "classification": "high_risk",
            "composite": 1.0,
            "finding_count": 4,
            "action": "report_only",
            "stars": 11,
            "updated_at": "2026-05-18T10:00:00Z",
        },
        {
            "full_name": "owner/repo-b",
            "scan_date": "2026-05-18",
            "classification": "watchlist",
            "composite": 0.7,
            "finding_count": 2,
            "action": "file_issue",
            "stars": 5,
            "updated_at": "2026-05-18T08:00:00Z",
        },
    ]

    table = _build_repo_table(records)

    assert table.count("owner/repo-a") == 1
    assert "| owner/repo-a | 1.000 | 4 | report_only | 11 | 2026-05-18 |" in table
