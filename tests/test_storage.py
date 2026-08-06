"""Tests for the append-only JSONL ledgers."""

# pylint: disable=missing-function-docstring
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

from pathlib import Path

from phantomcreds.models import NotificationRecord
from phantomcreds.storage import append_notifications, load_notifications

SCAN_DATE = "2026-05-18"


def _record(repo: str = "owner/repo", event: str = "created") -> NotificationRecord:
    return NotificationRecord(
        repo_full_name=repo,
        event=event,  # type: ignore[arg-type]
        issue_number=42,
        title="[phantomcreds] Exposed secrets detected in this repository",
        scan_date=SCAN_DATE,
        recorded_at="2026-05-18T07:03:11.482913+00:00",
    )


def test_notifications_round_trip_through_the_ledger(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "notifications.jsonl"
    append_notifications([_record(), _record("owner/other", "skipped_closed")], path)

    loaded = load_notifications(path)

    assert [record.repo_full_name for record in loaded] == ["owner/repo", "owner/other"]
    assert [record.event for record in loaded] == ["created", "skipped_closed"]
    assert loaded[0].issue_number == 42
    assert loaded[0].recorded_at == "2026-05-18T07:03:11.482913+00:00"


def test_append_notifications_is_additive_and_skips_empty_writes(tmp_path: Path) -> None:
    path = tmp_path / "notifications.jsonl"
    append_notifications([], path)
    assert not path.exists()

    append_notifications([_record()], path)
    append_notifications([_record("owner/second")], path)

    assert len(load_notifications(path)) == 2


def test_load_notifications_tolerates_missing_and_malformed_rows(tmp_path: Path) -> None:
    missing = tmp_path / "absent.jsonl"
    assert load_notifications(missing) == []

    path = tmp_path / "notifications.jsonl"
    path.write_text(
        "\n".join(
            [
                "not json at all",
                '{"repo_full_name": "owner/repo"}',
                '{"event": "created"}',
                '{"repo_full_name": "owner/ok", "event": "created", "issue_number": "7"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    loaded = load_notifications(path)

    assert [record.repo_full_name for record in loaded] == ["owner/ok"]
    # A non-integer issue number is dropped rather than coerced.
    assert loaded[0].issue_number is None
    assert loaded[0].recorded_at == ""
