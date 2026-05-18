"""Entry point for the daily credential-risk scan."""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from phantomcreds.config import (
    CODE_SEARCH_QUERIES,
    FINDINGS_FILE,
    MAX_CANDIDATES_PER_SCAN,
    MAX_CODE_RESULTS_PER_QUERY,
    MAX_FILES_PER_REPO,
    MAX_REPO_RESULTS_PER_QUERY,
    PRIORITY_PATH_SUFFIXES,
    README_CANDIDATE_PATHS,
    REPO_SEARCH_QUERIES,
    REPORTS_FILE,
)
from phantomcreds.github_client import GitHubClient
from phantomcreds.heuristics import analyze_repository
from phantomcreds.logging_config import setup_logging
from phantomcreds.models import RepoFinding, RepoReport
from phantomcreds.notifier import notify_all
from phantomcreds.reporter import update_readme
from phantomcreds.storage import append_findings, append_reports, load_allowlist

_log = logging.getLogger(__name__)


def _build_candidate_pool(client: GitHubClient) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    sources: dict[str, set[str]] = defaultdict(set)
    code_paths: dict[str, set[str]] = defaultdict(set)

    for label, query in REPO_SEARCH_QUERIES:
        repos = client.search_repositories(query, limit=MAX_REPO_RESULTS_PER_QUERY)
        _log.info("Repo query %s returned %d repos", label, len(repos))
        for repo in repos:
            sources[repo].add(label)

    for label, query in CODE_SEARCH_QUERIES:
        hits = client.search_code(query, limit=MAX_CODE_RESULTS_PER_QUERY, source_label=label)
        _log.info("Code query %s returned %d hits", label, len(hits))
        for hit in hits:
            sources[hit.repo_full_name].add(label)
            code_paths[hit.repo_full_name].add(hit.path)

    return sources, code_paths


def _prioritize_candidates(candidate_sources: dict[str, set[str]]) -> list[str]:
    ranked = sorted(
        candidate_sources,
        key=lambda repo: (len(candidate_sources[repo]), repo.lower()),
        reverse=True,
    )
    return ranked[:MAX_CANDIDATES_PER_SCAN]


def _select_paths(tree_paths: list[str], code_hits: set[str]) -> list[str]:
    selected = set(code_hits)
    tree_set = set(tree_paths)
    for readme_path in README_CANDIDATE_PATHS:
        if readme_path in tree_set:
            selected.add(readme_path)
    for suffix in PRIORITY_PATH_SUFFIXES:
        if suffix in tree_set:
            selected.add(suffix)
    return sorted(selected)[:MAX_FILES_PER_REPO]


def _write_step_summary(reports: list[RepoReport], findings: list[RepoFinding], scan_date: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    high_risk = [report for report in reports if report.classification == "high_risk"]
    file_issue = [report for report in reports if report.action == "file_issue"]
    report_only = [report for report in reports if report.action == "report_only"]

    lines = [
        f"## Phantomcreds Scan - {scan_date}",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Repos scanned | **{len(reports)}** |",
        f"| High-risk repos | **{len(high_risk)}** |",
        f"| Findings captured | **{len(findings)}** |",
        f"| Repos eligible for issue filing | **{len(file_issue)}** |",
        f"| Repos marked report-only | {len(report_only)} |",
        "",
    ]

    if high_risk:
        lines += [
            "### Highest-risk repos",
            "",
            "| Repo | Score | Findings | Action |",
            "|------|-------|----------|--------|",
        ]
        for report in sorted(high_risk, key=lambda item: item.composite, reverse=True)[:15]:
            lines.append(
                f"| [{report.full_name}](https://github.com/{report.full_name}) | "
                f"{report.composite:.3f} | {report.finding_count} | {report.action} |"
            )
        lines.append("")

    Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    _log.info("GitHub Actions step summary written")


def main() -> None:
    setup_logging()
    client = GitHubClient(token=os.environ["GH_TOKEN"])
    scan_date = datetime.now(UTC).date().isoformat()
    allowlist = load_allowlist()

    candidate_sources, code_paths = _build_candidate_pool(client)
    candidates = _prioritize_candidates(candidate_sources)
    _log.info("Candidate repos selected: %d", len(candidates))

    reports: list[RepoReport] = []
    findings: list[RepoFinding] = []

    for repo_full_name in candidates:
        if repo_full_name.lower() in allowlist:
            _log.info("Skipping allowlisted repo: %s", repo_full_name)
            continue

        _log.info("Analyzing %s", repo_full_name)
        metadata = client.get_repo_metadata(repo_full_name)
        tree_paths = client.get_repo_tree(repo_full_name, metadata.default_branch)
        selected_paths = _select_paths(tree_paths, code_paths.get(repo_full_name, set()))

        files: dict[str, str] = {}
        for path in selected_paths:
            content = client.get_file_content(repo_full_name, path, metadata.default_branch)
            if content is not None:
                files[path] = content

        report, repo_findings = analyze_repository(
            metadata=metadata,
            files=files,
            discovery_sources=candidate_sources[repo_full_name],
            scan_date=scan_date,
        )
        reports.append(report)
        findings.extend(repo_findings)

    append_reports(reports, Path(REPORTS_FILE))
    append_findings(findings, Path(FINDINGS_FILE))
    update_readme(Path(REPORTS_FILE))
    notify_all(client, reports, findings)
    _write_step_summary(reports, findings, scan_date)

    _log.info(
        "Scan complete: %d repos, %d high-risk, %d findings",
        len(reports),
        sum(1 for report in reports if report.classification == "high_risk"),
        len(findings),
    )


if __name__ == "__main__":
    main()
