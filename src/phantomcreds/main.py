"""Entry point for the daily credential-risk scan."""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from phantomcreds.config import (
    ALLOWLIST_FILE,
    CODE_SEARCH_QUERIES,
    FILE_FETCH_WORKERS,
    FINDINGS_FILE,
    MAX_CANDIDATES_PER_SCAN,
    MAX_CODE_RESULTS_PER_QUERY,
    MAX_DISCOVERY_CANDIDATES,
    MAX_FILES_PER_REPO,
    MAX_REPO_RESULTS_PER_QUERY,
    MAX_SECRET_SWEEP_FILES_PER_REPO,
    PRIORITY_PATH_SUFFIXES,
    README_CANDIDATE_PATHS,
    README_PATH,
    RECENT_PUSH_WINDOW_HOURS,
    REPO_SEARCH_QUERIES,
    REPORTS_FILE,
    SECRET_CANDIDATE_PATHS,
    SECRET_CANDIDATE_SUFFIXES,
)
from phantomcreds.github_client import GitHubClient
from phantomcreds.heuristics import analyze_repository
from phantomcreds.logging_config import setup_logging
from phantomcreds.models import RepoFinding, RepoMetadata, RepoReport
from phantomcreds.notifier import notify_all
from phantomcreds.reporter import update_readme
from phantomcreds.storage import append_findings, append_reports, load_allowlist

_log = logging.getLogger(__name__)

_TEXT_FILE_SUFFIXES: tuple[str, ...] = (
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".csv",
    ".env",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".md",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".svg",
    ".tf",
    ".tfvars",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
)
_LIKELY_BINARY_SUFFIXES: tuple[str, ...] = (
    ".7z",
    ".a",
    ".bin",
    ".class",
    ".dll",
    ".dmg",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".lockb",
    ".mp3",
    ".mp4",
    ".o",
    ".otf",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".tar",
    ".ttf",
    ".wav",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
)
_SKIP_TEXT_SWEEP_SEGMENTS: frozenset[str] = frozenset({
    ".git",
    ".next",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
    "target",
    "vendor",
})
_LANGUAGE_SUFFIXES: frozenset[str] = frozenset({
    "generic",
    "go",
    "javascript",
    "python",
    "rust",
    "typescript",
})


@dataclass(frozen=True, slots=True)
class RuntimeOptions:
    reports_path: Path
    findings_path: Path
    allowlist_path: Path
    readme_path: Path | None
    notify_external: bool


def _parse_github_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        _log.warning("Unable to parse GitHub timestamp: %s", value)
        return None


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    _log.warning("Invalid boolean value for %s=%r; using default=%s", name, raw, default)
    return default


def _resolve_runtime_options() -> RuntimeOptions:
    local_mode = _parse_bool_env("PHANTOMCREDS_LOCAL_MODE", False)
    if local_mode:
        output_root = Path(os.environ.get("PHANTOMCREDS_OUTPUT_DIR", ".local/phantomcreds"))
        return RuntimeOptions(
            reports_path=output_root / "repos.jsonl",
            findings_path=output_root / "findings.jsonl",
            allowlist_path=ALLOWLIST_FILE,
            readme_path=None,
            notify_external=_parse_bool_env("PHANTOMCREDS_NOTIFY_EXTERNAL", False),
        )

    return RuntimeOptions(
        reports_path=Path(os.environ.get("PHANTOMCREDS_REPORTS_FILE", str(REPORTS_FILE))),
        findings_path=Path(os.environ.get("PHANTOMCREDS_FINDINGS_FILE", str(FINDINGS_FILE))),
        allowlist_path=Path(os.environ.get("PHANTOMCREDS_ALLOWLIST_FILE", str(ALLOWLIST_FILE))),
        readme_path=(
            Path(os.environ.get("PHANTOMCREDS_README_PATH", str(README_PATH)))
            if _parse_bool_env("PHANTOMCREDS_UPDATE_README", True)
            else None
        ),
        notify_external=_parse_bool_env("PHANTOMCREDS_NOTIFY_EXTERNAL", True),
    )


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
        key=lambda repo: (
            len({_source_family(label) for label in candidate_sources[repo]}),
            len(candidate_sources[repo]),
            repo.lower(),
        ),
        reverse=True,
    )
    return ranked[:MAX_DISCOVERY_CANDIDATES]


def _source_family(label: str) -> str:
    family, separator, suffix = label.rpartition("-")
    if separator and suffix in _LANGUAGE_SUFFIXES:
        return family
    return label


def _candidate_score(repo_full_name: str, sources: set[str], metadata: RepoMetadata) -> tuple[float, datetime, str]:
    family_count = len({_source_family(label) for label in sources})
    source_count = len(sources)
    has_posture_signal = any(label.endswith("posture") for label in sources)
    has_code_signal = any(not label.endswith("posture") for label in sources)

    score = float(family_count * 4 + source_count)
    if has_posture_signal and has_code_signal:
        score += 3.0
    if metadata.fork:
        score -= 2.0
    if metadata.archived:
        score -= 6.0
    if metadata.stargazers_count == 0:
        score += 0.5
    elif metadata.stargazers_count < 25:
        score += 1.0

    pushed_at = _parse_github_timestamp(metadata.pushed_at) or datetime.min.replace(tzinfo=UTC)
    return score, pushed_at, repo_full_name.lower()


def _filter_recent_candidates(
    client: GitHubClient,
    candidate_sources: dict[str, set[str]],
    now: datetime,
) -> tuple[list[str], dict[str, RepoMetadata]]:
    cutoff = now - timedelta(hours=RECENT_PUSH_WINDOW_HOURS)
    metadata_by_repo: dict[str, RepoMetadata] = {}
    recent_candidates: list[str] = []

    for repo_full_name in candidate_sources:
        metadata = client.get_repo_metadata(repo_full_name)
        metadata_by_repo[repo_full_name] = metadata
        pushed_at = _parse_github_timestamp(metadata.pushed_at)
        if pushed_at is None or pushed_at < cutoff:
            continue
        recent_candidates.append(repo_full_name)

    ranked = sorted(
        recent_candidates,
        key=lambda repo: _candidate_score(repo, candidate_sources[repo], metadata_by_repo[repo]),
        reverse=True,
    )
    return ranked[:MAX_CANDIDATES_PER_SCAN], metadata_by_repo


def _select_paths(tree_paths: list[str], code_hits: set[str]) -> list[str]:
    tree_set = set(tree_paths)
    ordered: list[str] = []
    seen: set[str] = set()
    secret_candidate_names = {candidate.lower() for candidate in SECRET_CANDIDATE_PATHS}
    secret_candidate_suffixes = tuple(suffix.lower() for suffix in SECRET_CANDIDATE_SUFFIXES)

    for candidate in README_CANDIDATE_PATHS:
        if candidate in tree_set and candidate not in seen:
            ordered.append(candidate)
            seen.add(candidate)

    for path in sorted(tree_paths):
        if path in seen:
            continue
        lower_path = path.lower()
        basename = lower_path.rsplit("/", 1)[-1]
        if lower_path in secret_candidate_names or basename in secret_candidate_names:
            ordered.append(path)
            seen.add(path)
            continue
        if any(lower_path.endswith(suffix) or basename.endswith(suffix) for suffix in secret_candidate_suffixes):
            ordered.append(path)
            seen.add(path)

    for candidate in (*PRIORITY_PATH_SUFFIXES, *sorted(code_hits)):
        if candidate in tree_set and candidate not in seen:
            ordered.append(candidate)
            seen.add(candidate)

    return ordered[:MAX_FILES_PER_REPO]


def _is_text_like_path(path: str) -> bool:
    lower_path = path.lower()
    basename = lower_path.rsplit("/", 1)[-1]
    segments = set(lower_path.split("/"))
    if segments & _SKIP_TEXT_SWEEP_SEGMENTS:
        return False
    if any(lower_path.endswith(suffix) or basename.endswith(suffix) for suffix in _LIKELY_BINARY_SUFFIXES):
        return False
    if any(lower_path.endswith(suffix) or basename.endswith(suffix) for suffix in _TEXT_FILE_SUFFIXES):
        return True
    return "." not in basename


def _select_secret_sweep_paths(tree_paths: list[str], selected_paths: list[str]) -> list[str]:
    sweep_paths: list[str] = []
    seen = set(selected_paths)
    for path in sorted(tree_paths):
        if path in seen:
            continue
        if not _is_text_like_path(path):
            continue
        sweep_paths.append(path)
        if len(sweep_paths) >= MAX_SECRET_SWEEP_FILES_PER_REPO:
            break
    return sweep_paths


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


def _fetch_repo_files(
    client: GitHubClient,
    repo_full_name: str,
    ref: str,
    selected_paths: list[str],
) -> dict[str, str]:
    files = client.get_multiple_file_contents(
        repo_full_name,
        selected_paths,
        ref,
        max_workers=FILE_FETCH_WORKERS,
    )
    _log.info("Fetched %d/%d candidate files for %s", len(files), len(selected_paths), repo_full_name)
    return files


def main() -> None:
    setup_logging()
    client = GitHubClient(token=os.environ["GH_TOKEN"])
    now = datetime.now(UTC)
    scan_date = now.date().isoformat()
    runtime = _resolve_runtime_options()
    allowlist = load_allowlist(runtime.allowlist_path)

    candidate_sources, code_paths = _build_candidate_pool(client)
    initial_candidates = _prioritize_candidates(candidate_sources)
    _log.info("Initial candidate repos selected: %d", len(initial_candidates))
    recent_sources = {repo: candidate_sources[repo] for repo in initial_candidates}
    candidates, metadata_by_repo = _filter_recent_candidates(client, recent_sources, now)
    _log.info(
        "Recent candidate repos selected: %d within last %d hours",
        len(candidates),
        RECENT_PUSH_WINDOW_HOURS,
    )

    reports: list[RepoReport] = []
    findings: list[RepoFinding] = []

    for repo_full_name in candidates:
        if repo_full_name.lower() in allowlist:
            _log.info("Skipping allowlisted repo: %s", repo_full_name)
            continue

        _log.info("Analyzing %s", repo_full_name)
        metadata = metadata_by_repo[repo_full_name]
        tree_paths = client.get_repo_tree(repo_full_name, metadata.default_branch)
        selected_paths = _select_paths(tree_paths, code_paths.get(repo_full_name, set()))
        secret_sweep_paths = _select_secret_sweep_paths(tree_paths, selected_paths)

        files = _fetch_repo_files(
            client,
            repo_full_name,
            metadata.default_branch,
            [*selected_paths, *secret_sweep_paths],
        )

        report, repo_findings = analyze_repository(
            metadata=metadata,
            files=files,
            discovery_sources=candidate_sources[repo_full_name],
            scan_date=scan_date,
        )
        reports.append(report)
        findings.extend(repo_findings)

    append_reports(reports, runtime.reports_path)
    append_findings(findings, runtime.findings_path)
    if runtime.readme_path is not None:
        update_readme(runtime.reports_path, runtime.readme_path)
    else:
        _log.info("README update disabled for this run")
    if runtime.notify_external:
        notify_all(client, reports, findings)
    else:
        _log.info("External issue notifications disabled for this run")
    _write_step_summary(reports, findings, scan_date)

    _log.info(
        "Scan complete: %d repos, %d high-risk, %d findings",
        len(reports),
        sum(1 for report in reports if report.classification == "high_risk"),
        len(findings),
    )


if __name__ == "__main__":
    main()
