"""Repo-level credential-risk detection and scoring."""

from __future__ import annotations

import re
from collections.abc import Iterable

from phantomcreds.config import (
    CALLBACK_PATHS,
    LOGGER_PATHS,
    MANAGEMENT_ROUTE_PATHS,
    SCORE_HIGH_RISK,
    SCORE_WATCHLIST,
    SERVER_PATHS,
    STORE_PATHS,
)
from phantomcreds.models import Classification, IssueAction, RepoFinding, RepoMetadata, RepoReport

_POSTURE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("no_api_key_needed", re.compile(r"no api key needed", re.IGNORECASE)),
    ("multi_account", re.compile(r"multi-account|account pool", re.IGNORECASE)),
    ("shared_subscription", re.compile(r"shared subscription|top-up|relay", re.IGNORECASE)),
    ("auth_file", re.compile(r"auth file|session export|cookie login|token store", re.IGNORECASE)),
)

_TOKEN_SERIALIZATION_RE = re.compile(
    r"SaveTokenToFile|access_token|refresh_token|id_token|cookie|session", re.IGNORECASE
)
_LOCAL_MIRROR_RE = re.compile(
    r"mirror(?:ed)? to a local workspace|spool|auths|pgstore|objectstore", re.IGNORECASE
)
_RAW_AUTH_FORWARD_RE = re.compile(
    r"cloneHeaders\(headers\)|cloneHeaders\(w\.requestHeaders\)|Authorization", re.IGNORECASE
)
_CALLBACK_RE = re.compile(r"0\.0\.0\.0|Addr:\s*fmt\.Sprintf\(\"", re.IGNORECASE)
_AUTH_BYPASS_RE = re.compile(r"wrapManagementAuth|/threads|/auth|/settings|/docs")
_WILDCARD_CORS_RE = re.compile(
    r"Access-Control-Allow-Origin\",\s*\"\*\"|Access-Control-Allow-Origin',\s*'\*'"
)
_CORS_CONTEXT_RE = re.compile(
    r"engine\.Use\(corsMiddleware\(\)\)|/v0/management"
    r"|Access-Control-Allow-Origin\",\s*\"\*\"|Access-Control-Allow-Origin',\s*'\*'"
)

_TYPE_WEIGHTS: dict[str, float] = {
    "harvest_posture": 0.18,
    "credential_persistence": 0.18,
    "local_secret_mirror": 0.24,
    "raw_auth_forwarding": 0.32,
    "callback_exposure": 0.20,
    "management_auth_bypass": 0.24,
    "wildcard_management_cors": 0.20,
}


def _collect_refs(path: str, content: str, pattern: re.Pattern[str], limit: int = 3) -> list[str]:
    refs: list[str] = []
    for lineno, line in enumerate(content.splitlines(), 1):
        if pattern.search(line):
            snippet = line.strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            refs.append(f"{path}:{lineno} - {snippet}")
            if len(refs) >= limit:
                break
    return refs


def _find_matching_files(
    files: dict[str, str], pattern: re.Pattern[str], paths: Iterable[str] | None = None
) -> list[str]:
    refs: list[str] = []
    path_filter = set(paths) if paths is not None else None
    for path, content in files.items():
        if path_filter is not None and path not in path_filter:
            continue
        refs.extend(_collect_refs(path, content, pattern))
    return refs


def _detect_harvest_posture(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> tuple[list[RepoFinding], bool]:
    readme_text = "\n".join(
        text for path, text in files.items() if path.lower().startswith("readme")
    )
    combined = "\n".join(filter(None, [metadata.description or "", readme_text]))
    evidence: list[str] = []
    matched_labels: list[str] = []
    for label, pattern in _POSTURE_PATTERNS:
        match = pattern.search(combined)
        if match:
            matched_labels.append(label)
            snippet = match.group(0)
            evidence.append(f"README/description - {snippet}")

    if not matched_labels:
        return [], False

    return (
        [
            RepoFinding(
                repo_full_name=metadata.full_name,
                finding_type="harvest_posture",
                title="README advertises shared-subscription or credential relay usage",
                severity="medium",
                confidence="confirmed",
                summary=(
                    "Repository docs advertise account pooling, auth-file import, "
                    "relay usage, or 'no API key needed' posture."
                ),
                issue_worthy=False,
                scan_date=scan_date,
                evidence=tuple(evidence[:4]),
            )
        ],
        len(matched_labels) >= 2,
    )


def _detect_credential_persistence(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> list[RepoFinding]:
    evidence = _find_matching_files(files, _TOKEN_SERIALIZATION_RE)
    if len(evidence) < 2:
        return []
    return [
        RepoFinding(
            repo_full_name=metadata.full_name,
            finding_type="credential_persistence",
            title="Credential material appears to be serialized into auth files",
            severity="medium",
            confidence="confirmed",
            summary=(
                "The repo contains code paths that write token-like material to disk, "
                "including refresh-token, session, or cookie storage."
            ),
            issue_worthy=False,
            scan_date=scan_date,
            evidence=tuple(evidence[:4]),
        )
    ]


def _detect_local_secret_mirror(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> list[RepoFinding]:
    evidence = _find_matching_files(files, _LOCAL_MIRROR_RE, STORE_PATHS)
    if len(evidence) < 2:
        return []
    return [
        RepoFinding(
            repo_full_name=metadata.full_name,
            finding_type="local_secret_mirror",
            title="Remote token backends still mirror auth material to local spool directories",
            severity="high",
            confidence="confirmed",
            summary=(
                "Remote-backed auth storage still creates local auth/config directories, "
                "so operator expectations about central-only secret storage are violated."
            ),
            issue_worthy=True,
            scan_date=scan_date,
            evidence=tuple(evidence[:4]),
        )
    ]


def _detect_raw_auth_forwarding(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> list[RepoFinding]:
    logger_refs = _find_matching_files(files, _RAW_AUTH_FORWARD_RE, LOGGER_PATHS)
    if len(logger_refs) < 3:
        return []
    return [
        RepoFinding(
            repo_full_name=metadata.full_name,
            finding_type="raw_auth_forwarding",
            title="Home request logging forwards raw Authorization headers",
            severity="high",
            confidence="confirmed",
            summary=(
                "Downstream request headers appear to be cloned into centralized request-log "
                "transport without secret redaction."
            ),
            issue_worthy=True,
            scan_date=scan_date,
            evidence=tuple(logger_refs[:4]),
        )
    ]


def _detect_callback_exposure(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> list[RepoFinding]:
    evidence = _find_matching_files(files, _CALLBACK_RE, CALLBACK_PATHS)
    if len(evidence) < 2:
        return []
    return [
        RepoFinding(
            repo_full_name=metadata.full_name,
            finding_type="callback_exposure",
            title="OAuth callback listeners bind broadly and are published in default deployment files",
            severity="medium",
            confidence="confirmed",
            summary=(
                "Callback helpers intended for local browser round-trips are reachable beyond "
                "loopback by default."
            ),
            issue_worthy=True,
            scan_date=scan_date,
            evidence=tuple(evidence[:4]),
        )
    ]


def _detect_management_auth_bypass(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> list[RepoFinding]:
    evidence = _find_matching_files(files, _AUTH_BYPASS_RE, MANAGEMENT_ROUTE_PATHS)
    if len(evidence) < 3:
        return []
    return [
        RepoFinding(
            repo_full_name=metadata.full_name,
            finding_type="management_auth_bypass",
            title="Management proxy routes bypass API-key authentication",
            severity="high",
            confidence="confirmed",
            summary=(
                "The route wrapper skips auth for several management-related prefixes, "
                "expanding access to proxy/login functionality."
            ),
            issue_worthy=True,
            scan_date=scan_date,
            evidence=tuple(evidence[:4]),
        )
    ]


def _detect_wildcard_management_cors(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> list[RepoFinding]:
    server_path = next(iter(SERVER_PATHS))
    server_go = files.get(server_path)
    if not server_go or "/v0/management" not in server_go or not _WILDCARD_CORS_RE.search(server_go):
        return []
    evidence = _collect_refs(server_path, server_go, _CORS_CONTEXT_RE, limit=4)
    return [
        RepoFinding(
            repo_full_name=metadata.full_name,
            finding_type="wildcard_management_cors",
            title="Wildcard CORS is applied to management endpoints",
            severity="high",
            confidence="confirmed",
            summary=(
                "Management routes inherit Access-Control-Allow-Origin: * with broad methods "
                "and headers, widening the browser attack surface."
            ),
            issue_worthy=True,
            scan_date=scan_date,
            evidence=tuple(evidence),
        )
    ]


def _classify(score: float) -> Classification:
    if score >= SCORE_HIGH_RISK:
        return "high_risk"
    if score >= SCORE_WATCHLIST:
        return "watchlist"
    return "clean"


def analyze_repository(
    metadata: RepoMetadata,
    files: dict[str, str],
    discovery_sources: set[str],
    scan_date: str,
) -> tuple[RepoReport, list[RepoFinding]]:
    """Analyze one repository and return a report plus concrete findings."""

    findings: list[RepoFinding] = []

    posture_findings, overt_harvest_posture = _detect_harvest_posture(metadata, files, scan_date)
    findings.extend(posture_findings)
    findings.extend(_detect_credential_persistence(metadata, files, scan_date))
    findings.extend(_detect_local_secret_mirror(metadata, files, scan_date))
    findings.extend(_detect_raw_auth_forwarding(metadata, files, scan_date))
    findings.extend(_detect_callback_exposure(metadata, files, scan_date))
    findings.extend(_detect_management_auth_bypass(metadata, files, scan_date))
    findings.extend(_detect_wildcard_management_cors(metadata, files, scan_date))

    score = 0.0
    for finding in findings:
        score += _TYPE_WEIGHTS.get(finding.finding_type, 0.0)
    if findings:
        score += min(0.15, 0.03 * max(0, len(findings) - 1))
    score = round(min(score, 1.0), 3)

    classification = _classify(score)
    issue_worthy_count = sum(1 for finding in findings if finding.issue_worthy)
    has_persistence = any(f.finding_type == "credential_persistence" for f in findings)

    if issue_worthy_count > 0 and not overt_harvest_posture:
        action: IssueAction = "file_issue"
    elif overt_harvest_posture and (issue_worthy_count > 0 or has_persistence):
        action = "report_only"
    else:
        action = "watch"

    report = RepoReport(
        full_name=metadata.full_name,
        composite=score,
        classification=classification,
        action=action,
        finding_count=len(findings),
        issue_worthy_count=issue_worthy_count,
        stars=metadata.stargazers_count,
        scan_date=scan_date,
        created_at=metadata.created_at,
        updated_at=metadata.updated_at,
        discovery_sources=tuple(sorted(discovery_sources)),
        finding_types=tuple(sorted(f.finding_type for f in findings)),
    )
    return report, findings
