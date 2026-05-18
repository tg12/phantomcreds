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

_SECRET_FILE_SUFFIXES: tuple[str, ...] = (
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".pem",
    ".key",
    ".p8",
    ".p12",
    ".pfx",
    ".ini",
    ".tfvars",
    ".tfvars.json",
)
_SECRET_FILE_NAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.example",
        ".env.sample",
        ".npmrc",
        ".pypirc",
        ".terraformrc",
        "terraform.tfvars",
        "terraform.tfvars.json",
        "credentials",
        "auth.json",
        "cookies.json",
        "service-account.json",
        "gcp-service-account.json",
        "azure.json",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)

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
_SECRET_ASSIGNMENT_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "openai_api_key",
        re.compile(
            r"(OPENAI_API_KEY|openai[_-]?api[_-]?key)\s*[:=]\s*[\"']?(sk-(?:proj-)?[A-Za-z0-9_-]{12,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "anthropic_api_key",
        re.compile(
            r"(ANTHROPIC_API_KEY|anthropic[_-]?api[_-]?key)\s*[:=]\s*[\"']?(sk-ant-[A-Za-z0-9_-]{12,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "github_token",
        re.compile(
            r"(GH_TOKEN|GITHUB_TOKEN|github[_-]?token)\s*[:=]\s*[\"']?((?:github_pat|gh[pousr])_[A-Za-z0-9_]{20,255})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "google_api_key",
        re.compile(
            r"(GOOGLE_API_KEY|GEMINI_API_KEY|google[_-]?api[_-]?key|gemini[_-]?api[_-]?key)\s*[:=]\s*[\"']?(AIza[0-9A-Za-z\-_]{35})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "openrouter_api_key",
        re.compile(
            r"(OPENROUTER_API_KEY|openrouter[_-]?api[_-]?key)\s*[:=]\s*[\"']?(sk-or-v1-[A-Za-z0-9_-]{16,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "groq_api_key",
        re.compile(
            r"(GROQ_API_KEY|groq[_-]?api[_-]?key)\s*[:=]\s*[\"']?(gsk_[A-Za-z0-9]{20,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "replicate_api_token",
        re.compile(
            r"(REPLICATE_API_TOKEN|REPLICATE_TOKEN|replicate[_-]?(?:api[_-]?)?token)\s*[:=]\s*[\"']?(r8_[A-Za-z0-9]{20,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "deepseek_api_key",
        re.compile(
            r"(DEEPSEEK_API_KEY|deepseek[_-]?api[_-]?key)\s*[:=]\s*[\"']?(sk-[A-Za-z0-9_-]{20,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "perplexity_api_key",
        re.compile(
            r"(PERPLEXITY_API_KEY|PPLX_API_KEY|perplexity[_-]?api[_-]?key|pplx[_-]?api[_-]?key)\s*[:=]\s*[\"']?(pplx-[A-Za-z0-9_-]{20,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "aws_access_key_id",
        re.compile(
            r"(AWS_ACCESS_KEY_ID|aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*[\"']?((?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "aws_secret_access_key",
        re.compile(
            r"(AWS_SECRET_ACCESS_KEY|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "aws_session_token",
        re.compile(
            r"(AWS_SESSION_TOKEN|aws[_-]?session[_-]?token)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{32,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "azure_storage_connection_string",
        re.compile(
            r"(AZURE_STORAGE_CONNECTION_STRING|azure[_-]?storage[_-]?connection[_-]?string)\s*[:=]\s*[\"']?(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,};EndpointSuffix=[^\"';\s]+)[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "cloudflare_api_token",
        re.compile(
            r"(CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cloudflare[_-]?api[_-]?token)\s*[:=]\s*[\"']?([A-Za-z0-9_-]{30,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "sendgrid_api_key",
        re.compile(
            r"(SENDGRID_API_KEY|sendgrid[_-]?api[_-]?key)\s*[:=]\s*[\"']?(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "stripe_secret_key",
        re.compile(
            r"(STRIPE_SECRET_KEY|stripe[_-]?secret[_-]?key)\s*[:=]\s*[\"']?((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "huggingface_token",
        re.compile(
            r"(HUGGINGFACE(?:HUB)?_API_TOKEN|HF_TOKEN|huggingface[_-]?(?:hub[_-]?)?api[_-]?token|hf[_-]?token)\s*[:=]\s*[\"']?(hf_[A-Za-z0-9]{24,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "npm_token",
        re.compile(
            r"(NPM_TOKEN|npm[_-]?token|_authToken)\s*[:=]\s*[\"']?(npm_[A-Za-z0-9]{24,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "pypi_token",
        re.compile(
            r"(PYPI_TOKEN|pypi[_-]?token|password)\s*[:=]\s*[\"']?(pypi-[A-Za-z0-9_-]{24,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "vercel_token",
        re.compile(
            r"(VERCEL_TOKEN|vercel[_-]?token)\s*[:=]\s*[\"']?([A-Za-z0-9]{24,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "digitalocean_token",
        re.compile(
            r"(DIGITALOCEAN_TOKEN|DO_TOKEN|digitalocean[_-]?token|do[_-]?token)\s*[:=]\s*[\"']?(dop_v1_[A-Za-z0-9_-]{24,})[\"']?",
            re.IGNORECASE,
        ),
    ),
    (
        "slack_webhook",
        re.compile(
            r"(SLACK_WEBHOOK_URL|slack[_-]?webhook)\s*[:=]\s*[\"']?(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,})[\"']?",
            re.IGNORECASE,
        ),
    ),
)
_SSH_PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP|PRIVATE) PRIVATE KEY-----"
)
_GCP_SERVICE_ACCOUNT_RE = re.compile(
    r'"type"\s*:\s*"service_account".*"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----',
    re.IGNORECASE | re.DOTALL,
)
_PLACEHOLDER_SECRET_RE = re.compile(
    r"(example|changeme|your[_-]?key|placeholder|dummy|test[-_]?key|xxxxx+|<[^>]+>)",
    re.IGNORECASE,
)
_MAX_EXPOSED_SECRET_EVIDENCE = 12

_TYPE_WEIGHTS: dict[str, float] = {
    "harvest_posture": 0.18,
    "credential_persistence": 0.18,
    "local_secret_mirror": 0.24,
    "raw_auth_forwarding": 0.32,
    "callback_exposure": 0.20,
    "management_auth_bypass": 0.24,
    "wildcard_management_cors": 0.20,
    "exposed_secret": 0.35,
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


def _redact_secret(secret: str) -> str:
    if secret.startswith("https://hooks.slack.com/services/"):
        return "https://hooks.slack.com/services/REDACTED"
    if len(secret) <= 10:
        return "[REDACTED]"
    return f"{secret[:6]}...{secret[-4:]}"


def _is_redacted_example_line(line: str) -> bool:
    return "[REDACTED:" in line


def _collect_private_key_evidence(path: str, content: str) -> list[str]:
    evidence: list[str] = []
    for lineno, line in enumerate(content.splitlines(), 1):
        if _is_redacted_example_line(line):
            continue
        if _SSH_PRIVATE_KEY_HEADER_RE.search(line):
            header_match = _SSH_PRIVATE_KEY_HEADER_RE.search(line)
            if header_match is not None:
                evidence.append(f"{path}:{lineno} - [REDACTED:{header_match.group(0)}]")

    if "[REDACTED:" not in content and _GCP_SERVICE_ACCOUNT_RE.search(content):
        evidence.append(f"{path}:1 - [REDACTED:GCP service account private key block]")

    return evidence


def _collect_inline_secret_evidence(path: str, content: str, limit: int) -> list[str]:
    evidence: list[str] = []
    if limit <= 0:
        return evidence

    for lineno, line in enumerate(content.splitlines(), 1):
        if len(evidence) >= limit:
            return evidence
        if _is_redacted_example_line(line):
            continue
        for _secret_kind, pattern in _SECRET_ASSIGNMENT_RES:
            match = pattern.search(line)
            if not match:
                continue
            secret_value = match.group(2).strip()
            if _PLACEHOLDER_SECRET_RE.search(secret_value):
                continue
            redacted = _redact_secret(secret_value)
            evidence.append(f"{path}:{lineno} - {match.group(1)}=[REDACTED:{redacted}]")
            break

    return evidence


def _collect_exposed_secret_evidence(path: str, content: str, limit: int) -> list[str]:
    evidence = _collect_private_key_evidence(path, content)
    if len(evidence) >= limit:
        return evidence[:limit]
    evidence.extend(_collect_inline_secret_evidence(path, content, limit - len(evidence)))
    return evidence


def _detect_exposed_secrets(
    metadata: RepoMetadata, files: dict[str, str], scan_date: str
) -> list[RepoFinding]:
    evidence: list[str] = []
    total_secret_hits = 0

    for path, content in files.items():
        file_evidence = _collect_exposed_secret_evidence(
            path,
            content,
            _MAX_EXPOSED_SECRET_EVIDENCE,
        )
        if not file_evidence:
            continue
        total_secret_hits += len(file_evidence)
        remaining = _MAX_EXPOSED_SECRET_EVIDENCE - len(evidence)
        if remaining > 0:
            evidence.extend(file_evidence[:remaining])

    if not evidence:
        return []

    secret_label = "indicator" if total_secret_hits == 1 else "indicators"
    return [
        RepoFinding(
            repo_full_name=metadata.full_name,
            finding_type="exposed_secret",
            title="Secret-bearing credential material appears committed in current repository files",
            severity="high",
            confidence="confirmed",
            summary=(
                "Current repository files appear to contain committed API keys or webhook-style "
                f"credential material. {total_secret_hits} redacted secret {secret_label} "
                "were found in fetched repository files. Evidence is redacted in the report output."
            ),
            issue_worthy=True,
            scan_date=scan_date,
            evidence=tuple(evidence[:_MAX_EXPOSED_SECRET_EVIDENCE]),
        )
    ]


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
    if (
        not server_go
        or "/v0/management" not in server_go
        or not _WILDCARD_CORS_RE.search(server_go)
    ):
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
    findings.extend(_detect_exposed_secrets(metadata, files, scan_date))
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
    has_exposed_secret = any(f.finding_type == "exposed_secret" for f in findings)

    if has_exposed_secret or (issue_worthy_count > 0 and not overt_harvest_posture):
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
