"""Static configuration for the phantomcreds daily scan."""

from __future__ import annotations

from pathlib import Path
from typing import Final

GITHUB_API_BASE: Final[str] = "https://api.github.com"

REPO_SEARCH_QUERIES: Final[tuple[tuple[str, str], ...]] = (
    (
        "shared-subscription-posture",
        '"multi-account" OR "account pool" OR "shared subscription" OR "no API key needed"',
    ),
    (
        "auth-import-posture",
        '"auth file" OR "session export" OR "cookie login" OR "token store"',
    ),
    (
        "provider-relay-posture",
        '"Claude Code" relay OR "Codex" relay OR "Gemini" relay',
    ),
    (
        "session-reuse-posture",
        '"use your own session" OR "desktop auth" OR "browser cookies" OR "import cookies"',
    ),
    (
        "shared-provider-posture",
        '"shared quota" OR "team account" OR "provider relay" OR "account rotation"',
    ),
    (
        "auth-cache-posture",
        '"session.json" OR "cookies.json" OR "auth.json" OR "credential store"',
    ),
)

CODE_SEARCH_QUERIES: Final[tuple[tuple[str, str], ...]] = (
    ("token-persistence-go", '"refresh_token" "SaveTokenToFile" language:Go'),
    ("token-persistence-python", '"refresh_token" "write_text" language:Python'),
    ("token-persistence-javascript", '"refresh_token" "fs.writeFile" language:JavaScript'),
    ("token-persistence-typescript", '"refresh_token" "writeFile" language:TypeScript'),
    ("session-persistence-python", '"cookies.json" "json.dump" language:Python'),
    ("session-persistence-javascript", '"auth.json" "writeFile" language:JavaScript'),
    ("session-persistence-typescript", '"session.json" "writeFile" language:TypeScript'),
    ("raw-auth-forwarding-go", '"Authorization" "cloneHeaders" language:Go'),
    ("raw-auth-forwarding-python", '"Authorization" "request.headers" language:Python'),
    ("raw-auth-forwarding-javascript", '"Authorization" "req.headers" language:JavaScript'),
    ("callback-exposure-go", '"0.0.0.0" "oauth-callback" language:Go'),
    ("callback-exposure-python", '"0.0.0.0" "oauth" language:Python'),
    ("callback-exposure-typescript", '"0.0.0.0" "callback" language:TypeScript'),
    ("auth-bypass-go", '"wrapManagementAuth" language:Go'),
    (
        "auth-bypass-javascript",
        '"/v0/management" "Access-Control-Allow-Origin" language:JavaScript',
    ),
    ("auth-import-python", '"auth.json" "cookies.json" language:Python'),
    ("auth-import-typescript", '"auth.json" "cookies.json" language:TypeScript'),
    ("secret-path-env", '"OPENAI_API_KEY" filename:.env'),
    ("secret-path-service-account", '"private_key" "client_email" filename:service-account.json'),
    ("secret-path-private-key", '"BEGIN OPENSSH PRIVATE KEY"'),
)

README_CANDIDATE_PATHS: Final[tuple[str, ...]] = (
    "README.md",
    "README.MD",
    "readme.md",
    "README_CN.md",
)

SECRET_CANDIDATE_PATHS: Final[tuple[str, ...]] = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.example",
    ".env.sample",
    "env.example",
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.json",
    "secrets.json",
    "auth.json",
    "cookies.json",
    ".npmrc",
    ".pypirc",
    ".terraformrc",
    "terraform.tfvars",
    "terraform.tfvars.json",
    "credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "service-account.json",
    "gcp-service-account.json",
    "azure.json",
    "aws-credentials",
)

SECRET_CANDIDATE_SUFFIXES: Final[tuple[str, ...]] = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.example",
    ".env.sample",
    ".pem",
    ".key",
    ".p8",
    ".p12",
    ".pfx",
    ".tfvars",
    ".tfvars.json",
    "service-account.json",
    "credentials.json",
)

STORE_PATHS: Final[frozenset[str]] = frozenset(
    {
        "internal/store/objectstore.go",
        "internal/store/postgresstore.go",
    }
)

LOGGER_PATHS: Final[frozenset[str]] = frozenset(
    {
        "internal/logging/request_logger.go",
        "internal/logging/request_logger_home_test.go",
    }
)

CALLBACK_PATHS: Final[frozenset[str]] = frozenset(
    {
        "docker-compose.yml",
        "internal/api/handlers/management/auth_files.go",
        "internal/auth/codex/oauth_server.go",
        "internal/auth/claude/oauth_server.go",
    }
)

MANAGEMENT_ROUTE_PATHS: Final[frozenset[str]] = frozenset(
    {
        "internal/api/modules/amp/routes.go",
    }
)

SERVER_PATHS: Final[frozenset[str]] = frozenset(
    {
        "internal/api/server.go",
    }
)

PRIORITY_PATH_SUFFIXES: Final[tuple[str, ...]] = tuple(
    sorted(STORE_PATHS | LOGGER_PATHS | CALLBACK_PATHS | MANAGEMENT_ROUTE_PATHS | SERVER_PATHS)
)

MAX_REPO_RESULTS_PER_QUERY: Final[int] = 30
MAX_CODE_RESULTS_PER_QUERY: Final[int] = 40
MAX_DISCOVERY_CANDIDATES: Final[int] = 160
MAX_CANDIDATES_PER_SCAN: Final[int] = 100
MAX_FILES_PER_REPO: Final[int] = 18
MAX_SECRET_SWEEP_FILES_PER_REPO: Final[int] = 80
MAX_ISSUES_PER_SCAN: Final[int] = 10
FILE_FETCH_WORKERS: Final[int] = 8
RECENT_PUSH_WINDOW_HOURS: Final[int] = 72

SCORE_HIGH_RISK: Final[float] = 0.65
SCORE_WATCHLIST: Final[float] = 0.20

REPORTS_FILE: Final[Path] = Path("data/repos.jsonl")
FINDINGS_FILE: Final[Path] = Path("data/findings.jsonl")
ALLOWLIST_FILE: Final[Path] = Path("data/allowlist.txt")

README_START_MARKER: Final[str] = "<!-- STATS:START -->"
README_END_MARKER: Final[str] = "<!-- STATS:END -->"
REPO_STATS_START_MARKER: Final[str] = "<!-- REPO_STATS:START -->"
REPO_STATS_END_MARKER: Final[str] = "<!-- REPO_STATS:END -->"
README_PATH: Final[Path] = Path("README.md")
