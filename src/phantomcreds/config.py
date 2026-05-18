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
)

CODE_SEARCH_QUERIES: Final[tuple[tuple[str, str], ...]] = (
    ("token-serialization", '"SaveTokenToFile" "refresh_token" language:Go'),
    ("raw-auth-forwarding", '"cloneHeaders" "Authorization" "request log" language:Go'),
    ("callback-exposure", '"0.0.0.0" "oauth-callback" language:Go'),
    ("auth-bypass", '"wrapManagementAuth" language:Go'),
    ("management-cors", '"Access-Control-Allow-Origin" "v0/management" language:Go'),
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
)

STORE_PATHS: Final[frozenset[str]] = frozenset({
    "internal/store/objectstore.go",
    "internal/store/postgresstore.go",
})

LOGGER_PATHS: Final[frozenset[str]] = frozenset({
    "internal/logging/request_logger.go",
    "internal/logging/request_logger_home_test.go",
})

CALLBACK_PATHS: Final[frozenset[str]] = frozenset({
    "docker-compose.yml",
    "internal/api/handlers/management/auth_files.go",
    "internal/auth/codex/oauth_server.go",
    "internal/auth/claude/oauth_server.go",
})

MANAGEMENT_ROUTE_PATHS: Final[frozenset[str]] = frozenset({
    "internal/api/modules/amp/routes.go",
})

SERVER_PATHS: Final[frozenset[str]] = frozenset({
    "internal/api/server.go",
})

PRIORITY_PATH_SUFFIXES: Final[tuple[str, ...]] = tuple(sorted(
    STORE_PATHS | LOGGER_PATHS | CALLBACK_PATHS | MANAGEMENT_ROUTE_PATHS | SERVER_PATHS
))

MAX_REPO_RESULTS_PER_QUERY: Final[int] = 30
MAX_CODE_RESULTS_PER_QUERY: Final[int] = 40
MAX_CANDIDATES_PER_SCAN: Final[int] = 80
MAX_FILES_PER_REPO: Final[int] = 12
MAX_ISSUES_PER_SCAN: Final[int] = 10
RECENT_PUSH_WINDOW_HOURS: Final[int] = 72

SCORE_HIGH_RISK: Final[float] = 0.65
SCORE_WATCHLIST: Final[float] = 0.20

DATA_DIR: Final[Path] = Path("data")
REPORTS_FILE: Final[Path] = Path("data/repos.jsonl")
FINDINGS_FILE: Final[Path] = Path("data/findings.jsonl")
ALLOWLIST_FILE: Final[Path] = Path("data/allowlist.txt")

README_START_MARKER: Final[str] = "<!-- STATS:START -->"
README_END_MARKER: Final[str] = "<!-- STATS:END -->"
REPO_STATS_START_MARKER: Final[str] = "<!-- REPO_STATS:START -->"
REPO_STATS_END_MARKER: Final[str] = "<!-- REPO_STATS:END -->"
README_PATH: Final[Path] = Path("README.md")
