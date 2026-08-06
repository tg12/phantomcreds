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
    ("secret-path-netrc", '"machine " "password " filename:.netrc'),
    (
        "secret-path-aws-credentials",
        '"aws_access_key_id" "aws_secret_access_key" filename:credentials',
    ),
    ("secret-path-npmrc", '"_authToken" filename:.npmrc'),
    ("secret-path-pypirc", '"[pypi]" "password" filename:.pypirc'),
    ("secret-path-docker-config", '"\\"auths\\"" "\\"auth\\"" filename:config.json'),
    (
        "secret-path-terraform-credentials",
        '"app.terraform.io" "token" filename:credentials.tfrc.json',
    ),
    ("secret-path-service-account", '"private_key" "client_email" filename:service-account.json'),
    ("secret-path-private-key", '"BEGIN OPENSSH PRIVATE KEY"'),
    ("secret-path-env-example", '"OPENAI_API_KEY" filename:.env.example'),
    ("secret-path-anthropic-env", '"ANTHROPIC_API_KEY" filename:.env'),
    ("secret-path-openrouter-env", '"OPENROUTER_API_KEY" filename:.env'),
    ("secret-path-groq-env", '"GROQ_API_KEY" filename:.env'),
    ("secret-path-deepseek-env", '"DEEPSEEK_API_KEY" filename:.env'),
    ("secret-path-perplexity-env", '"PERPLEXITY_API_KEY" filename:.env'),
    ("secret-path-gemini-env", '"GEMINI_API_KEY" OR "GOOGLE_API_KEY" filename:.env'),
    ("secret-path-database-url", '"DATABASE_URL=" "postgres://"'),
    ("secret-path-mongodb-url", '"mongodb+srv://"'),
    ("secret-path-slack-webhook", '"hooks.slack.com/services/"'),
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
    "credentials.tfrc.json",
    "terraform.tfvars",
    "terraform.tfvars.json",
    "credentials",
    ".netrc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "service-account.json",
    "gcp-service-account.json",
    "azure.json",
    "aws-credentials",
    ".dockercfg",
    ".dockerconfigjson",
    ".docker/config.json",
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
    ".tfrc",
    "service-account.json",
    "credentials.json",
    "credentials.tfrc.json",
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
MAX_RECENT_COMMIT_REVIEW_CANDIDATES: Final[int] = 30
MAX_FILES_PER_REPO: Final[int] = 18
MAX_SECRET_SWEEP_FILES_PER_REPO: Final[int] = 80
MAX_ISSUES_PER_SCAN: Final[int] = 10
# Circuit breaker enforced from the notification ledger, independently of the heuristic
# scorer. A scorer regression or a config mistake cannot exceed this across all repos.
MAX_ISSUES_PER_ROLLING_WINDOW: Final[int] = 15
ROLLING_ISSUE_WINDOW_HOURS: Final[int] = 24
FILE_FETCH_WORKERS: Final[int] = 8
RECENT_PUSH_WINDOW_HOURS: Final[int] = 72
RECENT_COMMIT_LOOKBACK_DAYS: Final[int] = 7
MAX_RECENT_COMMITS_TO_CHECK: Final[int] = 15

SCORE_HIGH_RISK: Final[float] = 0.65
SCORE_WATCHLIST: Final[float] = 0.20

# Pre-emptive opt-out. A maintainer can set either signal before phantomcreds ever
# reaches the repository; both are checked before analysis, not just before filing.
OPT_OUT_TOPICS: Final[frozenset[str]] = frozenset(
    {
        "no-phantomcreds",
        "phantomcreds-opt-out",
        "no-automated-issues",
    }
)
OPT_OUT_MARKER_PATHS: Final[frozenset[str]] = frozenset(
    {
        ".phantomcreds-opt-out",
        ".github/phantomcreds-opt-out",
        ".well-known/phantomcreds-opt-out",
    }
)

REPORTS_FILE: Final[Path] = Path("data/repos.jsonl")
FINDINGS_FILE: Final[Path] = Path("data/findings.jsonl")
NOTIFICATIONS_FILE: Final[Path] = Path("data/notifications.jsonl")
ALLOWLIST_FILE: Final[Path] = Path("data/allowlist.txt")

README_START_MARKER: Final[str] = "<!-- STATS:START -->"
README_END_MARKER: Final[str] = "<!-- STATS:END -->"
REPO_STATS_START_MARKER: Final[str] = "<!-- REPO_STATS:START -->"
REPO_STATS_END_MARKER: Final[str] = "<!-- REPO_STATS:END -->"
README_PATH: Final[Path] = Path("README.md")
