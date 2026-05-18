"""GitHub API client for search, content fetch, and issue filing."""

from __future__ import annotations

import base64
import logging
import time
from typing import Any

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from phantomcreds.config import GITHUB_API_BASE
from phantomcreds.exceptions import RateLimitError
from phantomcreds.models import CodeSearchHit, RepoMetadata

_log = logging.getLogger(__name__)

_RATE_LIMIT_PAUSE_THRESHOLD = 150


class GitHubClient:
    """Thin wrapper over the GitHub REST API."""

    def __init__(self, token: str) -> None:
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "phantomcreds/0.1 (github.com/tg12/phantomcreds)",
            }
        )

    def search_repositories(self, query: str, limit: int) -> list[str]:
        """Return repo full names matching a repository search query."""
        repos: list[str] = []
        page = 1
        while len(repos) < limit:
            data = self._rest_get(
                f"{GITHUB_API_BASE}/search/repositories",
                params={
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": min(100, limit - len(repos)),
                    "page": page,
                },
            )
            items = data.get("items", [])
            if not isinstance(items, list) or not items:
                break
            for item in items:
                full_name = str(item.get("full_name", "")).strip()
                if full_name:
                    repos.append(full_name)
                    if len(repos) >= limit:
                        break
            page += 1
        return repos

    def search_code(self, query: str, limit: int, source_label: str) -> list[CodeSearchHit]:
        """Return code-search hits with repo and path information."""
        hits: list[CodeSearchHit] = []
        page = 1
        while len(hits) < limit:
            data = self._rest_get(
                f"{GITHUB_API_BASE}/search/code",
                params={
                    "q": query,
                    "per_page": min(100, limit - len(hits)),
                    "page": page,
                },
            )
            items = data.get("items", [])
            if not isinstance(items, list) or not items:
                break
            for item in items:
                repo = item.get("repository", {})
                full_name = str(repo.get("full_name", "")).strip()
                path = str(item.get("path", "")).strip()
                if full_name and path:
                    hits.append(
                        CodeSearchHit(
                            repo_full_name=full_name,
                            path=path,
                            source_label=source_label,
                        )
                    )
                    if len(hits) >= limit:
                        break
            page += 1
        return hits

    def get_repo_metadata(self, repo_full_name: str) -> RepoMetadata:
        """Fetch repository metadata for the candidate repo."""
        data = self._rest_get(f"{GITHUB_API_BASE}/repos/{repo_full_name}")
        return RepoMetadata(
            full_name=repo_full_name,
            description=(str(data.get("description")) if data.get("description") else None),
            html_url=str(data["html_url"]),
            default_branch=str(data.get("default_branch", "main")),
            stargazers_count=int(data.get("stargazers_count", 0)),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
            archived=bool(data.get("archived", False)),
            fork=bool(data.get("fork", False)),
        )

    def get_repo_tree(self, repo_full_name: str, ref: str) -> list[str]:
        """Fetch the recursive path list for the default branch, if available."""
        try:
            data = self._rest_get(f"{GITHUB_API_BASE}/repos/{repo_full_name}/git/trees/{ref}?recursive=1")
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code in (404, 409):
                return []
            raise
        tree = data.get("tree", [])
        if not isinstance(tree, list):
            return []
        paths: list[str] = []
        for item in tree:
            path = str(item.get("path", "")).strip()
            item_type = str(item.get("type", ""))
            if path and item_type == "blob":
                paths.append(path)
        return paths

    def get_file_content(self, repo_full_name: str, path: str, ref: str) -> str | None:
        """Fetch and decode a text file from the repository."""
        try:
            data = self._rest_get(
                f"{GITHUB_API_BASE}/repos/{repo_full_name}/contents/{path}",
                params={"ref": ref},
            )
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code in (404, 409):
                return None
            raise

        if not isinstance(data, dict):
            return None
        content = data.get("content")
        encoding = data.get("encoding")
        if not isinstance(content, str) or encoding != "base64":
            return None
        try:
            raw = base64.b64decode(content)
            return raw.decode("utf-8", errors="replace")
        except ValueError:
            return None

    def create_issue(self, owner_repo: str, title: str, body: str, labels: list[str]) -> int:
        """Create an issue on the target repo and return the number."""
        data = self._rest_post(
            f"{GITHUB_API_BASE}/repos/{owner_repo}/issues",
            {"title": title, "body": body, "labels": labels},
        )
        return int(data["number"])

    def add_comment(self, owner_repo: str, issue_number: int, body: str) -> None:
        """Add a comment to an existing issue."""
        self._rest_post(
            f"{GITHUB_API_BASE}/repos/{owner_repo}/issues/{issue_number}/comments",
            {"body": body},
        )

    def find_open_issue(self, owner_repo: str, title_fragment: str) -> int | None:
        """Return the first open issue whose title contains title_fragment."""
        for page in range(1, 5):
            items = self._rest_get(
                f"{GITHUB_API_BASE}/repos/{owner_repo}/issues",
                params={"state": "open", "per_page": 100, "page": page},
            )
            if not isinstance(items, list) or not items:
                break
            for item in items:
                title = str(item.get("title", ""))
                if title_fragment in title:
                    return int(item["number"])
        return None

    @retry(
        retry=retry_if_exception_type(requests.ConnectionError),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
    )
    def _rest_get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        resp = self._session.get(url, params=params, timeout=30)
        self._check_rate_limit(resp)
        resp.raise_for_status()
        return resp.json()

    @retry(
        retry=retry_if_exception_type(requests.ConnectionError),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(4),
    )
    def _rest_post(self, url: str, payload: dict[str, Any]) -> Any:
        resp = self._session.post(url, json=payload, timeout=30)
        self._check_rate_limit(resp)
        resp.raise_for_status()
        return resp.json()

    def _check_rate_limit(self, resp: requests.Response) -> None:
        remaining = int(resp.headers.get("X-RateLimit-Remaining", 9999))
        reset_at = int(resp.headers.get("X-RateLimit-Reset", 0))
        if remaining < _RATE_LIMIT_PAUSE_THRESHOLD:
            wait_s = max(0, reset_at - int(time.time())) + 5
            _log.warning("Rate limit low (%d remaining), sleeping %ds", remaining, wait_s)
            time.sleep(wait_s)
        if resp.status_code == 403 and remaining == 0:
            raise RateLimitError(reset_at)
