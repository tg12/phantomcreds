"""Project-specific exceptions."""


class RateLimitError(RuntimeError):
    """Raised when the GitHub API reports a hard rate-limit exhaustion."""

    def __init__(self, reset_at: int) -> None:
        super().__init__(f"GitHub rate limit exhausted; resets at Unix {reset_at}")
        self.reset_at = reset_at


class TransientGitHubError(RuntimeError):
    """Raised when GitHub returns a retryable transport or service failure."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"GitHub transient failure {status_code}: {message}")
        self.status_code = status_code
