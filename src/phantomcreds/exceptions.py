"""Project-specific exceptions."""


class RateLimitError(RuntimeError):
    """Raised when the GitHub API reports a hard rate-limit exhaustion."""
