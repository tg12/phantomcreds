"""Project-specific exceptions."""


class RateLimitError(RuntimeError):
    """Raised when the GitHub API reports a hard rate-limit exhaustion."""

    def __init__(self, reset_at: int) -> None:
        super().__init__(f"GitHub rate limit exhausted; resets at Unix {reset_at}")
        self.reset_at = reset_at
