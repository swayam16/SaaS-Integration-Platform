"""Error taxonomy shared by every outbound call.

The distinction that matters for duplicate-free writes is *ambiguity*: after a timeout or a
5xx the remote side may or may not have applied the write. Non-idempotent writes must check
before they retry; idempotent ones (upsert by external ID, PATCH) can simply retry.
"""

from __future__ import annotations


class SyncError(Exception):
    """Base class."""


class TransientError(SyncError):
    """Safe to retry. `ambiguous` means the write may already have been applied."""

    def __init__(self, message: str, *, ambiguous: bool = False, retry_after: float | None = None):
        super().__init__(message)
        self.ambiguous = ambiguous
        self.retry_after = retry_after


class RateLimited(TransientError):
    """HTTP 429 / REQUEST_LIMIT_EXCEEDED. The request was rejected, so never ambiguous."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message, ambiguous=False, retry_after=retry_after)


class AuthExpired(SyncError):
    """Access token rejected; refresh and retry once."""


class PermanentError(SyncError):
    """Retrying will not help (validation error, missing record, revoked app). Dead-letter it."""


class Defer(SyncError):
    """Not an error: try this message again later (lock held, dependency not synced yet,
    retry budget exceeded). The worker returns it to the queue with a delay."""

    def __init__(self, reason: str, delay: float = 5.0):
        super().__init__(reason)
        self.delay = delay
