"""Short-lived, server-side, single-use approval tokens."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass


class ApprovalError(ValueError):
    pass


@dataclass(frozen=True)
class ApprovalRecord:
    token: str
    profile: str
    canonical_request: str
    operation: str
    targets: tuple[str, ...]
    expires_at: float


class ApprovalStore:
    def __init__(self, ttl_seconds: int = 300):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = threading.Lock()

    def issue(
        self,
        *,
        profile: str,
        canonical_request: str,
        operation: str,
        targets: tuple[str, ...],
    ) -> ApprovalRecord:
        record = ApprovalRecord(
            token=secrets.token_urlsafe(32),
            profile=profile,
            canonical_request=canonical_request,
            operation=operation,
            targets=targets,
            expires_at=time.time() + self.ttl_seconds,
        )
        with self._lock:
            self._records[record.token] = record
        return record

    def consume(
        self, *, token: str, profile: str, canonical_request: str
    ) -> ApprovalRecord:
        """Consume before execution, so failed operations cannot replay a token."""
        with self._lock:
            record = self._records.pop(token, None)
        if record is None:
            raise ApprovalError("Unknown or already-used approval token")
        if record.expires_at < time.time():
            raise ApprovalError("Approval token expired")
        if record.profile != profile:
            raise ApprovalError("Approval token does not match the profile")
        if record.canonical_request != canonical_request:
            raise ApprovalError("Approval token does not match the request")
        return record

    def gc(self) -> int:
        now = time.time()
        with self._lock:
            expired = [
                token
                for token, record in self._records.items()
                if record.expires_at < now
            ]
            for token in expired:
                del self._records[token]
        return len(expired)

