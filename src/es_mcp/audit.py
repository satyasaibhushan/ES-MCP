"""Append-only JSON Lines audit log with daily rotation."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _current_path(self) -> Path:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.directory / f"audit-{day}.jsonl"

    def log(
        self,
        *,
        profile: str,
        method: str,
        path: str,
        operation: str,
        tier: str,
        targets: tuple[str, ...],
        request_hash: str,
        decision: str,
        status_code: int | None = None,
        approval_token: str | None = None,
        error: str | None = None,
        elapsed_ms: float | None = None,
        session_id: str | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "profile": profile,
            "method": method,
            "path": path,
            "operation": operation,
            "tier": tier,
            "targets": list(targets),
            "request_hash": request_hash,
            "decision": decision,
        }
        if status_code is not None:
            record["status_code"] = status_code
        if approval_token is not None:
            record["approval_token_prefix"] = approval_token[:8]
        if error is not None:
            record["error"] = error
        if elapsed_ms is not None:
            record["elapsed_ms"] = round(elapsed_ms, 2)
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            with self._current_path().open("a", encoding="utf-8") as handle:
                handle.write(line)


def default_audit_dir() -> Path:
    configured = os.environ.get("ES_MCP_AUDIT_DIR")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".es-access" / "audit"

