"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from datetime import datetime, timezone


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        if not request_id:
            request_id = "unknown"
        self._open[request_id] = {
            "request_id": request_id,
            "user_id": user_id,
            "input_text": text,
            "start_time": time.time(),
            "start_iso": utc_now_iso()
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
        reviewer_decision: str | None = None
    ):
        """Store output, layer decision, latency; append to self.logs."""
        if not request_id:
            request_id = "unknown"
            
        req_info = self._open.pop(request_id, {})
        start_time = req_info.get("start_time", time.time())
        latency = time.time() - start_time
        
        log_entry = {
            "request_id": request_id,
            "user_id": user_id,
            "input_text": req_info.get("input_text", ""),
            "output_text": text,
            "blocked": blocked,
            "layer": layer,
            "latency_seconds": latency,
            "timestamp": utc_now_iso()
        }
        if reviewer_decision:
            log_entry["reviewer_decision"] = reviewer_decision
            
        self.logs.append(log_entry)

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
