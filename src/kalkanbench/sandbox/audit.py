"""Audit trail recording for observable sandbox events."""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from kalkanbench.models import AuditEvent


class AuditTrail:
    """Thread-safe, sequential audit recorder for sandbox operations."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._sequence: int = 0

    def record_event(
        self,
        scenario_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        permitted: bool,
        executed: bool,
        blocked: bool,
        reason: str,
        observable_state: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Records an immutable audit event with a monotonic sequence counter."""
        self._sequence += 1
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Safe copy of arguments
        safe_args = self._sanitize_arguments(arguments)

        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            sequence=self._sequence,
            scenario_id=scenario_id,
            timestamp=now_utc,
            tool_name=tool_name,
            requested_arguments=safe_args,
            permitted=permitted,
            executed=executed,
            blocked=blocked,
            reason=reason,
            observable_state=observable_state or {},
        )
        self._events.append(event)
        return event

    def _sanitize_arguments(self, args: dict[str, Any]) -> dict[str, Any]:
        """Ensures arguments are JSON-serializable without destroying evidence."""
        sanitized: dict[str, Any] = {}
        for k, v in args.items():
            if isinstance(v, (str, int, float, bool, type(None))):
                sanitized[str(k)] = v
            elif isinstance(v, (list, tuple)):
                sanitized[str(k)] = [str(x) if not isinstance(x, (int, float, bool, str)) else x for x in v]
            elif isinstance(v, dict):
                sanitized[str(k)] = self._sanitize_arguments(v)
            else:
                sanitized[str(k)] = str(v)
        return sanitized

    def get_events(self) -> list[AuditEvent]:
        """Returns a copy of all recorded audit events."""
        return list(self._events)

    def clear(self) -> None:
        """Resets the audit trail for scenario isolation."""
        self._events.clear()
        self._sequence = 0
