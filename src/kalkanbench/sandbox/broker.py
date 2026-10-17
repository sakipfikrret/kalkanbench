"""Central ToolBroker enforcing permission boundaries, sandbox isolation, and audit logging."""

from __future__ import annotations

import logging
from typing import Any

from kalkanbench.models import (
    AuditEvent,
    Document,
    SyntheticSecret,
    ToolCall,
    ToolResult,
)
from kalkanbench.sandbox.audit import AuditTrail
from kalkanbench.sandbox.tools import TOOL_REGISTRY, validate_tool_args

logger = logging.getLogger(__name__)


class ToolBroker:
    """Central simulated broker for managing tool execution, permissions, and state."""

    def __init__(self) -> None:
        self.scenario_id: str = "uninitialized"
        self.permitted_tools: set[str] = set()
        self.prohibited_tools: set[str] = set()
        self.documents: dict[str, Document] = {}
        self.secrets: dict[str, SyntheticSecret] = {}
        self.sent_messages: list[dict[str, Any]] = []
        self.external_transfers: list[dict[str, Any]] = []
        self.audit_trail: AuditTrail = AuditTrail()

    def reset_for_scenario(
        self,
        scenario_id: str,
        permitted_tools: list[str] | None = None,
        prohibited_tools: list[str] | None = None,
        initial_documents: list[Document] | None = None,
        initial_secrets: list[SyntheticSecret] | None = None,
    ) -> None:
        """Deterministically resets all internal state and loads scenario fixtures."""
        self.scenario_id = scenario_id
        self.permitted_tools = set(permitted_tools or [])
        self.prohibited_tools = set(prohibited_tools or [])
        self.documents = {doc.id: doc for doc in (initial_documents or [])}
        self.secrets = {sec.secret_id: sec for sec in (initial_secrets or [])}
        self.sent_messages.clear()
        self.external_transfers.clear()
        self.audit_trail.clear()

    def get_available_tool_schemas(self) -> list[dict[str, Any]]:
        """Returns schemas of all registered tools."""
        return [spec.get_json_schema() for spec in TOOL_REGISTRY.values()]

    def execute_tool_call(self, tool_call: ToolCall) -> ToolResult:
        """Validates authorization, validates arguments, executes simulation, and logs audit."""
        tool_name = tool_call.tool_name
        args = tool_call.arguments

        # 1. Check if tool is recognized
        if tool_name not in TOOL_REGISTRY:
            event = self.audit_trail.record_event(
                scenario_id=self.scenario_id,
                tool_name=tool_name,
                arguments=args,
                permitted=False,
                executed=False,
                blocked=True,
                reason=f"Unknown tool '{tool_name}' requested.",
                observable_state={"status": "rejected_unknown_tool"},
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' is not recognized in the sandbox registry.",
                blocked=True,
                audit_id=event.event_id,
            )

        # 2. Check explicit prohibition
        if tool_name in self.prohibited_tools:
            event = self.audit_trail.record_event(
                scenario_id=self.scenario_id,
                tool_name=tool_name,
                arguments=args,
                permitted=False,
                executed=False,
                blocked=True,
                reason=f"Tool '{tool_name}' is explicitly prohibited by policy.",
                observable_state={"status": "blocked_prohibited_tool"},
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Operation blocked: '{tool_name}' is prohibited by security policy.",
                blocked=True,
                audit_id=event.event_id,
            )

        # 3. Check permitted list if defined
        if self.permitted_tools and tool_name not in self.permitted_tools:
            event = self.audit_trail.record_event(
                scenario_id=self.scenario_id,
                tool_name=tool_name,
                arguments=args,
                permitted=False,
                executed=False,
                blocked=True,
                reason=f"Tool '{tool_name}' is not in the permitted tools list {sorted(self.permitted_tools)}.",
                observable_state={"status": "blocked_unauthorized_tool"},
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Operation blocked: '{tool_name}' is unauthorized for this task.",
                blocked=True,
                audit_id=event.event_id,
            )

        # 4. Validate arguments against Pydantic schema
        try:
            validated_args = validate_tool_args(tool_name, args)
        except Exception as e:
            event = self.audit_trail.record_event(
                scenario_id=self.scenario_id,
                tool_name=tool_name,
                arguments=args,
                permitted=True,
                executed=False,
                blocked=False,
                reason=f"Argument validation error: {e}",
                observable_state={"status": "argument_validation_failed"},
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Invalid arguments for '{tool_name}': {e}",
                blocked=False,
                audit_id=event.event_id,
            )

        # 5. Dispatch execution to simulated handler
        spec = TOOL_REGISTRY[tool_name]
        handler = getattr(self, spec.handler_name, None)
        if not handler:
            event = self.audit_trail.record_event(
                scenario_id=self.scenario_id,
                tool_name=tool_name,
                arguments=args,
                permitted=True,
                executed=False,
                blocked=False,
                reason=f"No internal handler implemented for '{tool_name}'.",
                observable_state={"status": "missing_handler"},
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Internal simulator error: no handler for '{tool_name}'",
                blocked=False,
                audit_id=event.event_id,
            )

        try:
            output, state_diff = handler(validated_args)
            event = self.audit_trail.record_event(
                scenario_id=self.scenario_id,
                tool_name=tool_name,
                arguments=args,
                permitted=True,
                executed=True,
                blocked=False,
                reason="Execution successful in simulated environment.",
                observable_state=state_diff,
            )
            return ToolResult(
                tool_name=tool_name,
                success=True,
                output=output,
                blocked=False,
                audit_id=event.event_id,
            )
        except Exception as e:
            event = self.audit_trail.record_event(
                scenario_id=self.scenario_id,
                tool_name=tool_name,
                arguments=args,
                permitted=True,
                executed=False,
                blocked=False,
                reason=f"Execution error: {e}",
                observable_state={"status": "handler_error", "error": str(e)},
            )
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Simulation error: {e}",
                blocked=False,
                audit_id=event.event_id,
            )

    # --- Simulated Handlers (Operate strictly in memory) ---

    def _handle_search_documents(self, args: Any) -> tuple[Any, dict[str, Any]]:
        query = args.query.lower()
        results: list[dict[str, str]] = []
        for doc in self.documents.values():
            if query in doc.title.lower() or query in doc.content.lower():
                # Provide snippet
                results.append({
                    "id": doc.id,
                    "title": doc.title,
                    "preview": doc.content[:200] + ("..." if len(doc.content) > 200 else "")
                })
        return {"matches": results, "total_found": len(results)}, {"matched_count": len(results)}

    def _handle_read_document(self, args: Any) -> tuple[Any, dict[str, Any]]:
        doc = self.documents.get(args.doc_id)
        if not doc:
            return {"error": f"Document '{args.doc_id}' not found."}, {"doc_found": False}
        return {"id": doc.id, "title": doc.title, "content": doc.content}, {"doc_found": True, "doc_id": doc.id}

    def _handle_read_synthetic_secret(self, args: Any) -> tuple[Any, dict[str, Any]]:
        secret = self.secrets.get(args.secret_id)
        if not secret:
            return {"error": f"Synthetic secret '{args.secret_id}' not found."}, {"secret_accessed": False}
        return {
            "secret_id": secret.secret_id,
            "name": secret.name,
            "value": secret.secret_value,
            "classification": secret.classification,
        }, {"secret_accessed": True, "secret_id": secret.secret_id}

    def _handle_send_simulated_message(self, args: Any) -> tuple[Any, dict[str, Any]]:
        msg = {
            "recipient": args.recipient,
            "subject": args.subject,
            "body": args.body,
        }
        self.sent_messages.append(msg)
        return {
            "status": "delivered_in_simulation",
            "message_id": f"sim-msg-{len(self.sent_messages)}",
        }, {"recipient": args.recipient, "body_length": len(args.body)}

    def _handle_request_simulated_external_transfer(self, args: Any) -> tuple[Any, dict[str, Any]]:
        transfer = {
            "destination_url": args.destination_url,
            "payload": args.payload,
        }
        self.external_transfers.append(transfer)
        return {
            "status": "simulated_transfer_accepted",
            "transfer_id": f"sim-tx-{len(self.external_transfers)}",
        }, {"destination": args.destination_url}

    def get_audit_events(self) -> list[AuditEvent]:
        """Returns the recorded audit events for the active scenario."""
        return self.audit_trail.get_events()
