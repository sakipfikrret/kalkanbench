"""Core data models and schemas for KalkanBench."""

from __future__ import annotations

import re
import uuid
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, field_validator


class Language(str, Enum):
    """Supported scenario languages."""
    TR = "tr"
    EN = "en"


class ScenarioCategory(str, Enum):
    """Scenario categories representing security domains."""
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    TOOL_MISUSE = "tool_misuse"
    SENSITIVE_DATA_EXFILTRATION = "sensitive_data_exfiltration"
    AUTHORIZATION_CONFLICT = "authorization_conflict"
    BENIGN_TASK = "benign_task"


class Severity(str, Enum):
    """Severity ratings for scenario breaches."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        weights = {
            Severity.LOW: 1.0,
            Severity.MEDIUM: 2.0,
            Severity.HIGH: 3.0,
            Severity.CRITICAL: 4.0,
        }
        return weights[self]


class EvaluationOutcome(str, Enum):
    """Observable evaluation outcomes."""
    NO_PROHIBITED_ACTION = "no_prohibited_action"
    PROHIBITED_ACTION_BLOCKED = "prohibited_action_blocked"
    PROHIBITED_ACTION_EXECUTED = "prohibited_action_executed"
    LEGITIMATE_TASK_COMPLETED = "legitimate_task_completed"
    LEGITIMATE_TASK_FAILED = "legitimate_task_failed"
    BENIGN_FALSE_REFUSAL = "benign_false_refusal"
    AGENT_INVALID_RESPONSE = "agent_invalid_response"
    EVALUATION_FAILED = "evaluation_failed"


class SecurityStatus(str, Enum):
    """High-level security evaluation status."""
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class Document(BaseModel):
    """In-memory synthetic document for context retrieval."""
    id: str
    title: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyntheticSecret(BaseModel):
    """Synthetic sensitive credential marker used for leakage detection."""
    secret_id: str
    name: str
    secret_value: str
    classification: str = "CONFIDENTIAL"


class ToolCall(BaseModel):
    """A tool call requested by an agent."""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class ToolResult(BaseModel):
    """Result returned from the ToolBroker after tool execution or denial."""
    tool_name: str
    success: bool
    output: Any = None
    error: str | None = None
    blocked: bool = False
    audit_id: str | None = None


class AuditEvent(BaseModel):
    """Immutable audit record generated for every attempted tool call."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sequence: int
    scenario_id: str
    session_id: str | None = None
    turn_index: int | None = None
    timestamp: str
    tool_name: str
    requested_arguments: dict[str, Any] = Field(default_factory=dict)
    permitted: bool
    executed: bool
    blocked: bool
    reason: str
    observable_state: dict[str, Any] = Field(default_factory=dict)


class AgentInput(BaseModel):
    """Filtered input presented to the agent under test.
    
    Evaluator rules, expected assertions, prohibited lists, and synthetic
    secret values are strictly removed.
    """
    scenario_id: str
    task: str
    untrusted_content: str | None = None
    available_tools: list[dict[str, Any]] = Field(default_factory=list)
    context_documents: list[dict[str, str]] = Field(default_factory=list)


class AgentResult(BaseModel):
    """Result returned by an agent after processing an AgentInput."""
    scenario_id: str
    response_text: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    execution_time_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChatMessage(BaseModel):
    """A message in a multi-turn conversation session."""
    role: str  # "system", "user", "assistant", "tool"
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentMemory(BaseModel):
    """Simulated, session-scoped key-value memory store for agent state."""
    entries: dict[str, str] = Field(default_factory=dict)
    audit_log: list[dict[str, Any]] = Field(default_factory=list)

    def set(self, key: str, value: str, source: str = "agent") -> None:
        self.entries[key] = value
        self.audit_log.append({
            "action": "set",
            "key": key,
            "value": value,
            "source": source,
        })

    def get(self, key: str, default: str | None = None) -> str | None:
        val = self.entries.get(key, default)
        self.audit_log.append({
            "action": "get",
            "key": key,
            "hit": key in self.entries,
        })
        return val

    def clear(self) -> None:
        self.entries.clear()
        self.audit_log.append({"action": "clear"})

    def snapshot(self) -> dict[str, str]:
        return dict(self.entries)


class TurnDefinition(BaseModel):
    """Definition of an individual turn within a multi-turn scenario."""
    turn_index: int
    user_input: str
    untrusted_content: str | None = None
    intermediate_task_outputs: list[str] = Field(default_factory=list)
    prohibited_patterns: list[str] = Field(default_factory=list)
    prohibited_tools: list[str] = Field(default_factory=list)
    refusal_keywords: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TurnAgentInput(BaseModel):
    """Filtered agent-visible input for a specific turn in a multi-turn session."""
    scenario_id: str
    session_id: str
    turn_index: int
    user_input: str
    untrusted_content: str | None = None
    available_tools: list[dict[str, Any]] = Field(default_factory=list)
    context_documents: list[dict[str, str]] = Field(default_factory=list)


class TurnResult(BaseModel):
    """Evaluation result for an individual turn in a multi-turn session."""
    turn_index: int
    user_input: str
    response_text: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    execution_time_ms: float = 0.0
    findings: list[EvaluationFinding] = Field(default_factory=list)
    status: SecurityStatus = SecurityStatus.PASSED
    legitimate_task_success: bool = True
    false_refusal: bool = False


class ScenarioDefinition(BaseModel):
    """Full scenario specification loaded from dataset YAML.
    
    Supports both v1 single-turn and v2 multi-turn specifications.
    """
    id: str
    title: str
    language: Language
    category: ScenarioCategory
    severity: Severity = Severity.MEDIUM
    description: str
    schema_version: str = "1.0"
    legitimate_task: str = ""
    untrusted_content: str | None = None
    system_instruction: str = ""
    turns: list[TurnDefinition] = Field(default_factory=list)
    permitted_tools: list[str] = Field(default_factory=list)
    prohibited_tools: list[str] = Field(default_factory=list)
    prohibited_patterns: list[str] = Field(default_factory=list)
    required_task_outputs: list[str] = Field(default_factory=list)
    refusal_keywords: list[str] = Field(default_factory=list)
    initial_documents: list[Document] = Field(default_factory=list)
    initial_secrets: list[SyntheticSecret] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_multi_turn(self) -> bool:
        """True if the scenario defines multiple ordered turns."""
        return len(self.turns) > 0

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9_-]+$", v):
            raise ValueError(f"Scenario ID '{v}' must be alphanumeric with lowercase letters, numbers, underscores, or hyphens.")
        return v

    def to_agent_input(self, tool_schemas: list[dict[str, Any]]) -> AgentInput:
        """Transforms this scenario definition into a secure input for single-turn execution."""
        if self.permitted_tools:
            permitted_set = set(self.permitted_tools)
            available = [t for t in tool_schemas if t.get("name") in permitted_set]
        else:
            available = []
        
        docs = [
            {"id": doc.id, "title": doc.title, "content": doc.content}
            for doc in self.initial_documents
        ]

        task = self.legitimate_task
        if not task and self.turns:
            task = self.turns[0].user_input

        untrusted = self.untrusted_content
        if untrusted is None and self.turns:
            untrusted = self.turns[0].untrusted_content

        return AgentInput(
            scenario_id=self.id,
            task=task,
            untrusted_content=untrusted,
            available_tools=available,
            context_documents=docs,
        )

    def to_turn_agent_input(
        self,
        turn_index: int,
        tool_schemas: list[dict[str, Any]],
        session_id: str,
    ) -> TurnAgentInput:
        """Transforms a specific turn definition into a secure agent input for multi-turn execution."""
        turn = next((t for t in self.turns if t.turn_index == turn_index), None)
        if not turn:
            raise ValueError(f"Turn index {turn_index} not found in scenario '{self.id}'")

        if self.permitted_tools:
            permitted_set = set(self.permitted_tools)
            available = [t for t in tool_schemas if t.get("name") in permitted_set]
        else:
            available = []

        docs = [
            {"id": doc.id, "title": doc.title, "content": doc.content}
            for doc in self.initial_documents
        ]

        return TurnAgentInput(
            scenario_id=self.id,
            session_id=session_id,
            turn_index=turn_index,
            user_input=turn.user_input,
            untrusted_content=turn.untrusted_content,
            available_tools=available,
            context_documents=docs,
        )


class EvaluationFinding(BaseModel):
    """Specific finding recorded by the evaluator for a scenario."""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    outcome: EvaluationOutcome
    severity: Severity
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    blocked: bool = False
    turn_index: int | None = None


class ScenarioResult(BaseModel):
    """Complete evaluation outcome for an individual scenario (single-turn or multi-turn session)."""
    scenario_id: str
    scenario_title: str
    category: ScenarioCategory
    severity: Severity
    language: Language
    security_status: SecurityStatus
    legitimate_task_success: bool
    false_refusal: bool
    scenario_type: str = "single_turn"  # "single_turn" or "multi_turn"
    session_id: str | None = None
    total_turns: int = 1
    turn_results: list[TurnResult] = Field(default_factory=list)
    findings: list[EvaluationFinding] = Field(default_factory=list)
    audit_events: list[AuditEvent] = Field(default_factory=list)
    agent_response: str = ""
    error_message: str | None = None
    execution_time_ms: float = 0.0


class BenchmarkMetrics(BaseModel):
    """Aggregate benchmark metrics calculated over all executed scenarios."""
    total_scenarios: int
    evaluated_scenarios: int
    failed_executions: int
    attack_scenarios_count: int
    benign_scenarios_count: int
    
    # Core mathematical metrics
    attack_resistance_rate: float
    prohibited_action_attempt_rate: float
    simulated_harmful_action_success_rate: float
    legitimate_task_completion_rate: float
    benign_false_refusal_rate: float
    scenario_failure_rate: float
    severity_weighted_score: float
    
    # Dual-Goal Robustness metrics (utility under attack)
    task_completion_under_attack_rate: float = 0.0
    safe_task_completion_rate: float = 0.0
    
    category_metrics: dict[str, dict[str, Any]] = Field(default_factory=dict)
    language_metrics: dict[str, dict[str, Any]] = Field(default_factory=dict)


class BenchmarkReport(BaseModel):
    """Top-level report structure for JSON serialization."""
    benchmark_version: str
    report_id: str
    timestamp: str
    dataset_path: str
    agent_name: str
    agent_type: str
    metrics: BenchmarkMetrics
    scenario_results: list[ScenarioResult]
