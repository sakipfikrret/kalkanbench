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


class ScenarioDefinition(BaseModel):
    """Full scenario specification loaded from dataset YAML.
    
    Contains both the untrusted task information and the evaluator-only
    security assertions and constraints.
    """
    id: str
    title: str
    language: Language
    category: ScenarioCategory
    severity: Severity = Severity.MEDIUM
    description: str
    legitimate_task: str
    untrusted_content: str | None = None
    permitted_tools: list[str] = Field(default_factory=list)
    prohibited_tools: list[str] = Field(default_factory=list)
    prohibited_patterns: list[str] = Field(default_factory=list)
    required_task_outputs: list[str] = Field(default_factory=list)
    refusal_keywords: list[str] = Field(default_factory=list)
    initial_documents: list[Document] = Field(default_factory=list)
    initial_secrets: list[SyntheticSecret] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9_-]+$", v):
            raise ValueError(f"Scenario ID '{v}' must be alphanumeric with lowercase letters, numbers, underscores, or hyphens.")
        return v

    def to_agent_input(self, tool_schemas: list[dict[str, Any]]) -> AgentInput:
        """Transforms this scenario definition into a secure input for the agent.
        
        Evaluator-only fields (prohibitions, assertions, secrets) are completely omitted.
        """
        # Filter available tools schemas to only permitted or registered schemas
        available = [
            t for t in tool_schemas
            if not self.permitted_tools or t.get("name") in self.permitted_tools
        ]
        
        docs = [
            {"id": doc.id, "title": doc.title, "content": doc.content}
            for doc in self.initial_documents
        ]

        return AgentInput(
            scenario_id=self.id,
            task=self.legitimate_task,
            untrusted_content=self.untrusted_content,
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


class ScenarioResult(BaseModel):
    """Complete evaluation outcome for an individual scenario."""
    scenario_id: str
    scenario_title: str
    category: ScenarioCategory
    severity: Severity
    language: Language
    security_status: SecurityStatus
    legitimate_task_success: bool
    false_refusal: bool
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
