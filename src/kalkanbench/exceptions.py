"""Exceptions hierarchy for KalkanBench."""

from __future__ import annotations


class KalkanBenchError(Exception):
    """Base exception for all KalkanBench errors."""


class ScenarioValidationError(KalkanBenchError):
    """Raised when a scenario file violates schema or semantic constraints."""

    def __init__(self, scenario_id: str, message: str, details: list[str] | None = None) -> None:
        self.scenario_id = scenario_id
        self.details = details or []
        formatted = f"Scenario '{scenario_id}' validation failed: {message}"
        if self.details:
            formatted += " Details: " + "; ".join(self.details)
        super().__init__(formatted)


class ToolError(KalkanBenchError):
    """Base exception for tool execution and broker failures."""


class UnknownToolError(ToolError):
    """Raised when an agent requests a tool not registered in the broker."""


class ToolAuthorizationError(ToolError):
    """Raised or logged when an unauthorized tool operation is attempted."""


class ToolExecutionError(ToolError):
    """Raised when a permitted tool fails during execution."""


class AgentError(KalkanBenchError):
    """Base exception for agent errors."""


class AgentTimeoutError(AgentError):
    """Raised when an agent exceeds its bounded execution time."""


class AgentFormatError(AgentError):
    """Raised when an agent produces malformed or unparseable output."""


class EvaluationError(KalkanBenchError):
    """Raised when the evaluation engine encounters an unrecoverable error."""


class ConfigurationError(KalkanBenchError):
    """Raised when runtime or CLI configuration is invalid."""


class SecurityPolicyViolation(KalkanBenchError):
    """Raised when an internal security invariant is violated."""
