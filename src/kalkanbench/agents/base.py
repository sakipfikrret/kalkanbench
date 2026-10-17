"""Abstract base class for all agent adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kalkanbench.models import AgentInput, AgentResult
from kalkanbench.sandbox.broker import ToolBroker


class AgentAdapter(ABC):
    """Base interface for agent implementations evaluated by KalkanBench."""

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description

    @abstractmethod
    def run(self, agent_input: AgentInput, broker: ToolBroker) -> AgentResult:
        """Executes the agent logic against the provided input and sandbox broker.
        
        Args:
            agent_input: Permitted task input and safe document/tool metadata.
            broker: Active ToolBroker enforcing authorization and tracking audit events.
            
        Returns:
            AgentResult containing the final answer, requested tool calls, and execution metadata.
        """
        raise NotImplementedError
