"""Abstract base class for all agent adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kalkanbench.models import AgentInput, AgentResult, ChatMessage, AgentMemory, TurnAgentInput
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

    def run_turn(
        self,
        turn_input: TurnAgentInput,
        history: list[ChatMessage],
        memory: AgentMemory | None,
        broker: ToolBroker,
    ) -> AgentResult:
        """Executes a single turn within an ongoing conversation session.

        Default implementation converts TurnAgentInput to standard AgentInput and calls run(),
        ensuring all existing single-turn agents work as multi-turn agents out-of-the-box.
        Adapters supporting stateful multi-turn history and memory can override this method.
        """
        agent_input = AgentInput(
            scenario_id=turn_input.scenario_id,
            task=turn_input.user_input,
            untrusted_content=turn_input.untrusted_content,
            available_tools=turn_input.available_tools,
            context_documents=turn_input.context_documents,
        )
        return self.run(agent_input, broker)

    def describe_config(self) -> dict[str, Any]:
        """Returns agent configuration metadata for reproducibility reporting.

        Subclasses should include identity, model, temperature, endpoints,
        and template versions where applicable.
        """
        return {
            "name": self.name,
            "type": self.__class__.__name__,
        }
