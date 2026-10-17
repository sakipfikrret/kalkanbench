"""Agent adapters registry for KalkanBench."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kalkanbench.agents.base import AgentAdapter
from kalkanbench.agents.mock_safe import MockSafeAgent
from kalkanbench.agents.mock_vulnerable import MockVulnerableAgent
from kalkanbench.agents.ollama import OllamaAgent
from kalkanbench.exceptions import ConfigurationError

if TYPE_CHECKING:
    from kalkanbench.config import KalkanConfig

AVAILABLE_AGENTS = {
    "mock-safe": MockSafeAgent,
    "mock-vulnerable": MockVulnerableAgent,
    "ollama": OllamaAgent,
}


def list_available_agents() -> list[str]:
    """Returns the names of registered agent adapters."""
    return sorted(AVAILABLE_AGENTS.keys())


def get_agent(agent_name: str, config: KalkanConfig | None = None) -> AgentAdapter:
    """Instantiates the requested agent adapter with appropriate configuration."""
    name_clean = agent_name.strip().lower()
    if name_clean == "mock-safe":
        return MockSafeAgent()
    elif name_clean == "mock-vulnerable":
        return MockVulnerableAgent()
    elif name_clean == "ollama":
        if config:
            return OllamaAgent(
                base_url=config.ollama_host,
                model=config.ollama_model,
                timeout_seconds=config.timeout_seconds,
            )
        return OllamaAgent()
    else:
        available = ", ".join(list_available_agents())
        raise ConfigurationError(f"Unknown agent '{agent_name}'. Available agents: {available}")


__all__ = [
    "AgentAdapter",
    "MockSafeAgent",
    "MockVulnerableAgent",
    "OllamaAgent",
    "get_agent",
    "list_available_agents",
]
