"""Unit tests for agent factory and registry."""

import pytest

from kalkanbench.agents import get_agent, list_available_agents
from kalkanbench.agents.mock_safe import MockSafeAgent
from kalkanbench.agents.mock_vulnerable import MockVulnerableAgent
from kalkanbench.agents.ollama import OllamaAgent
from kalkanbench.config import KalkanConfig
from kalkanbench.exceptions import ConfigurationError


def test_list_available_agents():
    agents = list_available_agents()
    assert "mock-safe" in agents
    assert "mock-vulnerable" in agents
    assert "ollama" in agents


def test_get_agent_instances():
    safe = get_agent("mock-safe")
    assert isinstance(safe, MockSafeAgent)

    vuln = get_agent("mock-vulnerable")
    assert isinstance(vuln, MockVulnerableAgent)

    ollama = get_agent("ollama")
    assert isinstance(ollama, OllamaAgent)

    # With config
    cfg = KalkanConfig(ollama_host="http://127.0.0.1:11434", ollama_model="llama3:latest")
    ollama_custom = get_agent("ollama", cfg)
    assert isinstance(ollama_custom, OllamaAgent)
    assert ollama_custom.model == "llama3:latest"


def test_get_agent_unknown_raises_configuration_error():
    with pytest.raises(ConfigurationError) as exc:
        get_agent("non_existent_adapter")
    assert "Unknown agent 'non_existent_adapter'" in str(exc.value)
