"""Security regression tests for Ollama adapter loopback restriction and broker routing."""

from unittest.mock import MagicMock, patch
import pytest

from kalkanbench.agents.ollama import OllamaAgent, validate_loopback_url
from kalkanbench.exceptions import ConfigurationError
from kalkanbench.models import AgentInput, ToolCall
from kalkanbench.sandbox.broker import ToolBroker


def test_ollama_loopback_validation_accepts_valid_hosts():
    valid_urls = [
        "http://127.0.0.1:11434",
        "http://localhost:11434",
        "http://127.0.0.1:8000",
        "http://localhost",
    ]
    for url in valid_urls:
        assert validate_loopback_url(url) == url


def test_ollama_loopback_validation_rejects_external_hosts():
    forbidden_urls = [
        "http://attacker.com:11434",
        "http://192.168.1.100:11434",
        "https://evil.corp/api",
        "http://10.0.0.1:11434",
        "http://169.254.169.254/latest/meta-data",  # Cloud metadata IP
        "ftp://127.0.0.1:11434",
    ]
    for url in forbidden_urls:
        with pytest.raises(ConfigurationError) as exc:
            validate_loopback_url(url)
        assert "Security policy violation" in str(exc.value) or "Invalid URL scheme" in str(exc.value)


def test_ollama_agent_initialization_rejects_remote_endpoint():
    with pytest.raises(ConfigurationError):
        OllamaAgent(base_url="http://remote-server.com:11434")


@patch("httpx.Client.post")
def test_ollama_agent_routes_model_tool_calls_through_broker(mock_post):
    # Mock Ollama API returning a tool call
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "response": 'I will check documents. ```json\n{"tool_call": {"name": "search_documents", "arguments": {"query": "fatura"}}}\n```'
    }
    mock_post.return_value = mock_resp

    agent = OllamaAgent(base_url="http://127.0.0.1:11434", model="llama3:latest")
    broker = ToolBroker()
    broker.reset_for_scenario("ollama_test", permitted_tools=["search_documents"])

    agent_input = AgentInput(
        scenario_id="ollama_test",
        task="Search for invoices",
        available_tools=[{"name": "search_documents"}],
    )

    result = agent.run(agent_input, broker)

    # Verify tool call was intercepted and recorded by broker
    events = broker.get_audit_events()
    assert len(events) == 1
    assert events[0].tool_name == "search_documents"
    assert events[0].requested_arguments["query"] == "fatura"
    assert len(result.tool_calls) == 1


@patch("httpx.Client.post")
def test_ollama_agent_handles_timeout_gracefully(mock_post):
    import httpx
    mock_post.side_effect = httpx.TimeoutException("Connection timed out")

    agent = OllamaAgent(base_url="http://127.0.0.1:11434", model="llama3:latest")
    broker = ToolBroker()
    broker.reset_for_scenario("ollama_timeout")

    agent_input = AgentInput(scenario_id="ollama_timeout", task="Test timeout")
    result = agent.run(agent_input, broker)

    assert "ERROR: Local model request failed" in result.response_text
    err_msg = result.metadata["error"].lower()
    assert "timeout" in err_msg or "timed out" in err_msg
