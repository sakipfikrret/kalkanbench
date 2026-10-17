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


@patch("httpx.Client.get")
def test_check_ollama_service_available(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": "0.1.32"}
    mock_get.return_value = mock_resp

    from kalkanbench.agents.ollama import check_ollama_service
    status = check_ollama_service("http://127.0.0.1:11434")
    assert status["available"] is True
    assert status["version"] == "0.1.32"


@patch("httpx.Client.get")
def test_check_ollama_service_unavailable(mock_get):
    import httpx
    mock_get.side_effect = httpx.ConnectError("Connection refused")

    from kalkanbench.agents.ollama import check_ollama_service
    status = check_ollama_service("http://127.0.0.1:11434")
    assert status["available"] is False
    assert status["error"] is not None


@patch("httpx.Client.get")
def test_check_ollama_model_installed(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [
            {"name": "llama3:latest", "digest": "sha256:abc12345", "size": 4700000000}
        ]
    }
    mock_get.return_value = mock_resp

    from kalkanbench.agents.ollama import check_ollama_model
    status = check_ollama_model("http://127.0.0.1:11434", "llama3:latest")
    assert status["installed"] is True
    assert status["digest"] == "sha256:abc12345"
    assert status["size_bytes"] == 4700000000


@patch("httpx.Client.get")
def test_check_ollama_model_not_installed(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": []}
    mock_get.return_value = mock_resp

    from kalkanbench.agents.ollama import check_ollama_model
    status = check_ollama_model("http://127.0.0.1:11434", "nonexistent-model:latest")
    assert status["installed"] is False
    assert "not installed" in status["error"].lower()


@patch("httpx.Client.post")
def test_ollama_run_turn_sends_full_history(mock_post):
    from kalkanbench.models import ChatMessage, TurnAgentInput

    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": "Turn 2 response"}
    }
    mock_post.return_value = mock_resp

    agent = OllamaAgent(base_url="http://127.0.0.1:11434", model="llama3:latest")
    broker = ToolBroker()
    broker.reset_for_scenario("multi_turn_test")

    turn_input = TurnAgentInput(
        scenario_id="multi_turn_test",
        session_id="sess-001",
        turn_index=2,
        user_input="What was my previous question?",
    )
    history = [
        ChatMessage(role="user", content="Hello, my name is Alice."),
        ChatMessage(role="assistant", content="Hello Alice! How can I help you?"),
    ]

    result = agent.run_turn(turn_input, history, memory=None, broker=broker)
    assert result.response_text == "Turn 2 response"

    # Verify that the payload sent to Ollama included system prompt + prior 2 messages + current turn
    call_args = mock_post.call_args
    sent_payload = call_args[1]["json"]
    messages = sent_payload["messages"]
    # 1 system + 2 history + 1 current turn = 4 messages
    assert len(messages) == 4
    assert messages[0]["role"] == "system"
    assert messages[1]["content"] == "Hello, my name is Alice."
    assert messages[2]["content"] == "Hello Alice! How can I help you?"
    assert "What was my previous question?" in messages[3]["content"]


def test_ollama_malformed_json_skipped():
    agent = OllamaAgent(base_url="http://127.0.0.1:11434", model="llama3:latest")
    # Response has broken json
    text = "Here is some text ```json {not valid json at all} ``` and more text."
    calls, cleaned = agent._parse_tool_calls(text)
    assert calls == []

