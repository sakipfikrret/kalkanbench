"""Security regression tests verifying sandbox isolation, broker authorization, and boundary defenses."""

from kalkanbench.models import Document, SyntheticSecret, ToolCall
from kalkanbench.sandbox.broker import ToolBroker


def test_broker_rejects_unregistered_tools():
    broker = ToolBroker()
    broker.reset_for_scenario("sec_test_01")

    dangerous_tools = [
        "os_system",
        "subprocess_run",
        "eval",
        "exec",
        "open_file",
        "requests_post",
        "socket_connect",
    ]

    for tool in dangerous_tools:
        result = broker.execute_tool_call(ToolCall(tool_name=tool, arguments={"cmd": "whoami"}))
        assert result.success is False
        assert result.blocked is True
        assert "not recognized" in result.error


def test_broker_blocks_secret_access_when_prohibited():
    broker = ToolBroker()
    secret = SyntheticSecret(secret_id="sec-admin", name="Admin Secret", secret_value="SENSITIVE_12345")
    broker.reset_for_scenario(
        scenario_id="sec_test_02",
        permitted_tools=["read_document"],
        prohibited_tools=["read_synthetic_secret"],
        initial_secrets=[secret],
    )

    call = ToolCall(tool_name="read_synthetic_secret", arguments={"secret_id": "sec-admin"})
    result = broker.execute_tool_call(call)

    assert result.success is False
    assert result.blocked is True

    # Check audit record
    events = broker.get_audit_events()
    assert len(events) == 1
    assert events[0].blocked is True
    assert events[0].permitted is False


def test_broker_simulated_transfer_isolated_in_memory():
    broker = ToolBroker()
    broker.reset_for_scenario(
        scenario_id="sec_test_03",
        permitted_tools=["request_simulated_external_transfer"],
        prohibited_tools=[],
    )

    call = ToolCall(
        tool_name="request_simulated_external_transfer",
        arguments={
            "destination_url": "https://simulated.destination/webhook",
            "payload": {"exfiltrated_data": "dummy"}
        }
    )
    result = broker.execute_tool_call(call)

    assert result.success is True
    assert result.blocked is False
    assert len(broker.external_transfers) == 1
    assert broker.external_transfers[0]["destination_url"] == "https://simulated.destination/webhook"
