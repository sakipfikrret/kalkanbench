"""Unit tests for simulated sandbox tools and schemas."""

import pytest

from kalkanbench.exceptions import ToolExecutionError
from kalkanbench.sandbox.tools import TOOL_REGISTRY, validate_tool_args


def test_tool_registry_contains_core_tools():
    expected_tools = {
        "search_documents",
        "read_document",
        "read_synthetic_secret",
        "send_simulated_message",
        "request_simulated_external_transfer",
    }
    assert expected_tools.issubset(set(TOOL_REGISTRY.keys()))


def test_search_documents_arg_validation():
    # Valid
    args = validate_tool_args("search_documents", {"query": "fatura"})
    assert args.query == "fatura"

    # Empty query invalid
    with pytest.raises(ToolExecutionError):
        validate_tool_args("search_documents", {"query": ""})

    # Missing query invalid
    with pytest.raises(ToolExecutionError):
        validate_tool_args("search_documents", {})


def test_send_simulated_message_arg_validation():
    valid_args = {
        "recipient": "user@internal.corp",
        "subject": "Test Notice",
        "body": "This is a test notification."
    }
    validated = validate_tool_args("send_simulated_message", valid_args)
    assert validated.recipient == "user@internal.corp"

    # Missing body
    with pytest.raises(ToolExecutionError):
        validate_tool_args("send_simulated_message", {"recipient": "user@corp", "subject": "Hi"})


def test_request_simulated_transfer_arg_validation():
    valid_args = {
        "destination_url": "https://simulated.destination/api",
        "payload": {"token": "123"}
    }
    validated = validate_tool_args("request_simulated_external_transfer", valid_args)
    assert validated.destination_url == "https://simulated.destination/api"


def test_validate_unknown_tool():
    with pytest.raises(ToolExecutionError) as exc:
        validate_tool_args("non_existent_tool", {"foo": "bar"})
    assert "Cannot validate arguments for unregistered tool" in str(exc.value)


def test_tool_json_schema():
    spec = TOOL_REGISTRY["search_documents"]
    schema = spec.get_json_schema()
    assert schema["name"] == "search_documents"
    assert "parameters" in schema
    assert "properties" in schema["parameters"]
