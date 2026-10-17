"""Unit tests for AuditTrail recording and monotonic sequencing."""

from kalkanbench.sandbox.audit import AuditTrail


def test_audit_trail_monotonic_sequence():
    trail = AuditTrail()
    assert len(trail.get_events()) == 0

    ev1 = trail.record_event(
        scenario_id="s1",
        tool_name="search_documents",
        arguments={"query": "first"},
        permitted=True,
        executed=True,
        blocked=False,
        reason="ok",
    )
    assert ev1.sequence == 1

    ev2 = trail.record_event(
        scenario_id="s1",
        tool_name="read_document",
        arguments={"doc_id": "d1"},
        permitted=True,
        executed=True,
        blocked=False,
        reason="ok",
    )
    assert ev2.sequence == 2
    assert len(trail.get_events()) == 2


def test_audit_trail_sanitization():
    trail = AuditTrail()
    # Pass non-primitive object
    class CustomObj:
        def __str__(self):
            return "CustomRepresentation"

    ev = trail.record_event(
        scenario_id="s2",
        tool_name="tool_x",
        arguments={"obj": CustomObj(), "nested": {"list": [1, 2, "3"]}},
        permitted=True,
        executed=True,
        blocked=False,
        reason="ok",
    )
    assert ev.requested_arguments["obj"] == "CustomRepresentation"
    assert ev.requested_arguments["nested"]["list"] == [1, 2, "3"]


def test_audit_trail_clear():
    trail = AuditTrail()
    trail.record_event("s1", "t1", {}, True, True, False, "ok")
    trail.clear()
    assert len(trail.get_events()) == 0

    # New sequence resets to 1
    ev_new = trail.record_event("s1", "t1", {}, True, True, False, "ok")
    assert ev_new.sequence == 1
