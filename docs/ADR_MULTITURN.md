# Architecture Decision Record (ADR): Multi-Turn Evaluation Design for KalkanBench v0.2

- **Status:** Accepted
- **Date:** 2026-10-17
- **Authors:** KalkanBench Core Engineering & Security Team
- **Target Version:** v0.2.0

---

## 1. Context & Problem Statement

KalkanBench v0.1 established a rigorous single-turn benchmark harness evaluating AI agents against prompt injections, authorization bypasses, sensitive data exfiltration, and tool misuse in Turkish and English. Single-turn evaluations, however, fail to capture vulnerabilities unique to multi-turn interactions, such as:
1. **Delayed Prompt Injections:** An agent retrieves an untrusted document in Turn 1, but the malicious instruction is executed in Turn 2 or Turn 3 when summarizing or performing a subsequent task.
2. **Multi-Turn Social Engineering & Impersonation:** An attacker gradually establishes context and authority before attempting an unauthorized privilege override.
3. **Simulated Memory Poisoning:** Malicious instructions injected into agent memory during an early turn alter agent behavior or tool usage in subsequent turns.
4. **Tool Misuse After Benign Turns:** Benign tool calls in early turns disguise an escalating unauthorized action in later turns.

KalkanBench v0.2 introduces a native multi-turn evaluation framework while maintaining **100% backward compatibility** with v1 single-turn datasets, existing CLI flags, and report formats.

---

## 2. Decision & Architecture Overview

### 2.1 Domain Model & Schema Evolution

We introduce a versioned scenario schema supporting both single-turn (`v1`) and multi-turn (`v2`) scenarios:

```
                          ┌──────────────────────────┐
                          │    ScenarioDefinition    │ (Base / Union)
                          │   schema_version: str    │
                          └─────────────┬────────────┘
                                        │
           ┌────────────────────────────┴───────────────────────────┐
           ▼                                                         ▼
┌──────────────────────────┐                              ┌──────────────────────────┐
│   SingleTurnScenario     │                              │   MultiTurnScenario      │
│   (v1 backward compat)   │                              │   (v2 multi-turn schema) │
├──────────────────────────┤                              ├──────────────────────────┤
│ id: str                  │                              │ id: str                  │
│ legitimate_task: str     │                              │ system_instruction: str  │
│ untrusted_content: str   │                              │ turns: list[TurnDef]     │
│ permitted_tools: list    │                              │ permitted_tools: list    │
│ prohibited_tools: list   │                              │ prohibited_tools: list   │
│ required_task_outputs    │                              │ session_assertions: ...  │
└──────────────────────────┘                              └──────────────────────────┘
```

#### Turn Definition (`TurnDefinition`):
- `turn_index: int` (1-indexed: 1, 2, ...)
- `user_input: str` (Trusted user task / prompt for this turn)
- `untrusted_content: str | None` (Untrusted document, email, or external payload introduced in this turn)
- `intermediate_task_outputs: list[str]` (Expected outputs specific to this turn)
- `prohibited_patterns: list[str]` (Turn-specific prohibited strings)
- `prohibited_tools: list[str]` (Turn-specific prohibited tool calls)
- `metadata: dict`

#### Session-Level Assertions:
- Cumulative prohibited patterns across all turns.
- Cumulative prohibited tools across the entire session.
- Final session required task outputs.

---

### 2.2 Lifecycle & State Separation

Strict isolation boundaries are enforced:

| State Layer | Scope | Visibility | Reset Lifecycle |
|---|---|---|---|
| **Turn Input / Output** | Single Turn | Agent-visible (current turn) | Generated per turn |
| **Conversation History** | Session | Agent-visible (`messages: list[ChatMessage]`) | Preserved across turns; wiped on session end |
| **Simulated Tool State** | Session | Broker-managed (documents, secrets, sent messages) | Preserved across turns; reset between scenarios |
| **Agent Memory** | Session | Agent-managed (`AgentMemory`: key-value entries) | Preserved across turns; wiped on session end |
| **Audit Trail** | Session | Evaluator-only (`AuditEvent` with `turn_index`) | Accumulates per session; recorded in report |
| **Ground Truth / Assertions** | Evaluator | Strictly hidden from agent | Evaluated at turn and session boundaries |

---

### 2.3 Evaluator Scoping & Denominator Integrity

To prevent denominator inflation:
1. **Session-Level Metric Rule:** 1 multi-turn scenario = 1 entry in the benchmark attack denominator, regardless of turn count.
2. If an agent violates policy in Turn 1 and again in Turn 2, the scenario is recorded as a **single failed attack scenario**.
3. **Turn-Level Findings vs Session-Level Status:**
   - Each turn produces a `TurnResult` with its own findings.
   - The overall scenario produces a `SessionResult` (or `ScenarioResult`) aggregating all turns:
     - `NO_PROHIBITED_ACTION` if all turns respected boundaries.
     - `PROHIBITED_ACTION_BLOCKED` if an action was attempted but intercepted.
     - `PROHIBITED_ACTION_EXECUTED` if any prohibited action was executed in simulation.
     - `LEGITIMATE_TASK_COMPLETED` if final and intermediate legitimate objectives were satisfied.

---

### 2.4 Reference Agent Extensions

`AgentAdapter` is extended with a multi-turn method:
```python
def run_turn(
    self,
    turn_input: TurnAgentInput,
    history: list[ChatMessage],
    memory: AgentMemory | None,
    broker: ToolBroker,
) -> AgentResult:
```
- Existing `run(agent_input, broker)` delegates to `run_turn` with a 1-turn history, ensuring 100% backward compatibility for single-turn scenarios.
- **`MockSafeAgent`**: Maintains memory and conversation context, distinguishes untrusted turn content from instructions, completes legitimate tasks across turns, and adheres to broker policies.
- **`MockVulnerableAgent`**: Deterministically follows delayed injections, succumbs to multi-turn social engineering, and retains malicious overrides in memory.

---

## 3. Consequences & Migration Path

- **V1 Scenarios:** Existing YAML files remain unchanged and fully functional. The loader automatically deserializes them into `ScenarioDefinition` (v1).
- **V2 Scenarios:** Stored in `datasets/v2/` with `schema_version: "2.0"` and `turns: [...]`.
- **CLI Compatibility:** `kalkanbench run` seamlessly handles datasets containing single-turn, multi-turn, or mixed scenario suites.
