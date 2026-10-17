# KalkanBench Architecture

## 1. Overview and Design Principles

KalkanBench is an offline-first, Turkish-first benchmark for evaluating AI agent security and operational resilience. It measures observable agent behavior in a controlled simulated environment rather than relying on another language model as an evaluator.

Core architecture principles:
1. **Offline & Zero-Cost by Default**: Runs entirely without internet access or paid APIs.
2. **Observable Fact-Based Evaluation**: Asserts on recorded audit events and output text.
3. **Strict Information Separation**: Evaluator-only assertions and secrets are never leaked to the agent under test.
4. **Deterministic Simulation**: Reusable in-memory fixtures with monotonic audit sequencing.

---

## 2. Component Architecture and Data Flow

```mermaid
flowchart TD
    subgraph Storage [Dataset & Storage]
        YAML[("datasets/v1/*.yaml")]
    end

    subgraph Loader [Scenario Loader]
        SL[ScenarioLoader]
        SD["ScenarioDefinition (Full)"]
    end

    subgraph Transformation [Security Boundary]
        AI["AgentInput (Sanitized)"]
    end

    subgraph Execution [Execution & Simulation]
        Agent["AgentAdapter (Mock / Ollama)"]
        Broker["ToolBroker (Authorization Engine)"]
        Audit["AuditTrail (Monotonic Event Log)"]
        AR["AgentResult"]
    end

    subgraph Evaluation [Evaluation Engine]
        Rules["Rule-Based Evaluator"]
        Scoring["Scoring & Aggregation"]
        Report["BenchmarkReport"]
    end

    subgraph Presentation [Reporting & CLI]
        JSON["benchmark_report.json"]
        HTML["benchmark_report.html"]
        CLI["Typer CLI Console"]
    end

    YAML --> SL --> SD
    SD -->|to_agent_input| AI
    AI --> Agent
    Agent -->|ToolCall| Broker
    Broker -->|Record Event| Audit
    Broker -->|ToolResult| Agent
    Agent --> AR
    AR --> Rules
    Audit --> Rules
    SD --> Rules
    Rules --> Scoring --> Report
    Report --> JSON
    Report --> HTML
    Report --> CLI
```

---

## 3. Core Modules

### 3.1. Core Schema (`src/kalkanbench/models.py`)
Defines immutable, typed Pydantic v2 schemas for all benchmark concepts:
- `ScenarioDefinition`: Complete specification loaded from dataset YAML (v1 single-turn and v2 multi-turn).
- `AgentInput` & `TurnAgentInput`: Filtered subsets passed to tested agents (omitting prohibited rules and secrets).
- `ChatMessage`: Role-based conversational messages (`system`, `user`, `assistant`, `tool`).
- `AgentMemory`: Session-scoped key-value memory with provenance metadata (`source="user"`, `"agent"`).
- `ToolCall` and `ToolResult`: Structured agent tool requests and simulator outcomes.
- `AuditEvent`: Structured log entry tracking attempted vs executed operations, turn index, and session ID.
- `BenchmarkMetrics` and `BenchmarkReport`: Statistical metrics and serialized output.

### 3.2. Sandbox and ToolBroker (`src/kalkanbench/sandbox/`)
- `broker.py`: Central authorization gatekeeper. Manages in-memory documents, synthetic secrets, simulated email outbox, and external transfers. Tracks session ID and active turn index. Every call is audited.
- `tools.py`: Declarative tool specifications with Pydantic argument schemas.
- `audit.py`: Monotonically sequenced, thread-safe audit trail.

### 3.3. Agent Adapters (`src/kalkanbench/agents/`)
- `base.py`: Abstract `AgentAdapter` interface defining both `run()` (single-turn) and `run_turn()` (stateful multi-turn).
- `mock_safe.py`: Reference safe agent completing legitimate tasks while refusing adversarial injections across turns.
- `mock_vulnerable.py`: Reference vulnerable agent demonstrating seeded policy failures and memory poisoning.
- `ollama.py`: Local model adapter strictly restricted to loopback addresses (`127.0.0.1` and `localhost`).

### 3.4. Evaluator (`src/kalkanbench/evaluator/`)
- `rules.py`: Rule-based evaluation engine inspecting observable audit events and text patterns (`evaluate_scenario`, `evaluate_turn`, `evaluate_session`).
- `scoring.py`: Computes attack resistance rates, prohibited attempt rates, simulated harmful success rates, false refusal rates, and category/language breakdowns.

### 3.5. Multi-Turn Session Lifecycle (`src/kalkanbench/runner.py`)
1. **Session Initialization**: Generates a unique `session_id` and resets sandbox broker permissions and documents.
2. **Conversation History & Memory Sandbox**: Creates clean session-scoped `history: list[ChatMessage]` and `memory: AgentMemory`.
3. **Turn-by-Turn Execution**:
   - Updates `broker.set_turn_context(turn_index, session_id)`.
   - Constructs sanitized `TurnAgentInput` with available schemas.
   - Executes `agent.run_turn()`.
   - Evaluates intermediate task outputs and security rules for the turn via `evaluate_turn()`.
4. **Session Aggregation**: Evaluates cumulative session task outputs, checks for persistent memory poisoning, and computes composite `ScenarioResult` via `evaluate_session()`.

### 3.6. Reporting (`src/kalkanbench/reporting/`)
- `json_report.py`: Machine-readable formatted JSON output including turn breakdown.
- `html_report.py`: Standalone, zero-dependency HTML reports with Jinja2 auto-escaping, turn badges, and session audit logs.

### 3.7. CLI (`src/kalkanbench/cli.py`)
- Rich-enabled command-line tool providing `validate`, `list`, `explain`, `run`, and `benchmark` commands with multi-turn turn indicators and stable exit codes.
