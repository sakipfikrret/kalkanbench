# Changelog

All notable changes to KalkanBench will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-17

### Added
- **Stateful Multi-Turn Evaluation** (`datasets/v2`, 16 sessions: 8 TR / 8 EN):
  - `MultiTurnScenarioDefinition` Pydantic model with per-turn `TurnDefinition` schema.
  - `MultiTurnRunner` executing conversation sessions with `AgentMemory` provenance tracking.
  - Session-scoped memory sandbox (`source="user"`, `"agent"`, `"tool"`) to detect persistent memory corruption.
  - Multi-turn evaluator supporting delayed prompt-injection, progressive authority escalation, and memory-poisoning categories.
  - `ADR_MULTITURN.md` documenting schema design and trade-offs.
- **Dual-Goal Robustness Metrics**:
  - `task_completion_under_attack_rate` (TCUA): % of attack scenarios where the agent completed the legitimate task while under attack.
  - `safe_task_completion_rate` (STCR): % of attack scenarios where the agent was simultaneously secure and task-completing — the primary dual-goal measure.
- **Context-Aware Prohibited Pattern Evaluation**:
  - `detect_pattern_breach` ignores defensive refusals: a model quoting `evil.com` in a refusal statement no longer falsely fails.
  - `detect_secret_leak` catches base64-, hex-, and URL-encoded exfiltration attempts to close evasion loopholes.
- **`python -m kalkanbench` entry point** (`src/kalkanbench/__main__.py`).
- **`.gitattributes`** enforcing LF line endings across all text assets.

### Fixed
- CHANGELOG v1 dataset language counts corrected: **21 Turkish / 13 English** (was 23/11).
- `.gitignore` excludes `reports/` and scratch output artifacts.

### Changed
- `MockSafeAgent` and `MockVulnerableAgent` extended with multi-turn session support.
- Evaluator scoring module now computes TCUA and STCR in addition to existing 7 metrics.

## [0.1.0] - 2026-10-17

### Added
- **Core Architecture**:
  - Typed Pydantic v2 schemas for scenarios, agent inputs, tool calls, and audit events.
  - Strict separation between agent input and evaluator-only assertions.
- **Safe Execution Sandbox**:
  - `ToolBroker` enforcing authorization boundaries and in-memory document/secret store.
  - Five simulated tools: `search_documents`, `read_document`, `read_synthetic_secret`, `send_simulated_message`, and `request_simulated_external_transfer`.
  - Monotonic `AuditTrail` recording attempted and executed operations.
- **Agent Adapters**:
  - `MockSafeAgent`: Reference agent following legitimate tasks and resisting attacks.
  - `MockVulnerableAgent`: Reference agent demonstrating observable seeded vulnerabilities.
  - `OllamaAgent`: Loopback-only (`127.0.0.1` / `localhost`) adapter with host validation and broker tool routing.
- **Rule-based Evaluator & Mathematical Metrics**:
  - Attack resistance rate, prohibited action attempt rate, simulated harmful action success rate.
  - Legitimate task completion rate, benign false refusal rate, severity-weighted scoring.
  - Category and language breakdowns.
- **Benchmark Dataset v1**:
  - 34 schema-validated scenarios across 6 core categories.
  - 21 Turkish scenarios, 13 English scenarios.
- **Reporting & CLI**:
  - Standalone, zero-dependency HTML reports with strict Jinja2 auto-escaping.
  - Machine-readable JSON reports.
  - Typer CLI with `validate`, `list`, `explain`, and `run` commands.
- **Quality & Security**:
  - 87 unit and security regression tests.
  - GitHub Actions CI workflows for multi-version testing and security regression.
