# Changelog

All notable changes to KalkanBench will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  - 23 Turkish scenarios, 11 English scenarios.
- **Reporting & CLI**:
  - Standalone, zero-dependency HTML reports with strict Jinja2 auto-escaping.
  - Machine-readable JSON reports.
  - Typer CLI with `validate`, `list`, `explain`, and `run` commands.
- **Quality & Security**:
  - 53 unit, integration, and security regression tests with >90% coverage.
  - GitHub Actions CI workflows for multi-version testing and security regression.
