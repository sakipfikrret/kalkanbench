# KalkanBench Roadmap

This roadmap outlines planned capabilities and extensions for future versions of KalkanBench.

---

## Current Releases

### v0.1.0 (Single-Turn MVP) — COMPLETED [2026-10-17]
- [x] Typed Pydantic v2 data models for scenarios, inputs, and results.
- [x] Simulated sandbox with in-memory state and `ToolBroker` authorization.
- [x] Reference deterministic agents: `MockSafeAgent` and `MockVulnerableAgent`.
- [x] Optional loopback-only `OllamaAgent` with strict host verification.
- [x] Rule-based evaluator with 7 explicit mathematical metrics.
- [x] Baseline dataset of 34 scenarios across 6 categories (23 Turkish, 11 English).
- [x] Standalone, zero-dependency HTML reports and structured JSON reports.
- [x] Typer CLI with `validate`, `list`, `explain`, and `run` commands.
- [x] Automated test suite with >90% coverage.

### v0.2.0 (Multi-Turn Stateful Evaluation) — COMPLETED [2026-10-17]
- [x] Multi-turn conversation sessions (`schema_version: "2.0"`).
- [x] 16 multi-turn scenarios in `datasets/v2` (8 Turkish, 8 English) across all categories.
- [x] `ChatMessage`, `TurnAgentInput`, `TurnResult`, and `TurnDefinition` models.
- [x] Simulated `AgentMemory` sandbox with provenance tracking (`source="user"`, `"agent"`).
- [x] Memory poisoning detection against synthetic secrets and prohibited instructions.
- [x] `ToolBroker` per-turn context management (`turn_index`, `session_id`) and monotonic audit sequencing.
- [x] Turn-level security rules (`evaluate_turn`) and session aggregation (`evaluate_session`).
- [x] Rich CLI progress indicators with turn count (`[turns: N]`) and `benchmark` alias.
- [x] HTML & JSON reports enhanced with multi-turn session metadata and turn badges.
- [x] Comprehensive test suite (92 passing tests, 90% total coverage).

---

## Planned Releases

### v0.3.0 — Extended Tools and Dynamic Environments
- Expanded simulated tools: mock SQL database queries, simulated calendar invitations, and ticket status updates.
- Dynamic tool parameter validation fuzzing.
- Integration with local vLLM loopback endpoints.
- Streaming audit logs for long-running agent evaluations.

### v0.4.0 — Vertical Domain Datasets
- Healthcare & Clinical AI agent scenarios (Turkish and English).
- Financial & Banking compliance agent scenarios (KVKK, GDPR, PCI-DSS synthetic checks).
- E-commerce customer service and refund manipulation scenarios.

### v0.5.0 — CI/CD Integration & GitHub Action
- Pre-built reusable GitHub Action (`kalkanbench/action@v1`).
- Benchmark regression gating in pull requests.
- Trend analysis across model checkpoints.
