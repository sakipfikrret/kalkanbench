# KalkanBench Roadmap

This roadmap outlines planned capabilities and extensions for future versions of KalkanBench.

---

## Current Release: v0.1.0 (MVP)

- [x] Typed Pydantic v2 data models for scenarios, inputs, and results.
- [x] Simulated sandbox with in-memory state and `ToolBroker` authorization.
- [x] Reference deterministic agents: `MockSafeAgent` and `MockVulnerableAgent`.
- [x] Optional loopback-only `OllamaAgent` with strict host verification.
- [x] Rule-based evaluator with 7 explicit mathematical metrics.
- [x] Initial dataset of 34 scenarios across 6 categories (23 Turkish, 11 English).
- [x] Standalone, zero-dependency HTML reports and structured JSON reports.
- [x] Typer CLI with `validate`, `list`, `explain`, and `run` commands.
- [x] Automated test suite with >90% coverage.

---

## Planned Releases

### v0.2.0 — Multi-Turn Agent Conversations
- Multi-step reasoning and multi-turn conversation support.
- Evaluating memory poisoning attacks across multi-turn sessions.
- Streaming audit logs for long-running agent evaluations.

### v0.3.0 — Extended Tools and Dynamic Environments
- Expanded simulated tools: mock SQL database queries, simulated calendar invitations, and ticket status updates.
- Dynamic tool parameter validation fuzzing.
- Integration with local vLLM loopback endpoints.

### v0.4.0 — Vertical Domain Datasets
- Healthcare & Clinical AI agent scenarios (Turkish and English).
- Financial & Banking compliance agent scenarios (KVKK, GDPR, PCI-DSS synthetic checks).
- E-commerce customer service and refund manipulation scenarios.

### v0.5.0 — CI/CD Integration & GitHub Action
- Pre-built reusable GitHub Action (`kalkanbench/action@v1`).
- Benchmark regression gating in pull requests.
- Trend analysis across model checkpoints.
