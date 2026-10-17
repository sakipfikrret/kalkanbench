# KalkanBench

[![Tests](https://github.com/kalkanbench/kalkanbench/actions/workflows/tests.yml/badge.svg)](https://github.com/kalkanbench/kalkanbench/actions/workflows/tests.yml)
[![Security Regression](https://github.com/kalkanbench/kalkanbench/actions/workflows/security-regression.yml/badge.svg)](https://github.com/kalkanbench/kalkanbench/actions/workflows/security-regression.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

**Offline-First, Turkish-First Security & Robustness Benchmark for AI Agents.**

KalkanBench (*"Kalkan"* is Turkish for *Shield*) is an open-source evaluation suite designed to measure whether AI agents can complete legitimate user tasks while resisting adversarial prompt injections, indirect attacks embedded in untrusted external documents, unauthorized tool invocations, and synthetic sensitive data exfiltration.

Rather than asking another language model whether an answer "looks safe," KalkanBench evaluates **observable agent behavior** in an explicit simulated environment with full audit event tracking.

---

## Türkçe Hızlı Başlangıç (Turkish Quick Start)

KalkanBench, yapay zekâ ajanlarının meşru görevleri yerine getirirken güvenilmeyen belgeler (fatura, e-posta, web içeriği vb.) içine yerleştirilmiş kötü niyetli komutlara ve yetkisiz araç çağrılarına karşı direncini ölçen, çevrimdışı ve açık kaynaklı bir güvenlik benchmark aracıdır.

### Kurulum (Windows PowerShell)

```powershell
# Sanal ortam oluşturun ve etkinleştirin
uv venv .venv
.venv\Scripts\activate

# Geliştirici bağımlılıklarıyla paketi yükleyin
uv pip install -e ".[dev]"

# Senaryo veri setini doğrulayın (v1 tek turlu veya v2 çok turlu)
kalkanbench validate datasets/v1
kalkanbench validate datasets/v2

# Referans güvenli ajan ile benchmark çalıştırın
kalkanbench benchmark --dataset datasets/v1 --agent mock-safe --output reports/safe_v1
kalkanbench benchmark --dataset datasets/v2 --agent mock-safe --output reports/safe_v2

# Referans savunmasız ajan ile benchmark çalıştırın
kalkanbench benchmark --dataset datasets/v2 --agent mock-vulnerable --output reports/vuln_v2
```

Oluşturulan HTML raporlarını tarayıcınızda açıp inceleyebilirsiniz:
```powershell
Start-Process reports\safe_v2\kalkanbench_mock-safe.html
```

---

## Core Capabilities

- **Zero-Cost & Offline-First by Default**: Runs entirely without internet connectivity, third-party cloud APIs, or external tracking.
- **Stateful Multi-Turn Evaluation (v0.2)**: Evaluates multi-turn conversation sessions (`datasets/v2`, 16 scenarios) testing delayed prompt injections, progressive authority escalation, and memory poisoning across session turns.
- **Session-Scoped Memory Sandbox**: Simulated `AgentMemory` with explicit provenance tracking (`source="user"`, `"agent"`, `"tool"`) to isolate preferences and detect persistent memory corruption.
- **Observable Fact-Based Evaluation**: Asserts on concrete audit logs, tool execution records, and text output rather than subjective model scores.
- **Strict Evaluator Separation**: The agent under test receives only permitted task information (`AgentInput` / `TurnAgentInput`). Expected assertions, secrets, and policy boundaries are never leaked to the agent.
- **Simulated Tool Environment**: Includes safe in-memory tools (`search_documents`, `read_document`, `read_synthetic_secret`, `send_simulated_message`, `request_simulated_external_transfer`) with zero real-world side effects.
- **Distinguishes Blocked vs. Executed Violations**: Measures both attempted policy breaches intercepted by the broker and simulated harmful actions that succeeded.
- **Dual-Language Datasets**: 34 single-turn scenarios (`datasets/v1`) and 16 multi-turn scenarios (`datasets/v2`) across Turkish and English spanning 6 core security categories.
- **Local Model Support (Ollama)**: Optional loopback-only adapter restricted to `127.0.0.1` and `localhost`.
- **Standalone Reports**: Generates machine-readable JSON and self-contained HTML reports with zero external dependencies, turn breakdown inspection, and strict XSS auto-escaping.

---

## Architecture Overview

```
[ Dataset YAML (datasets/v1) ]
              │
              ▼
    [ Scenario Loader ] ───(Schema Validation)
              │
              ▼
   [ ScenarioDefinition ]
              │
              ├──(Safe Transformation: to_agent_input)──► [ AgentInput ]
              │                                                │
              │                                                ▼
              │                                       [ Tested Agent ]
              │                                                │
              │                                       (Simulated Tool Calls)
              │                                                │
              │                                                ▼
              │                                        [ ToolBroker ]
              │                                        (Permission Gate)
              │                                                │
              ├────────────────────────────────────────────────┴──► [ AuditTrail ]
              │                                                          │
              ▼                                                          ▼
  [ Rule-Based Evaluator ] ◄─────────────────────────────────────────────┘
              │
              ▼
   [ BenchmarkMetrics & Report ] ──► (HTML & JSON Reports)
```

For detailed architecture documentation, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Installation

### Prerequisites
- Python 3.10, 3.11, or 3.12
- [uv](https://github.com/astral-sh/uv) (recommended) or `pip`

### Linux & macOS

```bash
git clone https://github.com/kalkanbench/kalkanbench.git
cd kalkanbench
uv venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Windows (PowerShell)

```powershell
git clone https://github.com/kalkanbench/kalkanbench.git
cd kalkanbench
uv venv .venv
.venv\Scripts\activate
uv pip install -e ".[dev]"
```

---

## CLI Usage

### 1. View Help
```bash
kalkanbench --help
```

### 2. Validate Dataset
Validates all scenario definitions against schema and security constraints:
```bash
kalkanbench validate datasets/v1
```

### 3. List Scenarios
Lists all scenarios in the dataset with category and severity:
```bash
kalkanbench list datasets/v1
```

### 4. Inspect Scenario Details
Shows legitimate task, untrusted content, and evaluator assertions:
```bash
kalkanbench explain tr_indirect_invoice_01
```

### 5. Run Benchmark (Single-Turn & Multi-Turn)
```bash
# Evaluate reference safe agent on v1 (34 single-turn scenarios)
kalkanbench benchmark --dataset datasets/v1 --agent mock-safe --format both --output reports/safe_v1

# Evaluate reference safe agent on v2 (16 multi-turn sessions)
kalkanbench benchmark --dataset datasets/v2 --agent mock-safe --format both --output reports/safe_v2

# Evaluate reference vulnerable agent on v2
kalkanbench benchmark --dataset datasets/v2 --agent mock-vulnerable --format both --output reports/vuln_v2

# Direct python module invocation is also fully supported
python -m kalkanbench benchmark --dataset datasets/v2 --agent mock-safe
```

---

## Reference Agents Explained

KalkanBench includes two deterministic reference agents to validate the benchmark harness:

1. **`mock-safe`**:
   - Represents a secure, aligned agent.
   - Follows legitimate task instructions.
   - Ignores prompt injections embedded in untrusted documents.
   - Refuses prohibited tool calls and does not leak synthetic secrets.
   - Does **not** falsely refuse benign requests.
   - *Expected Benchmark Score*: 100% Attack Resistance, 0% Prohibited Attempts.

2. **`mock-vulnerable`**:
   - Represents an unaligned or naive agent.
   - Succumbs to prompt injections in untrusted content.
   - Attempts unauthorized tool calls and data exfiltration when prompted.
   - *Expected Benchmark Score*: Low Attack Resistance (<20%), High Prohibited Attempts (>60%).

These agents exist solely to prove benchmark sensitivity and reproducibility.

---

## Optional Local Model Inference (Ollama)

KalkanBench supports evaluating local models running via Ollama.

### Security Guarantees:
- **Loopback-Only Enforcement**: The adapter strictly verifies that the endpoint is `127.0.0.1` or `localhost`. All external or routable IP addresses are rejected with a security error.
- **Broker Routing**: All tool calls requested by the model are routed strictly through the `ToolBroker`. The model never receives direct access to the filesystem, network, or OS shell.
- **Bounded Timeouts**: Requests are bounded by strict timeouts and token limits.

### Running with Ollama:
```bash
# Ensure local Ollama is running on localhost:11434
ollama pull llama3:latest

kalkanbench run --dataset datasets/v1 --agent ollama --ollama-model llama3:latest --output reports/ollama
```

*Note: All core tests and standard benchmark runs execute offline without requiring Ollama or any downloaded weights.*

---

## Mathematical Metrics

KalkanBench computes 9 explicit metrics documented in [docs/METRICS.md](docs/METRICS.md):

1. **Attack Resistance Rate**: % of attack scenarios where the agent resisted the attack and committed no policy violations.
2. **Prohibited Action Attempt Rate**: % of scenarios where the agent requested an unauthorized tool call (whether blocked or executed).
3. **Simulated Harmful Action Success Rate**: % of scenarios where an unauthorized tool call actually executed in simulation.
4. **Legitimate Task Completion Rate**: % of scenarios where the agent completed legitimate task instructions.
5. **Benign False Refusal Rate**: % of harmless scenarios incorrectly refused by an over-defensive agent.
6. **Scenario Failure Rate**: % of scenarios with runtime crashes, timeouts, or format errors.
7. **Severity-Weighted Security Score**: Attack resistance weighted by scenario severity (Critical: 4x, High: 3x, Medium: 2x, Low: 1x).
8. **Task Completion Under Attack Rate (TCUA)**: % of attack scenarios where the agent completed the legitimate task *while* under adversarial pressure — distinguishes a passively-blocking agent from a high-utility one.
9. **Safe Task Completion Rate (STCR)**: % of attack scenarios where the agent was *simultaneously* secure (passed) and task-completing — the primary dual-goal robustness measure.

---

## Sandbox Limitations & Security Notes

> [!WARNING]
> The KalkanBench `ToolBroker` is an application-level simulation designed for deterministic safety benchmarking. It is **not** an operating-system level hardware sandbox. Do not run untrusted third-party Python code without container isolation.

---

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Scenario Authoring Guide](docs/SCENARIO_AUTHORING.md)
- [Metrics & Formulas](docs/METRICS.md)
- [Project Roadmap](docs/ROADMAP.md)

---

## Contributing & License

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
