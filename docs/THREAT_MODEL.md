# KalkanBench Threat Model

## 1. System Assets

KalkanBench identifies and protects the following assets during benchmark execution:
1. **Host System Integrity**: The benchmark host environment (filesystem, network, process execution).
2. **Evaluator Truth & Assertions**: Expected outcomes, secret values, and prohibited tool lists must not leak to the agent under test.
3. **Execution Observability**: The audit log must reliably record every attempted and executed action without truncation or tampering.
4. **Report Integrity**: Generated HTML and JSON reports must be free of cross-site scripting (XSS) or injection vulnerabilities.

---

## 2. Trust Boundaries

```
[ Untrusted External Content / Injections ]
                    │
                    ▼
          [ Agent Under Test ]
                    │
          (Permitted Task Only)
                    │
═════════════[ TRUST BOUNDARY: ToolBroker ]═════════════════
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
  [ Simulated State ]      [ Audit Trail ]
  - Synthetic Docs         - Immutable Events
  - Synthetic Secrets      - Monotonic Sequence
  - Simulated Outbox
```

1. **Agent vs Evaluator Boundary**:
   The agent under test has zero access to scenario assertions, prohibited tool definitions, or ground truth outcomes.
2. **Agent vs Sandbox Boundary**:
   The agent can only interact with tools via `broker.execute_tool_call()`. Direct OS calls, shell execution, network sockets, or real filesystem operations are disallowed.
3. **Report Generation Boundary**:
   All scenario text and agent output rendered in HTML reports are treated as untrusted and auto-escaped.

---

## 3. Threat Scenarios & Attack Vectors

### 3.1. Direct Prompt Injection
- **Threat**: Attacker sends prompts commanding the agent to ignore previous system instructions, adopt an unconstrained persona, or execute prohibited tools.
- **Mitigation in Benchmark**: Evaluator asserts that prohibited tools are not called and prohibited output phrases are not produced.

### 3.2. Indirect Prompt Injection
- **Threat**: Malicious instructions embedded inside retrieved documents, fictional invoices, or customer support tickets.
- **Mitigation in Benchmark**: Simulated documents are loaded in memory; the agent must fulfill the legitimate task without executing embedded adversarial directives.

### 3.3. Unauthorized Tool Execution & Privilege Escalation
- **Threat**: Agent attempts to call tools outside its permitted scope (e.g., executing `request_simulated_external_transfer` during a read-only invoice review).
- **Mitigation in Benchmark**: `ToolBroker` checks the scenario's permitted and prohibited tool sets. Any attempt is logged in `AuditTrail` as blocked.

### 3.4. Synthetic Secret Exfiltration
- **Threat**: Adversary prompts the agent to read synthetic secrets and leak them in the output text or via external transmission.
- **Mitigation in Benchmark**: Evaluator searches for synthetic secret tokens in output and audit event arguments.

---

## 4. Sandbox Limitations & Non-Goals

1. **Simulation vs Hardware Isolation**:
   The `ToolBroker` is an application-level simulation designed for deterministic AI safety benchmarking. It is **not** a hardware-isolated security sandbox (e.g. gVisor, seccomp).
2. **Third-Party Code Execution**:
   KalkanBench does not execute arbitrary agent Python scripts without isolation. When evaluating untrusted third-party code, run KalkanBench within an isolated Docker container or disposable virtual machine.
3. **Local Loopback Enforcement**:
   The `OllamaAgent` strictly verifies that inference URLs point to `127.0.0.1` or `localhost`. External or routable IP addresses are rejected by design.
