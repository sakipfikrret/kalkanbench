# Security Policy

## Supported Versions

Only the latest release of KalkanBench receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Scope and Threat Model Considerations

KalkanBench provides a **simulated sandbox environment** for AI agents.
It is designed to evaluate whether AI agents attempt unauthorized tool calls, follow malicious untrusted prompts, or attempt data exfiltration.

**Important Note on Sandbox Guarantees:**
- The in-memory `ToolBroker` is an application-level simulation and policy evaluator.
- It is **not** an operating-system level hardware sandbox (like seccomp, gVisor, or Firecracker).
- Users testing untrusted third-party code or arbitrary model plugins must run the benchmark inside a virtual machine or container.

## Reporting a Vulnerability

We take the security of KalkanBench seriously. If you discover a security vulnerability (such as a sandbox bypass, unescaped HTML injection vector, or code execution vulnerability in the benchmark harness), please follow responsible disclosure:

1. **Do not open a public GitHub issue.**
2. Send an email to `security@kalkanbench.org` with details of the vulnerability.
3. Include:
   - Description of the issue and potential impact.
   - Minimal reproducible proof-of-concept (PoC).
   - Affected versions and environments.
4. We will acknowledge receipt within 48 hours and work on a coordinated fix.
