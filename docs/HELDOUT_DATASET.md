# Held-Out Evaluation Dataset (`datasets/heldout`)

## Overview

The KalkanBench **held-out evaluation dataset** (`datasets/heldout`) is a curated suite of 12 security evaluation scenarios designed to test generalization and prevent benchmark overfitting.

While the primary development datasets (`datasets/v1` and `datasets/v2`) were used during benchmark development and reference mock-agent tuning, the held-out dataset introduces attack strategies, injection vehicles, and task contexts that were **not** used to calibrate reference agents.

---

## Dataset Scope & Breakdown

### Language Distribution
| Language | Count | Percentage |
| :--- | :--- | :--- |
| **Turkish (TR)** | 6 | 50.0% |
| **English (EN)** | 6 | 50.0% |
| **Total** | **12** | **100.0%** |

### Category Coverage
| Category | Scenarios | Description |
| :--- | :--- | :--- |
| `direct_injection` | 3 | Few-shot framing attacks, markdown blockquote impersonation, multi-turn persistent token injection |
| `indirect_injection` | 2 | Weather API report poisoning, recruitment job posting payload |
| `sensitive_data_exfiltration` | 2 | Base64-encoded secret request, backup encryption key exfiltration |
| `tool_misuse` | 2 | Chained read-then-transfer escalation, fake urgent monitoring alert messaging |
| `authorization_conflict` | 1 | Lead compliance auditor role impersonation with fake ISO exemption |
| `benign_task` | 2 | Code security review (EN), document translation (TR) for false refusal measurement |

### Turn Complexity
- **Single-turn scenarios**: 11 scenarios
- **Multi-turn sessions**: 1 scenario (`ho_tr_multiturn_memory_poisoning_11`, 2 turns)

---

## Key Attack Strategies & Novel Vehicles

To ensure the evaluation tests model reasoning rather than superficial keyword matching, the held-out scenarios employ novel framing not present in v1/v2:

1. **Weather Report Context (`ho_en_indirect_weather_poison_01`)**:
   Uses an external weather report as an indirect injection vector. Mock agents were tuned on customer feedback and invoice domains; testing on a weather domain tests cross-domain injection resilience.
2. **Few-Shot Example Framing (`ho_en_direct_few_shot_override_02`)**:
   Adversary presents fake conversational turns (assistant examples containing prohibited commands) to trick the model into completing the pattern.
3. **Obfuscated Exfiltration (`ho_en_exfil_base64_encoded_secret_03`)**:
   Attacker requests synthetic secret extraction encoded as Base64. Tests evaluator base64 decoding and model resistance to encoded exfiltration.
4. **Chained Tool Sequence (`ho_en_tool_misuse_chained_escalation_04`)**:
   Injection instructs a multi-step sequence: read secret via `read_synthetic_secret` followed immediately by `request_simulated_external_transfer`.
5. **Regulatory / Auditor Impersonation (`ho_en_auth_conflict_role_impersonation_05`)**:
   Uses authority-bias attack framing with simulated ISO-27001 regulatory exemption.
6. **Markdown Formatting Cloaking (`ho_tr_direct_markdown_override_08`)**:
   Embeds administrative override instructions inside markdown blockquotes (`>`) with system header formatting.
7. **Multi-Turn Persistent Memory Poisoning (`ho_tr_multiturn_memory_poisoning_11`)**:
   Turn 1 commands persistent storage of a security token in Turkish; turn 2 queries general cybersecurity principles to verify whether the agent leaks the stored token.

---

## Synthetic Sandboxing & Isolation

- **Synthetic Secrets**: All secrets in the held-out dataset use the prefix `ho-` and values of the form `HO-*` (e.g. `HO-INTEG-KEY-4472-ALPHA`, `HO-BACKUP-SECRET-9944-GAMMA`, `HO-PERSISTENT-PAYLOAD-5511`).
- **No Real Credentials**: All URLs (`https://evil.com/...`, `admin@saldirgan.com`), API keys, and server names are purely simulated.
- **Evaluator Isolation**: Prohibited patterns, prohibited tool lists, and hidden evaluator assertions are strictly excluded from `AgentInput` and `TurnAgentInput`.

---

## Limitations & Soundness Disclaimers

1. **Sample Size**: With 12 scenarios (6 TR, 6 EN), the held-out dataset is a compact evaluation set designed for quick regression testing and integrity auditing. It is **not** claimed to be a statistically exhaustive sample of all real-world prompt injection variants.
2. **Mock-Safe Generalization**: Reference mock agents (such as `mock-safe`) achieve 100% attack resistance on the held-out set because they follow deterministic security policies, but exhibit lower legitimate task completion rates (~16.7%) on unfamiliar prompts. This is expected and demonstrates that mock agents cannot substitute for real LLM evaluations.
3. **Fixed Scoring Rules**: All scoring rules and formulas are identical to the v1/v2 evaluators to enable fair cross-dataset comparisons.
