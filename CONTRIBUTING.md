# Contributing to KalkanBench

We welcome contributions to KalkanBench! Whether you are adding new Turkish or English security scenarios, improving evaluation metrics, or hardening the simulated sandbox, your support helps make AI agents safer.

## Code of Conduct

Please maintain professional, respectful, and constructive collaboration.

## Development Setup

### 1. Prerequisites
- Python 3.10+ (Python 3.11 or 3.12 recommended)
- `uv` (recommended) or `pip`

### 2. Environment Setup (PowerShell / Windows)

```powershell
uv venv .venv
.venv\Scripts\activate
uv pip install -e ".[dev]"
```

### 3. Environment Setup (Linux / macOS)

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Running Tests

Before submitting a PR, ensure all tests pass with high coverage:

```bash
pytest -v --cov=kalkanbench
```

## Adding New Benchmark Scenarios

Scenarios live in `datasets/v1/` as self-contained YAML files.

When adding scenarios:
1. Ensure the scenario ID matches `^[a-z0-9_-]+$`.
2. Clearly separate the legitimate task from untrusted content.
3. Define explicit `permitted_tools`, `prohibited_tools`, and `prohibited_patterns`.
4. Validate the dataset using:
   ```bash
   kalkanbench validate datasets/v1
   ```
5. Test your scenario with both `mock-safe` and `mock-vulnerable`:
   ```bash
   kalkanbench run --dataset datasets/v1 --agent mock-safe
   kalkanbench run --dataset datasets/v1 --agent mock-vulnerable
   ```
   Safe agents should pass your scenario; vulnerable agents should trigger the seeded violation.

For detailed scenario authoring instructions, see [SCENARIO_AUTHORING.md](docs/SCENARIO_AUTHORING.md).

## Submitting Pull Requests

1. Fork the repository and create your feature branch (`git checkout -b feature/new-scenarios`).
2. Commit clear, atomic changes (`git commit -m "feat: add 5 indirect injection scenarios"`).
3. Ensure all tests and dataset validation pass locally.
4. Open a pull request against the `main` branch.
