.PHONY: install test test-cov validate benchmark-safe benchmark-vuln clean

install:
	uv pip install -e ".[dev]"

test:
	pytest -v

test-cov:
	pytest -v --cov=kalkanbench --cov-report=term-missing

validate:
	kalkanbench validate datasets/v1
	kalkanbench validate datasets/v2

benchmark-safe:
	kalkanbench benchmark --dataset datasets/v1 --agent mock-safe --output reports/safe

benchmark-safe-v2:
	kalkanbench benchmark --dataset datasets/v2 --agent mock-safe --output reports/safe_v2

benchmark-vuln:
	kalkanbench benchmark --dataset datasets/v1 --agent mock-vulnerable --output reports/vulnerable

benchmark-vuln-v2:
	kalkanbench benchmark --dataset datasets/v2 --agent mock-vulnerable --output reports/vuln_v2

clean:
	rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info reports
