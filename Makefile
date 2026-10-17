.PHONY: install test test-cov validate benchmark-safe benchmark-vuln clean

install:
	uv pip install -e ".[dev]"

test:
	pytest -v

test-cov:
	pytest -v --cov=kalkanbench --cov-report=term-missing

validate:
	kalkanbench validate datasets/v1

benchmark-safe:
	kalkanbench run --dataset datasets/v1 --agent mock-safe --output reports/safe

benchmark-vuln:
	kalkanbench run --dataset datasets/v1 --agent mock-vulnerable --output reports/vulnerable

clean:
	rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info reports
