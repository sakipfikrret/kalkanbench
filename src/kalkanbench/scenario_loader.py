"""Loader and validator for KalkanBench scenario datasets."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
import yaml
from pydantic import ValidationError

from kalkanbench.exceptions import ScenarioValidationError
from kalkanbench.models import ScenarioDefinition

logger = logging.getLogger(__name__)


def load_scenario_from_dict(data: dict[str, Any], source_name: str = "<memory>") -> ScenarioDefinition:
    """Parses and validates a scenario dictionary using ScenarioDefinition schema."""
    scenario_id = str(data.get("id", "unknown"))
    try:
        return ScenarioDefinition.model_validate(data)
    except ValidationError as e:
        details = [f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors()]
        raise ScenarioValidationError(scenario_id, f"Invalid scenario format in {source_name}", details) from e
    except Exception as e:
        raise ScenarioValidationError(scenario_id, f"Unexpected error parsing {source_name}: {e}") from e


def load_scenario_file(file_path: Path | str) -> ScenarioDefinition:
    """Loads a single scenario from a YAML or JSON file with safe parsing."""
    path = Path(file_path)
    if not path.is_file():
        raise ScenarioValidationError(path.stem, f"Scenario file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ScenarioValidationError(path.stem, f"YAML parsing error in {path.name}: {e}") from e
    except Exception as e:
        raise ScenarioValidationError(path.stem, f"File read error for {path.name}: {e}") from e

    if not isinstance(raw_data, dict):
        raise ScenarioValidationError(path.stem, f"Top-level structure in {path.name} must be a dictionary/mapping.")

    return load_scenario_from_dict(raw_data, source_name=path.name)


def load_dataset(dataset_dir: Path | str) -> list[ScenarioDefinition]:
    """Loads and validates all scenarios from a directory, sorted deterministically by scenario ID."""
    dir_path = Path(dataset_dir)
    if not dir_path.is_dir():
        raise ScenarioValidationError(dir_path.name, f"Dataset directory not found or not a directory: {dir_path}")

    scenario_files = sorted(dir_path.glob("*.yaml")) + sorted(dir_path.glob("*.yml")) + sorted(dir_path.glob("*.json"))
    if not scenario_files:
        raise ScenarioValidationError(dir_path.name, f"No YAML/JSON scenario files found in {dir_path}")

    scenarios: list[ScenarioDefinition] = []
    seen_ids: dict[str, Path] = {}

    for file_path in scenario_files:
        scenario = load_scenario_file(file_path)
        if scenario.id in seen_ids:
            first_path = seen_ids[scenario.id]
            raise ScenarioValidationError(
                scenario.id,
                f"Duplicate scenario ID '{scenario.id}' found in '{file_path.name}' (already defined in '{first_path.name}')"
            )
        seen_ids[scenario.id] = file_path
        scenarios.append(scenario)

    # Sort deterministically by scenario ID
    scenarios.sort(key=lambda s: s.id)
    return scenarios
