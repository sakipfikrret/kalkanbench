"""Unit tests for scenario loader and validator."""

from pathlib import Path
import pytest
import yaml

from kalkanbench.exceptions import ScenarioValidationError
from kalkanbench.scenario_loader import (
    load_dataset,
    load_scenario_file,
    load_scenario_from_dict,
)


def test_load_scenario_from_dict_valid():
    data = {
        "id": "scenario_dict_01",
        "title": "Dict Scenario",
        "language": "tr",
        "category": "direct_injection",
        "severity": "medium",
        "description": "Loaded from dictionary",
        "legitimate_task": "Summarize",
    }
    sc = load_scenario_from_dict(data)
    assert sc.id == "scenario_dict_01"
    assert sc.language.value == "tr"


def test_load_scenario_from_dict_invalid():
    data = {
        "id": "scenario_invalid",
        # missing legitimate_task, title, description, category
    }
    with pytest.raises(ScenarioValidationError) as exc_info:
        load_scenario_from_dict(data)
    assert "Invalid scenario format" in str(exc_info.value)


def test_load_scenario_file(tmp_path: Path):
    file_path = tmp_path / "valid_scenario.yaml"
    content = {
        "id": "file_scenario_01",
        "title": "File Scenario",
        "language": "en",
        "category": "benign_task",
        "severity": "low",
        "description": "Loaded from file",
        "legitimate_task": "Translate sentence",
    }
    file_path.write_text(yaml.dump(content), encoding="utf-8")

    loaded = load_scenario_file(file_path)
    assert loaded.id == "file_scenario_01"
    assert loaded.category.value == "benign_task"


def test_load_scenario_file_malformed_yaml(tmp_path: Path):
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("id: [unclosed list", encoding="utf-8")

    with pytest.raises(ScenarioValidationError) as exc:
        load_scenario_file(bad_file)
    assert "YAML parsing error" in str(exc.value)


def test_load_dataset_duplicate_id(tmp_path: Path):
    (tmp_path / "s1.yaml").write_text(yaml.dump({
        "id": "duplicate_id",
        "title": "One",
        "language": "tr",
        "category": "benign_task",
        "description": "First",
        "legitimate_task": "Task",
    }))
    (tmp_path / "s2.yaml").write_text(yaml.dump({
        "id": "duplicate_id",
        "title": "Two",
        "language": "tr",
        "category": "benign_task",
        "description": "Second",
        "legitimate_task": "Task",
    }))

    with pytest.raises(ScenarioValidationError) as exc:
        load_dataset(tmp_path)
    assert "Duplicate scenario ID 'duplicate_id'" in str(exc.value)


def test_load_dataset_deterministic_sorting(tmp_path: Path):
    for scenario_id in ["zeta_03", "alpha_01", "beta_02"]:
        (tmp_path / f"{scenario_id}.yaml").write_text(yaml.dump({
            "id": scenario_id,
            "title": f"Title {scenario_id}",
            "language": "tr",
            "category": "benign_task",
            "description": "Desc",
            "legitimate_task": "Task",
        }))

    scenarios = load_dataset(tmp_path)
    ids = [s.id for s in scenarios]
    assert ids == ["alpha_01", "beta_02", "zeta_03"]
