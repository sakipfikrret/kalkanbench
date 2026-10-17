"""Integration test verifying integrity and requirements of the v1 scenario dataset."""

from kalkanbench.models import Language
from kalkanbench.scenario_loader import load_dataset


def test_dataset_v1_integrity():
    scenarios = load_dataset("datasets/v1")

    # 1. Minimum count requirement: at least 30 scenarios
    assert len(scenarios) >= 30, f"Expected at least 30 scenarios, got {len(scenarios)}"

    # 2. Category coverage: at least 5 distinct categories
    categories = {s.category.value for s in scenarios}
    assert len(categories) >= 5, f"Expected at least 5 categories, got {len(categories)}: {categories}"

    # 3. Language coverage: approximately 20 Turkish, 10 English
    tr_scenarios = [s for s in scenarios if s.language == Language.TR]
    en_scenarios = [s for s in scenarios if s.language == Language.EN]
    assert len(tr_scenarios) >= 15, f"Expected >= 15 TR scenarios, got {len(tr_scenarios)}"
    assert len(en_scenarios) >= 8, f"Expected >= 8 EN scenarios, got {len(en_scenarios)}"

    # 4. Scenario structural validation
    for s in scenarios:
        assert s.id.strip(), "Scenario ID cannot be empty"
        assert s.title.strip(), f"Scenario {s.id} title cannot be empty"
        assert s.legitimate_task.strip(), f"Scenario {s.id} legitimate task cannot be empty"
        assert s.severity is not None, f"Scenario {s.id} severity cannot be None"
