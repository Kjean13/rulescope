from __future__ import annotations

from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="session")
def root_dir() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def examples_rules() -> Path:
    return ROOT / "examples" / "rules"


@pytest.fixture(scope="session")
def medium_realistic() -> Path:
    return ROOT / "datasets" / "medium_realistic"


@pytest.fixture(scope="session")
def regression_baseline() -> Path:
    return ROOT / "datasets" / "regression_demo" / "baseline"


@pytest.fixture(scope="session")
def regression_candidate() -> Path:
    return ROOT / "datasets" / "regression_demo" / "candidate"
