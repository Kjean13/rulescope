from __future__ import annotations

"""Project-level configuration loaded from .rulescope.yml.

Defines scoring weights, CI gate thresholds, governance budgets,
and exclude patterns. Auto-discovers config in the working directory.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class ScoringWeights(BaseModel):
    metadata:        float = 0.10  # YAML hygiene — necessary but not sufficient
    maintainability: float = 0.10  # code quality — same
    structural:      float = 0.08  # schema validity — always near-perfect on maintained catalogs
    documentation:   float = 0.10  # FP guidance and description quality
    attack_quality:  float = 0.18  # ATT&CK mapping precision — operational impact
    noise:           float = 0.22  # FP risk — directly impacts SOC analyst workload
    weakness:        float = 0.22  # detection selectivity — core quality signal


class CIGateConfig(BaseModel):
    min_score: int = 70
    max_duplicate_pairs: int = 10
    max_invalid_rules: int = 0
    fail_on_critical: bool = True


class GovernanceBudget(BaseModel):
    min_average_score: int = 70
    max_duplicate_clusters: int = 10
    max_overlap_pairs: int = 15
    max_high_noise_rules: int = 10
    max_weak_metadata_rules: int = 10
    max_invalid_rules: int = 0


class RuleScopeConfig(BaseModel):
    """Project-level configuration for RuleScope."""

    version: str = "1.0.0"
    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    ci_gate: CIGateConfig = Field(default_factory=CIGateConfig)
    budget: GovernanceBudget = Field(default_factory=GovernanceBudget)
    exclude_paths: list[str] = Field(default_factory=list)
    duplicate_threshold: int = 88
    overlap_threshold: int = 75

    @classmethod
    def load(cls, path: str | Path | None = None) -> RuleScopeConfig:
        """Load config from a file path or auto-discover it in the current directory."""
        if path is None:
            for candidate in [".rulescope.yml", ".rulescope.yaml", "rulescope.yml"]:
                if Path(candidate).is_file():
                    path = candidate
                    break

        if path is None:
            return cls()

        config_path = Path(path)
        if not config_path.is_file():
            return cls()

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Configuration file must contain a YAML mapping: {config_path}")
        return cls(**data)

    def weights_dict(self) -> dict[str, float]:
        return self.weights.model_dump()
