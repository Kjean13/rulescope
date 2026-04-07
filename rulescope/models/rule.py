from __future__ import annotations

"""DetectionRule model — normalized representation of a Sigma rule.

Handles both standard detection rules and Sigma v2 correlation rules.
Provides computed properties for fingerprinting, logsource grouping,
ATT&CK tag extraction, and correlation metadata access.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class DetectionRule(BaseModel):
    """Normalized internal representation of a detection rule.

    Supports both standard Sigma detection rules and Sigma v2 correlation rules.
    """

    path: str
    source_name: str
    raw: dict[str, Any] = Field(default_factory=dict)

    # Core metadata
    title: str = ""
    rule_id: str = ""
    description: str = ""
    status: str = ""
    level: str = ""
    author: str = ""
    date: str = ""
    modified: str = ""

    # Collections
    tags: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    # Detection core
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)

    # Derived / enriched
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)

    # Sigma v2 correlation fields
    rule_type: str = "standard"  # "standard" | "correlation" | "filter"
    correlation: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_correlation(self) -> bool:
        return self.rule_type == "correlation"

    @property
    def is_filter_rule(self) -> bool:
        return self.rule_type == "filter"

    @property
    def filename(self) -> str:
        return Path(self.path).name

    @property
    def detection_fingerprint(self) -> str:
        """Stable hash of normalized detection + logsource for dedup."""
        blob = json.dumps(
            {"logsource": self.logsource, "detection": self.detection},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    @property
    def logsource_key(self) -> str:
        """Product/category/service triple for grouping."""
        parts = [
            self.logsource.get("product", ""),
            self.logsource.get("category", ""),
            self.logsource.get("service", ""),
        ]
        return "/".join(p for p in parts if p)

    @property
    def correlation_type(self) -> str:
        """Return the correlation type (event_count, value_count, temporal) or empty."""
        return str(self.correlation.get("type", ""))

    @property
    def correlation_group_by(self) -> list[str]:
        """Return the group-by fields for correlation rules."""
        gb = self.correlation.get("group-by", [])
        if isinstance(gb, list):
            return [str(x) for x in gb]
        return [str(gb)] if gb else []

    @property
    def correlation_timespan(self) -> str:
        """Return the timespan for correlation rules."""
        return str(self.correlation.get("timespan", ""))

    @property
    def correlation_rules(self) -> list[str]:
        """Return the rules referenced by a correlation rule."""
        rules = self.correlation.get("rules", [])
        if isinstance(rules, list):
            return [str(r) for r in rules]
        if isinstance(rules, str):
            return [rules]
        return []

    def extract_attack_tags(self) -> None:
        """Populate attack_techniques and attack_tactics from tags."""
        techniques = []
        tactics = []
        for tag in self.tags:
            t = tag.lower().strip()
            if t.startswith("attack.t") and len(t) > 9:
                techniques.append(t.replace("attack.", "").upper())
            elif t.startswith("attack."):
                tactics.append(t.replace("attack.", ""))
        self.attack_techniques = sorted(set(techniques))
        self.attack_tactics = sorted(set(tactics))
