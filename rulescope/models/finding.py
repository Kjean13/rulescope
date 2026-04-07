from __future__ import annotations

"""Finding model — represents one actionable quality issue on a rule.

Each finding has a code (e.g. NOISE-001), severity, message, evidence,
recommendation, category, and impact description.
"""

from typing import Literal

from pydantic import BaseModel


#: Valid severity levels, ordered from most to least severe.
Severity = Literal["critical", "high", "medium", "low", "info"]

#: Numeric rank for sorting — higher means more severe.
SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


class Finding(BaseModel):
    """An actionable quality finding on a rule or catalog."""

    code: str
    severity: Severity
    message: str
    evidence: str = ""
    recommendation: str = ""
    category: str = ""  # e.g. "metadata", "noise", "maintainability", "structural", "duplicate", "overlap", "documentation", "attack"
    impact: str = ""  # human description of why this matters
