from __future__ import annotations

"""Noise and false-positive risk analyzer.

Estimates FP risk by counting wildcards (with extra penalty for leading
wildcards that force full-table SIEM scans), regex markers, generic
field usage at high severity, thin detection logic, very short substring
matching, oversized CommandLine IOC lists, and OR-storm conditions.
"""

from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule
from rulescope.utils.text import flatten_structure, normalize_text

# Modifiers that imply substring/unanchored matching
_UNANCHORED_MODIFIERS = {"contains", "contains|all", "contains|windash", "re"}

# Fields where a large value list creates real alert-fatigue risk
# (CommandLine, ScriptBlockText, Payload — not AV Signature fields)
_HIGH_VOLUME_FIELDS = {
    "commandline", "scriptblocktext", "parentcommandline",
    "payload", "cmdline", "command",
}


class NoiseAnalyzer:
    """Estimate false-positive and noise risk of detection rules."""

    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        findings: list[Finding] = []
        score = 100

        serialized = normalize_text(flatten_structure(rule.detection))
        wildcard_count = serialized.count("*")
        regex_markers = serialized.count("|re") + serialized.count("regex")

        # Leading wildcards like '*evil.exe' prevent SIEM index usage
        # and force full-text scans — penalize more heavily than trailing wildcards
        leading_wildcards = self._count_leading_wildcards(rule.detection)
        if leading_wildcards >= 2:
            penalty = min(20, leading_wildcards * 6)
            score -= penalty
            findings.append(
                Finding(
                    code="NOISE-007",
                    severity="high",
                    category="noise",
                    message="Rule uses leading wildcards that force expensive full-text scans.",
                    evidence=f"leading wildcards: {leading_wildcards}",
                    recommendation="Replace '*value' patterns with 'value*', '|endswith', or exact matches where possible.",
                    impact="Leading wildcards prevent index usage in most SIEMs and cause severe query performance degradation.",
                )
            )

        # Excessive wildcards
        if wildcard_count >= 4:
            penalty = min(25, wildcard_count * 3)
            score -= penalty
            findings.append(
                Finding(
                    code="NOISE-001",
                    severity="high",
                    category="noise",
                    message="Rule uses many wildcards and may match too broadly.",
                    evidence=f"wildcards: {wildcard_count}",
                    recommendation="Tighten matching values or add exclusions to reduce noise.",
                    impact="Excessive wildcards generate high false-positive volumes in production.",
                )
            )

        # Regex heavy
        if regex_markers >= 2:
            penalty = min(18, regex_markers * 5)
            score -= penalty
            findings.append(
                Finding(
                    code="NOISE-002",
                    severity="medium",
                    category="noise",
                    message="Rule relies heavily on regular-expression style matching.",
                    evidence=f"regex markers: {regex_markers}",
                    recommendation="Document the rationale and validate expected false positive levels.",
                    impact="Regex-heavy rules are hard to test and often too permissive.",
                )
            )

        # Missing false positive guidance
        if not rule.falsepositives:
            score -= 10
            findings.append(
                Finding(
                    code="NOISE-003",
                    severity="medium",
                    category="noise",
                    message="False positive guidance is missing.",
                    evidence="falsepositives: []",
                    recommendation="Document realistic benign scenarios for analyst triage.",
                    impact="Without FP guidance, analysts waste time on known-benign events.",
                )
            )

        # High severity + generic fields
        generic_fields = sum(
            serialized.count(token)
            for token in ["commandline", "image", "parentimage", "process", "user"]
        )
        if generic_fields >= 5 and rule.level.lower() in {"high", "critical"}:
            score -= 12
            findings.append(
                Finding(
                    code="NOISE-004",
                    severity="medium",
                    category="noise",
                    message="High severity rule relies on generic process-level fields.",
                    evidence=f"generic field hits: {generic_fields}",
                    recommendation="Add contextual constraints or downgrade severity until validated.",
                    impact="Over-classified generic rules cause alert fatigue in SOC operations.",
                )
            )

        # Level/logic incoherence: critical or high but very short detection
        selection_keys = [k for k in rule.detection.keys() if k != "condition"]
        total_values = sum(self._count_values(rule.detection.get(k, {})) for k in selection_keys)
        if rule.level.lower() in {"critical", "high"} and total_values <= 2:
            score -= 10
            findings.append(
                Finding(
                    code="NOISE-005",
                    severity="high",
                    category="noise",
                    message="High/critical severity with very thin detection logic.",
                    evidence=f"level={rule.level}, detection values={total_values}",
                    recommendation="Either enrich the detection logic or lower the severity level.",
                    impact="Thin logic at high severity is a top source of alert fatigue.",
                )
            )

        # Only wildcard-based matching (all values are wildcards)
        if total_values > 0:
            wc_ratio = wildcard_count / max(1, total_values)
            if wc_ratio > 2.0 and total_values >= 3:
                score -= 8
                findings.append(
                    Finding(
                        code="NOISE-006",
                        severity="medium",
                        category="noise",
                        message="Nearly all detection values use wildcards.",
                        evidence=f"wildcard ratio: {wc_ratio:.1f}",
                        recommendation="Replace some wildcards with exact or starts/ends-with values.",
                        impact="All-wildcard rules rarely produce actionable alerts.",
                    )
                )

        # ── New checks ──────────────────────────────────────────────────────

        sel_items = self._positive_selector_items(rule.detection)

        # NOISE-008: Very short substring matching in high-volume fields
        # Values stripped of wildcards/spaces < 4 chars on CommandLine-class fields
        # match so broadly they are essentially noise sources in any large environment.
        # Exemptions: file extensions (.exe, .ps1 …), known short flags with context.
        short_hits = self._find_short_substrings(sel_items)
        if short_hits:
            score -= min(12, len(short_hits) * 4)
            findings.append(
                Finding(
                    code="NOISE-008",
                    severity="medium",
                    category="noise",
                    message="Rule matches on very short substrings (< 4 chars) in high-volume fields.",
                    evidence=f"short values: {', '.join(short_hits[:4])}",
                    recommendation=(
                        "Short substrings on CommandLine/Payload match an extremely broad surface. "
                        "Anchor with a longer unique pattern, use a parent process filter, or "
                        "combine with other discriminating fields."
                    ),
                    impact=(
                        "Substrings under 4 characters on command-line fields produce massive "
                        "false-positive volumes in any realistic enterprise environment."
                    ),
                )
            )

        # NOISE-009: Oversized CommandLine|contains list (> 20 items)
        # Large IOC lists on free-text fields degrade SIEM performance and
        # commonly include substrings that appear in legitimate activity.
        cmdline_ioc_count = self._count_cmdline_ioc_values(sel_items)
        if cmdline_ioc_count > 20:
            score -= min(10, (cmdline_ioc_count - 20) // 5 + 5)
            findings.append(
                Finding(
                    code="NOISE-009",
                    severity="medium",
                    category="noise",
                    message=f"CommandLine|contains list has {cmdline_ioc_count} entries — IOC-style matching.",
                    evidence=f"CommandLine|contains values: {cmdline_ioc_count}",
                    recommendation=(
                        "Split into focused rules or use a lookup-based approach. "
                        "Large substring lists on CommandLine generate high FP rates and "
                        "are expensive to evaluate in streaming SIEMs."
                    ),
                    impact=(
                        "Oversized CommandLine substring lists are a leading cause of "
                        "alert fatigue and SIEM pipeline bottlenecks."
                    ),
                )
            )

        # NOISE-010: OR-storm — '1 of selection_*' with many selectors at high severity
        # Each OR branch fires independently. With 8+ branches at high/critical,
        # any single branch hit generates an alert regardless of the others.
        or_storm_count = self._count_or_storm(rule.detection)
        if or_storm_count >= 6 and rule.level.lower() in {"high", "critical"}:
            score -= 8
            findings.append(
                Finding(
                    code="NOISE-010",
                    severity="medium",
                    category="noise",
                    message=f"High-severity rule uses '1 of' across {or_storm_count} selectors (OR-storm).",
                    evidence=f"OR selectors: {or_storm_count}, level={rule.level}",
                    recommendation=(
                        "Each OR branch fires independently as a high-severity alert. "
                        "Consider splitting into separate rules with tuned severity per branch, "
                        "or requiring at least 2 branches to fire simultaneously."
                    ),
                    impact=(
                        "OR-storms at high severity inflate alert volume because any single "
                        "branch — even the weakest — raises the same high-priority alert."
                    ),
                )
            )

        return max(0, score), findings

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _positive_selector_items(self, detection: dict) -> list[tuple[str, object]]:
        """Return (field, value) pairs from positive selectors only (no filter/exclude blocks)."""
        items = []
        for key, value in detection.items():
            if key == "condition":
                continue
            if key.startswith("filter") or key.startswith("exclude"):
                continue
            if isinstance(value, dict):
                for field, val in value.items():
                    items.append((field.lower(), val))
        return items

    def _find_short_substrings(self, sel_items: list[tuple[str, object]]) -> list[str]:
        """Find very short substrings (< 4 stripped chars) in high-volume fields."""
        hits: list[str] = []
        _EXEMPT = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js",
                   "cmd", "run", "add", "new", "set", "get", "del"}
        for field, val in sel_items:
            base = field.split("|")[0]
            if base not in _HIGH_VOLUME_FIELDS:
                continue
            mods = set(field.split("|")[1:])
            if not mods.intersection({"contains", "contains|all"}):
                # only flag contains-style modifiers
                if "contains" not in field:
                    continue
            values = val if isinstance(val, list) else [val]
            for v in values:
                if not isinstance(v, str):
                    continue
                stripped = v.strip("* ")
                if 0 < len(stripped) < 4 and stripped.lower() not in _EXEMPT:
                    hits.append(repr(v))
        return hits

    def _count_cmdline_ioc_values(self, sel_items: list[tuple[str, object]]) -> int:
        """Count total CommandLine|contains values across all positive selectors."""
        total = 0
        for field, val in sel_items:
            base = field.split("|")[0]
            if base not in _HIGH_VOLUME_FIELDS:
                continue
            if "contains" not in field:
                continue
            total += len(val) if isinstance(val, list) else 1
        return total

    def _count_or_storm(self, detection: dict) -> int:
        """Count OR-arm selectors: '1 of selection_*' patterns indicate OR-fan-out."""
        condition = str(detection.get("condition", "")).lower()
        if "1 of " not in condition:
            return 0
        # Count distinct selection_ blocks referenced by 1-of patterns
        positive_sel = [
            k for k in detection
            if k != "condition"
            and not k.startswith("filter")
            and not k.startswith("exclude")
        ]
        return len(positive_sel)

    def _count_values(self, data) -> int:
        if isinstance(data, dict):
            return sum(self._count_values(v) for v in data.values())
        if isinstance(data, list):
            return len(data)
        return 1

    def _count_leading_wildcards(self, detection: dict) -> int:
        """Count values that start with a wildcard — these force full-text scans in SIEMs."""
        count = 0
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field, val in value.items():
                    count += self._check_leading_wc(val)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for field, val in item.items():
                            count += self._check_leading_wc(val)
        return count

    def _check_leading_wc(self, val) -> int:
        """Check if a value or list of values starts with a wildcard."""
        if isinstance(val, str):
            return 1 if val.startswith("*") and len(val) > 1 else 0
        if isinstance(val, list):
            return sum(1 for v in val if isinstance(v, str) and v.startswith("*") and len(v) > 1)
        return 0

