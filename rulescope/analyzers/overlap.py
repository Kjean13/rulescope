from __future__ import annotations

"""Behavioral overlap analyzer.

Finds rules on the same logsource that share significant detection patterns —
potential merge or alert-cannibalization candidates.

This version uses deterministic exact pruning before exact semantic scoring:
- strict grouping by logsource
- candidate generation only for rules sharing at least one field family
- exact upper-bound pruning before the expensive semantic score
- exact final semantic score for every surviving pair
"""

from collections import defaultdict

from rulescope.models.report import OverlapPair
from rulescope.models.rule import DetectionRule
from rulescope.utils.detection_semantics import (
    build_detection_semantics,
    candidate_rule_pairs_by_logsource,
    event_surface_similarity,
    event_surface_similarity_upper_bound,
)


class OverlapAnalyzer:
    """Detect behavioral overlap between rules on the same logsource."""

    OVERLAP_THRESHOLD = 75
    def analyze(self, rules: list[DetectionRule]) -> list[OverlapPair]:
        by_logsource: dict[str, list[DetectionRule]] = defaultdict(list)
        semantics = {}
        for rule in rules:
            key = rule.logsource_key or "(unknown)"
            by_logsource[key].append(rule)
            semantics[rule.path] = build_detection_semantics(key, rule.detection)

        pairs: list[OverlapPair] = []
        seen: set[tuple[str, str]] = set()

        for key, group in by_logsource.items():
            if len(group) < 2:
                continue
            paths = [rule.path for rule in group]
            rules_by_path = {rule.path: rule for rule in group}
            for left_path, right_path in candidate_rule_pairs_by_logsource(paths, semantics):
                pair_key = (left_path, right_path)
                if pair_key in seen:
                    continue
                seen.add(pair_key)
                left = rules_by_path[left_path]
                right = rules_by_path[right_path]
                if left.detection_fingerprint == right.detection_fingerprint:
                    continue
                upper_bound = event_surface_similarity_upper_bound(semantics[left_path], semantics[right_path])
                if upper_bound < self.OVERLAP_THRESHOLD:
                    continue
                det_sim = event_surface_similarity(semantics[left_path], semantics[right_path])
                if det_sim < self.OVERLAP_THRESHOLD:
                    continue
                field_overlap = self._field_overlap(semantics[left_path].fields, semantics[right_path].fields)
                reason_parts = [f"detection similarity {det_sim}%"]
                if field_overlap >= 0.85:
                    reason_parts.append(f"field overlap {field_overlap:.0%}")
                pairs.append(
                    OverlapPair(
                        left=left.path,
                        right=right.path,
                        similarity=det_sim,
                        reason=f"Same logsource ({key}), {', '.join(reason_parts)}",
                    )
                )

        return pairs

    def _field_overlap(self, left_fields: set[str], right_fields: set[str]) -> float:
        if not left_fields or not right_fields:
            return 0.0
        intersection = left_fields & right_fields
        union = left_fields | right_fields
        return len(intersection) / len(union) if union else 0.0
