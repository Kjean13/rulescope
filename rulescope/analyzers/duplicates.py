from __future__ import annotations

"""Duplicate detection analyzer.

Exact duplicates still use a stable fingerprint hash.
Near-duplicates now use deterministic exact pruning before exact semantic scoring:

- strict grouping by logsource
- candidate generation only for rules sharing at least one field family
- exact upper-bound pruning before the expensive semantic score
- exact final semantic score for every surviving pair
"""

from collections import defaultdict

from rulescope.models.rule import DetectionRule
from rulescope.utils.detection_semantics import (
    build_detection_semantics,
    candidate_rule_pairs_by_logsource,
    event_surface_similarity,
    event_surface_similarity_upper_bound,
)


class DuplicateAnalyzer:
    """Detect exact and near-duplicate rules in a catalog."""

    NEAR_DUP_THRESHOLD = 78

    def analyze(self, rules: list[DetectionRule]) -> tuple[dict[str, list[str]], list[list[str]]]:
        candidates: dict[str, list[str]] = defaultdict(list)
        seen_pairs: set[tuple[str, str]] = set()

        fp_map: dict[str, list[DetectionRule]] = defaultdict(list)
        for rule in rules:
            fp_map[rule.detection_fingerprint].append(rule)

        for group in fp_map.values():
            if len(group) > 1:
                paths = sorted(r.path for r in group)
                for i, left in enumerate(paths):
                    others = [right for j, right in enumerate(paths) if i != j]
                    candidates[left].extend(others)
                    for right in others:
                        seen_pairs.add(tuple(sorted((left, right))))

        semantics = {rule.path: build_detection_semantics(rule.logsource_key, rule.detection) for rule in rules}
        by_logsource: dict[str, list[DetectionRule]] = defaultdict(list)
        for rule in rules:
            by_logsource[rule.logsource_key or "(unknown)"].append(rule)

        for _logsource, group in by_logsource.items():
            if len(group) < 2:
                continue
            paths = [rule.path for rule in group]
            for left_path, right_path in candidate_rule_pairs_by_logsource(paths, semantics):
                pair = (left_path, right_path)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                upper_bound = event_surface_similarity_upper_bound(semantics[left_path], semantics[right_path])
                if upper_bound < self.NEAR_DUP_THRESHOLD:
                    continue
                score = event_surface_similarity(semantics[left_path], semantics[right_path])
                if score >= self.NEAR_DUP_THRESHOLD:
                    candidates[left_path].append(right_path)
                    candidates[right_path].append(left_path)

        adjacency: dict[str, set[str]] = {}
        for key, values in candidates.items():
            uniq = set(values)
            adjacency[key] = uniq
            for value in uniq:
                adjacency.setdefault(value, set()).add(key)

        merged_clusters: list[list[str]] = []
        visited: set[str] = set()
        for node in sorted(adjacency):
            if node in visited:
                continue
            stack = [node]
            component: list[str] = []
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.append(current)
                stack.extend(sorted(adjacency.get(current, set()) - visited))
            if len(component) > 1:
                merged_clusters.append(sorted(component))

        normalized_candidates = {key: sorted(set(values)) for key, values in candidates.items()}
        return normalized_candidates, merged_clusters
