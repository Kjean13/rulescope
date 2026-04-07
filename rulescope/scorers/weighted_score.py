from __future__ import annotations

"""Weighted scoring engine — aggregates 7 quality pillars into one score.

Weights are configurable via .rulescope.yml. The catalog score
applies penalties for duplicates, overlap, noise, and invalid rules.
Score bands: Excellent (90+), Good (75+), Needs work (60+),
High risk (40+), Critical (<40).
"""

from statistics import median

from rulescope.models.report import CatalogSummary, RuleScore, SegmentScore


class WeightedScorer:
    """Compute weighted rule and catalog scores."""

    DEFAULT_WEIGHTS = {
        "metadata":        0.10,  # YAML hygiene — necessary but not sufficient
        "maintainability": 0.10,  # code quality — same
        "structural":      0.08,  # schema validity — always near-perfect on maintained catalogs
        "documentation":   0.10,  # FP guidance, description quality
        "attack_quality":  0.18,  # ATT&CK mapping precision — operational impact
        "noise":           0.22,  # FP risk — directly impacts SOC workload
        "weakness":        0.22,  # detection selectivity — core quality signal
    }

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or self.DEFAULT_WEIGHTS

    def score_rule(
        self,
        metadata: int,
        maintainability: int,
        noise: int,
        structural: int,
        documentation: int = 100,
        attack_quality: int = 100,
        weakness: int | None = None,
    ) -> RuleScore:
        if weakness is None:
            weakness = 0 if all(v == 0 for v in [metadata, maintainability, noise, structural, documentation, attack_quality]) else 100
        w = self.weights
        overall = round(
            (metadata * w["metadata"])
            + (maintainability * w["maintainability"])
            + (noise * w["noise"])
            + (structural * w["structural"])
            + (documentation * w["documentation"])
            + (attack_quality * w["attack_quality"])
            + (weakness * w.get("weakness", 0.0))
        )
        return RuleScore(
            metadata=metadata,
            maintainability=maintainability,
            noise=noise,
            structural=structural,
            documentation=documentation,
            attack_quality=attack_quality,
            weakness=weakness,
            overall=max(0, min(100, overall)),
        )

    def score_catalog(
        self,
        rule_scores: list[int],
        duplicate_pairs: int,
        overlap_pairs: int,
        weak_metadata_rules: int,
        high_noise_rules: int,
        invalid_rules: int,
        weak_rules: int = 0,
    ) -> CatalogSummary:
        raw_average = round(sum(rule_scores) / len(rule_scores)) if rule_scores else 0
        med = int(median(rule_scores)) if rule_scores else 0
        total = max(1, len(rule_scores))
        # Relative penalties (% of catalog) so large catalogs are judged fairly
        dup_pct   = duplicate_pairs / total * 100
        ovl_pct   = min(overlap_pairs, total) / total * 100
        noise_pct = high_noise_rules / total * 100
        weak_pct  = weak_rules / total * 100
        wmeta_pct = weak_metadata_rules / total * 100
        inv_pct   = invalid_rules / total * 100
        penalty = (
            min(15, round(dup_pct * 0.5))    # duplicates: up to 15pts
            + min(8,  round(ovl_pct * 0.02)) # overlaps: low weight, often intentional
            + min(6,  round(noise_pct * 2))  # high-noise rules: moderate
            + min(10, round(weak_pct * 0.3)) # weak rules: up to 10pts
            + min(6,  round(wmeta_pct * 1))  # weak metadata: up to 6pts
            + min(10, round(inv_pct * 2))    # invalid rules: heaviest weight
        )
        health_score = max(0, raw_average - penalty)
        band = self._band(health_score)
        return CatalogSummary(
            total_rules=len(rule_scores),
            average_score=raw_average,
            raw_average_score=raw_average,
            catalog_health_score=health_score,
            median_score=med,
            duplicate_pairs=duplicate_pairs,
            overlap_pairs=overlap_pairs,
            high_noise_rules=high_noise_rules,
            weak_metadata_rules=weak_metadata_rules,
            invalid_rules=invalid_rules,
            weak_rules=weak_rules,
            score_band=band,
        )

    def compute_segments(self, reports: list, key_fn) -> list[SegmentScore]:
        groups: dict[str, list[int]] = {}
        for report in reports:
            key = key_fn(report) or "(unknown)"
            groups.setdefault(key, []).append(report.scores.overall)
        segments = []
        for seg, scores in sorted(groups.items()):
            segments.append(SegmentScore(
                segment=seg,
                rule_count=len(scores),
                average_score=round(sum(scores) / len(scores)) if scores else 0,
                worst_score=min(scores) if scores else 0,
            ))
        return segments

    def _band(self, score: int) -> str:
        if score >= 90:
            return "Excellent"
        if score >= 75:
            return "Good"
        if score >= 60:
            return "Needs work"
        if score >= 40:
            return "High risk"
        return "Critical"
