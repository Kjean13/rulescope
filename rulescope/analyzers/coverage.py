from __future__ import annotations

"""ATT&CK coverage statistics.

Aggregates technique-level coverage per tactic, flags fragile areas
(single-rule coverage) and concentration risk.
"""

from collections import defaultdict

from rulescope.models.report import CoverageStat, RuleReport


class CoverageAnalyzer:
    """Compute ATT&CK coverage statistics and qualitative coverage hints."""

    def analyze(self, rule_reports: list[RuleReport]) -> list[CoverageStat]:
        tactic_data: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
        for rr in rule_reports:
            quality = rr.scores.overall
            for tactic in rr.attack_tactics:
                if rr.attack_techniques:
                    for tech in rr.attack_techniques:
                        tactic_data[tactic][tech].append(quality)
                else:
                    tactic_data[tactic]["(unmapped)"] += [quality]

        stats: list[CoverageStat] = []
        for tactic in sorted(tactic_data):
            techs = tactic_data[tactic]
            all_scores = [s for scores in techs.values() for s in scores]
            avg_q = round(sum(all_scores) / len(all_scores)) if all_scores else 0
            quality_band = self._band(avg_q)
            non_unmapped = [t for t in techs if t != "(unmapped)"]
            tech_rule_counts = [len(scores) for tech, scores in techs.items() if tech != "(unmapped)"]
            concentration_risk = any(count >= 3 for count in tech_rule_counts) and len(non_unmapped) <= 2
            fragile = avg_q < 65 or (len(non_unmapped) <= 1 and len(all_scores) <= 2)
            stats.append(
                CoverageStat(
                    tactic=tactic,
                    technique_count=len(non_unmapped),
                    rule_count=len(all_scores),
                    avg_quality=avg_q,
                    techniques=sorted(techs.keys()),
                    quality_band=quality_band,
                    fragile=fragile,
                    concentration_risk=concentration_risk,
                )
            )
        return stats

    def _band(self, score: int) -> str:
        if score >= 85:
            return "strong"
        if score >= 65:
            return "moderate"
        return "fragile"
