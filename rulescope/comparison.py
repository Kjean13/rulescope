from __future__ import annotations

"""Semantic comparison engine for baseline vs candidate rule packs.

Goes beyond text diff: detects wildcard increases, contains drift,
selector loss, field diversity changes, ATT&CK coverage gaps,
severity inflation, and condition complexity shifts.
"""

from rulescope.models.report import CatalogReport, CompareReport, CompareSummary, RuleDelta, SemanticChange
from rulescope.semantic_diff import attach_semantic_changes
from rulescope.utils.time import utc_now_iso


# ── Declarative semantic classification ─────────────────────────
# Adding a new SEM-* code? Add it to exactly one of these two sets.

#: Semantic change codes that indicate quality regression.
REGRESSION_CODES: frozenset[str] = frozenset({
    "SEM-LOGSOURCE",
    "SEM-BROADER-001",
    "SEM-BROADER-002",
    "SEM-WEAKER-001",
    "SEM-WEAKER-002",
    "SEM-SEVERITY-001",
    "SEM-COVERAGE-001",
    "SEM-MAINT-001",
})

#: Semantic change codes that indicate quality improvement.
IMPROVEMENT_CODES: frozenset[str] = frozenset({
    "SEM-TIGHTER-001",
    "SEM-TIGHTER-002",
    "SEM-STRONGER-001",
    "SEM-STRONGER-002",
    "SEM-COVERAGE-002",
    "SEM-SEVERITY-002",
    "SEM-MAINT-002",
})


def _is_semantic_regression(change: SemanticChange) -> bool:
    """True if a semantic change indicates quality regression."""
    return change.code in REGRESSION_CODES


def _is_semantic_improvement(change: SemanticChange) -> bool:
    """True if a semantic change indicates quality improvement."""
    return change.code in IMPROVEMENT_CODES


def _has_high_severity_regression(changes: list[SemanticChange]) -> bool:
    """True if any semantic change is a high/critical regression."""
    return any(
        change.severity in {"high", "critical"} and _is_semantic_regression(change)
        for change in changes
    )


def compare_catalogs(baseline: CatalogReport, candidate: CatalogReport, regression_threshold: int = 5) -> CompareReport:
    base_rules = {_rule_key(r): r for r in baseline.rules}
    cand_rules = {_rule_key(r): r for r in candidate.rules}

    # Match rules by filename — same file in both packs = same rule
    common_keys = sorted(set(base_rules) & set(cand_rules))
    added = sorted(set(cand_rules) - set(base_rules))
    removed = sorted(set(base_rules) - set(cand_rules))

    deltas: list[RuleDelta] = []
    improvements: list[RuleDelta] = []
    regressions: list[RuleDelta] = []
    semantic_regressions = 0
    semantic_improvements = 0

    for key in common_keys:
        before = base_rules[key]
        after = cand_rules[key]
        delta = RuleDelta(
            path=after.path,
            title=after.title,
            baseline_score=before.scores.overall,
            candidate_score=after.scores.overall,
            delta=after.scores.overall - before.scores.overall,
        )
        attach_semantic_changes(delta, before, after)
        deltas.append(delta)

        # Classify this delta as regression, improvement, or neither
        is_score_regression = delta.delta <= -regression_threshold
        is_score_improvement = delta.delta >= regression_threshold
        has_sem_regression = _has_high_severity_regression(delta.semantic_changes)
        has_sem_improvement = any(_is_semantic_improvement(ch) for ch in delta.semantic_changes)

        if is_score_regression or has_sem_regression:
            regressions.append(delta)
        elif is_score_improvement or has_sem_improvement:
            improvements.append(delta)

        # Count individual semantic changes
        semantic_regressions += sum(1 for ch in delta.semantic_changes if _is_semantic_regression(ch))
        semantic_improvements += sum(1 for ch in delta.semantic_changes if _is_semantic_improvement(ch))

    improvements.sort(key=lambda d: (d.delta, len(d.semantic_changes)), reverse=True)
    regressions.sort(key=lambda d: (d.delta, -len(d.semantic_changes)))

    score_delta = candidate.summary.average_score - baseline.summary.average_score
    duplicate_delta = candidate.summary.duplicate_pairs - baseline.summary.duplicate_pairs
    overlap_delta = candidate.summary.overlap_pairs - baseline.summary.overlap_pairs
    weak_rule_delta = candidate.summary.weak_rules - baseline.summary.weak_rules
    introduced_critical = max(0, candidate.summary.invalid_rules - baseline.summary.invalid_rules)

    verdict = _verdict(
        score_delta,
        introduced_critical,
        duplicate_delta,
        overlap_delta,
        weak_rule_delta,
        semantic_regressions,
    )
    takeaways = _takeaways(
        score_delta,
        duplicate_delta,
        overlap_delta,
        weak_rule_delta,
        len(added),
        len(removed),
        len(regressions),
        introduced_critical,
        semantic_regressions,
        semantic_improvements,
    )

    return CompareReport(
        generated_at=utc_now_iso(),
        summary=CompareSummary(
            baseline_target=baseline.target,
            candidate_target=candidate.target,
            baseline_score=baseline.summary.average_score,
            candidate_score=candidate.summary.average_score,
            score_delta=score_delta,
            duplicate_delta=duplicate_delta,
            overlap_delta=overlap_delta,
            weak_rule_delta=weak_rule_delta,
            added_rules=len(added),
            removed_rules=len(removed),
            changed_rules=len(deltas),
            improved_rules=len(improvements),
            regressed_rules=len(regressions),
            introduced_critical_findings=introduced_critical,
            semantic_regressions=semantic_regressions,
            semantic_improvements=semantic_improvements,
            summary_verdict=verdict,
            key_takeaways=takeaways,
        ),
        strongest_improvements=improvements[:10],
        strongest_regressions=regressions[:10],
    )


def _verdict(
    score_delta: int,
    introduced_critical: int,
    duplicate_delta: int,
    overlap_delta: int,
    weak_rule_delta: int,
    semantic_regressions: int,
) -> str:
    is_regression = (
        introduced_critical > 0
        or score_delta <= -5
        or weak_rule_delta > 0
        or duplicate_delta > 2
        or overlap_delta > 5
        or semantic_regressions > 0
    )
    if is_regression:
        return "Regression"
    is_improved = (
        score_delta >= 5
        and duplicate_delta <= 0
        and overlap_delta <= 0
        and weak_rule_delta <= 0
    )
    if is_improved:
        return "Improved"
    return "Mixed"


def _takeaways(
    score_delta: int,
    duplicate_delta: int,
    overlap_delta: int,
    weak_rule_delta: int,
    added: int,
    removed: int,
    regressions: int,
    introduced_critical: int,
    semantic_regressions: int,
    semantic_improvements: int,
) -> list[str]:
    out: list[str] = []
    out.append(f"Catalog score delta: {score_delta:+d} points.")
    if score_delta <= -5:
        out.append("Quality dropped materially; review the changed rules before merge.")
    elif score_delta >= 5:
        out.append("Catalog quality improved meaningfully over baseline.")

    if semantic_regressions:
        out.append(f"Semantic regressions detected: {semantic_regressions}.")
    if semantic_improvements:
        out.append(f"Semantic improvements detected: {semantic_improvements}.")
    if duplicate_delta:
        out.append(f"Duplicate pairs delta: {duplicate_delta:+d}.")
    if overlap_delta:
        out.append(f"Overlap pairs delta: {overlap_delta:+d}.")
        if overlap_delta > 0:
            out.append("Candidate pack introduces broader semantic overlap that may duplicate alerts.")
    if weak_rule_delta:
        out.append(f"Analytically weak rules delta: {weak_rule_delta:+d}.")
    if added or removed:
        out.append(f"Rules added/removed: +{added} / -{removed}.")
    if regressions:
        out.append(f"Rules with material regressions: {regressions}.")
    if introduced_critical:
        out.append(f"New high/critical findings introduced: {introduced_critical}.")
    return out


def _rule_key(rule) -> str:
    return rule.path.split("/")[-1]
