from __future__ import annotations

from rulescope.models.report import RuleDelta, RuleReport, RuleScore, SemanticProfile
from rulescope.semantic_diff import attach_semantic_changes, diff_rule_semantics


def _rule(title: str, profile: SemanticProfile, level: str = "medium", overall: int = 80) -> RuleReport:
    return RuleReport(
        path=f"rules/{title}.yml",
        source_name=f"{title}.yml",
        title=title,
        level=level,
        scores=RuleScore(
            overall=overall,
            metadata=80,
            maintainability=80,
            noise=80,
            structural=80,
            documentation=80,
            attack_quality=80,
            weakness=80,
        ),
        semantic_profile=profile,
        findings=[],
        duplicate_candidates=[],
        overlap_candidates=[],
        attack_techniques=["T1059"] if profile.technique_count else [],
        attack_tactics=["execution"] if profile.technique_count else [],
    )


def test_semantic_diff_surfaces_broader_rule() -> None:
    baseline = _rule(
        "baseline",
        SemanticProfile(
            selector_count=2,
            field_count=3,
            wildcard_count=0,
            contains_modifiers=0,
            exact_modifiers=2,
            technique_count=1,
            condition_complexity=1,
            logsource_key="windows:process_creation",
        ),
        level="medium",
        overall=85,
    )
    candidate = _rule(
        "candidate",
        SemanticProfile(
            selector_count=1,
            field_count=1,
            wildcard_count=3,
            contains_modifiers=2,
            exact_modifiers=0,
            technique_count=0,
            condition_complexity=5,
            logsource_key="windows:process_creation",
        ),
        level="high",
        overall=75,
    )
    codes = {change.code for change in diff_rule_semantics(baseline, candidate)}
    assert {"SEM-BROADER-001", "SEM-BROADER-002", "SEM-WEAKER-001", "SEM-WEAKER-002", "SEM-COVERAGE-001", "SEM-SEVERITY-001", "SEM-MAINT-001"}.issubset(codes)


def test_semantic_diff_surfaces_tighter_rule_and_attach() -> None:
    baseline = _rule(
        "baseline",
        SemanticProfile(
            selector_count=1,
            field_count=1,
            wildcard_count=3,
            contains_modifiers=1,
            exact_modifiers=0,
            technique_count=0,
            condition_complexity=6,
            logsource_key="windows:process_creation",
        ),
        level="high",
        overall=70,
    )
    candidate = _rule(
        "candidate",
        SemanticProfile(
            selector_count=3,
            field_count=4,
            wildcard_count=0,
            contains_modifiers=0,
            exact_modifiers=3,
            technique_count=2,
            condition_complexity=2,
            logsource_key="windows:process_creation",
        ),
        level="medium",
        overall=90,
    )
    delta = RuleDelta(path="rules/candidate.yml", title="candidate", baseline_score=70, candidate_score=90, delta=20)
    attach_semantic_changes(delta, baseline, candidate)
    codes = {change.code for change in delta.semantic_changes}
    assert {"SEM-TIGHTER-001", "SEM-TIGHTER-002", "SEM-STRONGER-001", "SEM-STRONGER-002", "SEM-COVERAGE-002", "SEM-SEVERITY-002", "SEM-MAINT-002"}.issubset(codes)
