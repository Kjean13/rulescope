from __future__ import annotations

"""Semantic diff engine for rule-level comparison.

Compares SemanticProfiles between baseline and candidate versions
of a rule. Detects 9 types of semantic changes: broader matching,
tighter matching, field loss/gain, selector changes, ATT&CK drift,
severity inflation, and condition complexity shifts.
"""

from rulescope.models.report import RuleDelta, RuleReport, SemanticChange


LEVEL_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def diff_rule_semantics(baseline: RuleReport, candidate: RuleReport) -> list[SemanticChange]:
    b = baseline.semantic_profile
    c = candidate.semantic_profile
    changes: list[SemanticChange] = []

    if c.logsource_key and b.logsource_key and c.logsource_key != b.logsource_key:
        changes.append(SemanticChange(
            code="SEM-LOGSOURCE",
            severity="high",
            summary="Logsource changed between baseline and candidate.",
            detail=f"{b.logsource_key} -> {c.logsource_key}",
        ))

    if c.wildcard_count - b.wildcard_count >= 2:
        changes.append(SemanticChange(
            code="SEM-BROADER-001",
            severity="high",
            summary="Rule became broader due to additional wildcard matching.",
            detail=f"wildcards {b.wildcard_count} -> {c.wildcard_count}",
        ))
    elif b.wildcard_count - c.wildcard_count >= 2:
        changes.append(SemanticChange(
            code="SEM-TIGHTER-001",
            severity="medium",
            summary="Rule became more selective by reducing wildcard usage.",
            detail=f"wildcards {b.wildcard_count} -> {c.wildcard_count}",
        ))

    if c.contains_modifiers > b.contains_modifiers:
        changes.append(SemanticChange(
            code="SEM-BROADER-002",
            severity="medium",
            summary="Candidate relies more on contains-style matching.",
            detail=f"contains modifiers {b.contains_modifiers} -> {c.contains_modifiers}",
        ))
    elif c.exact_modifiers > b.exact_modifiers:
        changes.append(SemanticChange(
            code="SEM-TIGHTER-002",
            severity="low",
            summary="Candidate adds more exact or bounded modifiers.",
            detail=f"exact-like modifiers {b.exact_modifiers} -> {c.exact_modifiers}",
        ))

    if b.field_count - c.field_count >= 1:
        changes.append(SemanticChange(
            code="SEM-WEAKER-001",
            severity="medium",
            summary="Candidate lost field diversity and may carry less context.",
            detail=f"fields {b.field_count} -> {c.field_count}",
        ))
    elif c.field_count - b.field_count >= 1:
        changes.append(SemanticChange(
            code="SEM-STRONGER-001",
            severity="low",
            summary="Candidate gained field diversity and investigative context.",
            detail=f"fields {b.field_count} -> {c.field_count}",
        ))

    if b.selector_count - c.selector_count >= 1:
        changes.append(SemanticChange(
            code="SEM-WEAKER-002",
            severity="medium",
            summary="Candidate has fewer selector blocks, reducing discrimination.",
            detail=f"selectors {b.selector_count} -> {c.selector_count}",
        ))
    elif c.selector_count - b.selector_count >= 1:
        changes.append(SemanticChange(
            code="SEM-STRONGER-002",
            severity="low",
            summary="Candidate adds selector blocks that may improve confidence.",
            detail=f"selectors {b.selector_count} -> {c.selector_count}",
        ))

    if c.technique_count < b.technique_count and b.technique_count > 0:
        changes.append(SemanticChange(
            code="SEM-COVERAGE-001",
            severity="medium",
            summary="Candidate exposes less ATT&CK technique coverage metadata.",
            detail=f"techniques {b.technique_count} -> {c.technique_count}",
        ))
    elif c.technique_count > b.technique_count:
        changes.append(SemanticChange(
            code="SEM-COVERAGE-002",
            severity="low",
            summary="Candidate increases ATT&CK technique coverage metadata.",
            detail=f"techniques {b.technique_count} -> {c.technique_count}",
        ))

    b_level = LEVEL_RANK.get((baseline.level or "").lower(), 0)
    c_level = LEVEL_RANK.get((candidate.level or "").lower(), 0)
    if c_level > b_level and candidate.scores.overall <= baseline.scores.overall:
        changes.append(SemanticChange(
            code="SEM-SEVERITY-001",
            severity="high",
            summary="Severity increased without stronger rule quality.",
            detail=f"level {baseline.level or '(none)'} -> {candidate.level or '(none)'} while score {baseline.scores.overall} -> {candidate.scores.overall}",
        ))
    elif c_level < b_level and candidate.scores.overall >= baseline.scores.overall:
        changes.append(SemanticChange(
            code="SEM-SEVERITY-002",
            severity="low",
            summary="Severity was reduced while quality stayed stable or improved.",
            detail=f"level {baseline.level or '(none)'} -> {candidate.level or '(none)'}",
        ))

    if c.condition_complexity - b.condition_complexity >= 3:
        changes.append(SemanticChange(
            code="SEM-MAINT-001",
            severity="medium",
            summary="Condition logic became materially more complex.",
            detail=f"condition complexity {b.condition_complexity} -> {c.condition_complexity}",
        ))
    elif b.condition_complexity - c.condition_complexity >= 3:
        changes.append(SemanticChange(
            code="SEM-MAINT-002",
            severity="low",
            summary="Condition logic became simpler and easier to review.",
            detail=f"condition complexity {b.condition_complexity} -> {c.condition_complexity}",
        ))

    return changes


def attach_semantic_changes(delta: RuleDelta, baseline: RuleReport, candidate: RuleReport) -> RuleDelta:
    delta.semantic_changes = diff_rule_semantics(baseline, candidate)
    return delta
