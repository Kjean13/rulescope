from __future__ import annotations

from pathlib import Path

from rulescope.explain import RuleExplainer
from rulescope.models.finding import Finding
from rulescope.models.report import RuleReport, RuleScore, SemanticProfile
from rulescope.utils import find_rule_files, flatten_structure, normalize_text


def _rule_report(**overrides) -> RuleReport:
    base = dict(
        path="rules/test_rule.yml",
        source_name="test_rule.yml",
        title="Test Rule",
        level="medium",
        scores=RuleScore(
            overall=76,
            metadata=70,
            maintainability=80,
            noise=65,
            structural=90,
            documentation=72,
            attack_quality=60,
            weakness=58,
        ),
        findings=[
            Finding(code="NOISE-003", severity="medium", category="noise", message="False positive guidance is missing."),
            Finding(code="META-005", severity="medium", category="metadata", message="Description is too short."),
            Finding(code="ATK-001", severity="medium", category="attack", message="Rule has no ATT&CK tags."),
            Finding(code="WEAK-001", severity="medium", category="weakness", message="Rule relies on a single selector block."),
        ],
        semantic_profile=SemanticProfile(
            selector_count=1,
            field_count=1,
            wildcard_count=3,
            contains_modifiers=1,
            exact_modifiers=0,
            technique_count=0,
            condition_complexity=2,
            logsource_key="windows:process_creation",
        ),
        duplicate_candidates=["dup-1"],
        overlap_candidates=["overlap-1", "overlap-2"],
        attack_techniques=[],
        attack_tactics=[],
    )
    base.update(overrides)
    return RuleReport(**base)


def test_explainer_outputs_actionable_sections() -> None:
    report = _rule_report()
    text = RuleExplainer().explain(report)
    assert "Severity focus: MEDIUM" in text
    assert "Review focus:" in text
    assert "Semantic profile:" in text
    assert "Immediate next steps:" in text
    assert "Document 2-3 concrete benign scenarios" in text
    assert "Replace at least 2 wildcard-heavy values" in text
    assert "Add at least one ATT&CK tactic and one technique tag" in text


def test_explainer_handles_clean_rule() -> None:
    report = _rule_report(
        findings=[],
        duplicate_candidates=[],
        overlap_candidates=[],
        attack_techniques=["T1059"],
        attack_tactics=["execution"],
        semantic_profile=SemanticProfile(
            selector_count=2,
            field_count=3,
            wildcard_count=0,
            contains_modifiers=0,
            exact_modifiers=2,
            technique_count=1,
            condition_complexity=1,
            logsource_key="linux:process_creation",
        ),
    )
    text = RuleExplainer().explain(report)
    assert "Severity focus: NONE" in text
    assert "No findings." in text
    assert "Next hardening steps:" in text or "Immediate next steps:" in text
    assert "production-ready" in text


def test_find_rule_files_supports_plain_exclude_pattern(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    (root / "ignore_me").mkdir(parents=True)
    (root / "keep").mkdir()
    (root / "ignore_me" / "a.yml").write_text("title: A\nlogsource: {product: windows}\ndetection: {sel: {Image: a}, condition: sel}\n")
    (root / "keep" / "b.yaml").write_text("title: B\nlogsource: {product: linux}\ndetection: {sel: {cmd: b}, condition: sel}\n")
    files = find_rule_files(str(root), exclude_patterns=["ignore_me"])
    assert [p.name for p in files] == ["b.yaml"]


def test_text_helpers_are_stable() -> None:
    assert normalize_text("  A   Test  Value ") == "a test value"
    assert flatten_structure({"b": 1, "a": [2, 3]}).startswith('{"a"')


def test_finding_registry_covers_all_emitted_codes() -> None:
    """Every finding code emitted by analyzers and engine must have a
    remediation suggestion in CODE_SUGGESTIONS. This prevents orphan codes
    from silently missing explain output."""
    import re
    from pathlib import Path
    from rulescope.explain import CODE_SUGGESTIONS

    # Collect all code="XXX-NNN" literals from analyzer and engine sources
    emitted: set[str] = set()
    source_dirs = [
        Path("rulescope/analyzers"),
        Path("rulescope"),
    ]
    for source_dir in source_dirs:
        for py_file in source_dir.glob("*.py"):
            text = py_file.read_text()
            emitted.update(re.findall(r'code="([A-Z]+-\d+)"', text))

    # CUSTOM-001 is an example in the docstring, not a real emitted code
    emitted.discard("CUSTOM-001")

    missing = emitted - set(CODE_SUGGESTIONS.keys())
    assert not missing, f"Finding codes emitted but missing from CODE_SUGGESTIONS: {sorted(missing)}"


def test_severity_rank_covers_all_severity_values() -> None:
    """SEVERITY_RANK must have an entry for every valid Severity literal."""
    from rulescope.models.finding import SEVERITY_RANK
    expected = {"critical", "high", "medium", "low", "info"}
    assert set(SEVERITY_RANK.keys()) == expected
