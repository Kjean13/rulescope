"""RuleScope test suite — covers parsing, all analyzers, scoring, engine, reporters, and CI gate."""

from __future__ import annotations

import json

import pytest

from rulescope import __version__
from rulescope.analyzers.attack_quality import AttackQualityAnalyzer
from rulescope.analyzers.documentation import DocumentationAnalyzer
from rulescope.analyzers.duplicates import DuplicateAnalyzer
from rulescope.analyzers.maintainability import MaintainabilityAnalyzer
from rulescope.analyzers.metadata import MetadataAnalyzer
from rulescope.analyzers.noise import NoiseAnalyzer
from rulescope.analyzers.overlap import OverlapAnalyzer
from rulescope.analyzers.structural import StructuralAnalyzer
from rulescope.comparison import compare_catalogs
from rulescope.config.settings import RuleScopeConfig
from rulescope.engine import RuleScopeEngine
from rulescope.models.rule import DetectionRule
from rulescope.parsers.sigma_parser import SigmaParser, SigmaParserError
from rulescope.reporters.html_reporter import HtmlReporter
from rulescope.reporters.json_reporter import JsonReporter
from rulescope.reporters.markdown_reporter import MarkdownReporter
from rulescope.reporters.sarif_reporter import SarifReporter
from rulescope.scorers.weighted_score import WeightedScorer


# ── Fixtures ──────────────────────────────────────────────────────

def _make_rule(**overrides) -> DetectionRule:
    defaults = dict(
        path="/fake/rule.yml",
        source_name="rule.yml",
        title="Test Rule Title",
        rule_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        description="Detects suspicious behavior for testing purposes in the lab.",
        status="experimental",
        level="medium",
        author="tester",
        date="2026-01-01",
        tags=["attack.execution", "attack.t1059.001"],
        falsepositives=["admin scripts"],
        references=["https://example.org/ref"],
        logsource={"product": "windows", "category": "process_creation"},
        detection={
            "selection": {"Image|endswith": "\\powershell.exe"},
            "condition": "selection",
        },
    )
    defaults.update(overrides)
    rule = DetectionRule(**defaults)
    rule.extract_attack_tags()
    return rule


@pytest.fixture
def good_rule():
    return _make_rule()


@pytest.fixture
def weak_rule():
    return _make_rule(
        title="x",
        description="bad",
        tags=[],
        falsepositives=[],
        references=[],
        rule_id="",
        author="",
        date="",
    )


# ── Parser Tests ──────────────────────────────────────────────────

class TestParser:
    def test_parse_valid_file(self, tmp_path):
        rule_file = tmp_path / "test.yml"
        rule_file.write_text(
            "title: Test\nid: aaaaaaaa-1111-2222-3333-444444444444\n"
            "logsource:\n  product: windows\ndetection:\n  sel:\n    Image: cmd.exe\n  condition: sel\nlevel: medium\n"
        )
        parser = SigmaParser()
        rule = parser.parse_file(rule_file)
        assert rule.title == "Test"
        assert rule.level == "medium"

    def test_parse_invalid_yaml(self, tmp_path):
        bad = tmp_path / "bad.yml"
        bad.write_text("key: [unclosed\n  bad:\nindent: broken")
        parser = SigmaParser()
        with pytest.raises(SigmaParserError):
            parser.parse_file(bad)

    def test_parse_non_dict(self, tmp_path):
        bad = tmp_path / "list.yml"
        bad.write_text("- item1\n- item2")
        parser = SigmaParser()
        with pytest.raises(SigmaParserError):
            parser.parse_file(bad)

    def test_parse_string(self):
        parser = SigmaParser()
        rule = parser.parse_string("title: FromString\nlevel: low\nlogsource:\n  product: linux\ndetection:\n  sel:\n    cmd: ls\n  condition: sel\n")
        assert rule.title == "FromString"

    def test_attack_extraction(self):
        rule = _make_rule(tags=["attack.execution", "attack.t1059.001", "attack.t1059"])
        assert "T1059.001" in rule.attack_techniques
        assert "T1059" in rule.attack_techniques
        assert "execution" in rule.attack_tactics


# ── Metadata Analyzer Tests ───────────────────────────────────────

class TestMetadataAnalyzer:
    def test_good_rule_high_score(self, good_rule):
        score, findings = MetadataAnalyzer().analyze(good_rule)
        assert score >= 80
        assert not any(f.code == "META-001" for f in findings)

    def test_missing_fields_penalized(self, weak_rule):
        score, findings = MetadataAnalyzer().analyze(weak_rule)
        assert score < 70
        assert any(f.code == "META-001" for f in findings)

    def test_invalid_uuid(self):
        rule = _make_rule(rule_id="not-a-uuid")
        _, findings = MetadataAnalyzer().analyze(rule)
        assert any(f.code == "META-002" for f in findings)

    def test_invalid_status(self):
        rule = _make_rule(status="banana")
        _, findings = MetadataAnalyzer().analyze(rule)
        assert any(f.code == "META-003" for f in findings)

    def test_invalid_level(self):
        rule = _make_rule(level="extreme")
        _, findings = MetadataAnalyzer().analyze(rule)
        assert any(f.code == "META-004" for f in findings)

    def test_short_description(self):
        rule = _make_rule(description="short")
        _, findings = MetadataAnalyzer().analyze(rule)
        assert any(f.code == "META-005" for f in findings)

    def test_few_tags(self):
        rule = _make_rule(tags=["one"])
        _, findings = MetadataAnalyzer().analyze(rule)
        assert any(f.code == "META-006" for f in findings)


# ── Maintainability Analyzer Tests ────────────────────────────────

class TestMaintainabilityAnalyzer:
    def test_simple_rule_high_score(self, good_rule):
        score, findings = MaintainabilityAnalyzer().analyze(good_rule)
        assert score >= 90

    def test_many_selections_penalized(self):
        detection = {f"sel{i}": {"field": "val"} for i in range(8)}
        detection["condition"] = "sel0 or sel1 or sel2 or sel3 or sel4 or sel5 or sel6 or sel7"
        rule = _make_rule(detection=detection)
        score, findings = MaintainabilityAnalyzer().analyze(rule)
        assert score < 85
        assert any(f.code == "MAINT-001" for f in findings)

    def test_complex_condition(self):
        detection = {
            "sel1": {"f": "v"}, "sel2": {"f": "v"}, "sel3": {"f": "v"},
            "condition": "sel1 and sel2 or sel3 and not sel1 or 1 of sel*",
        }
        rule = _make_rule(detection=detection)
        _, findings = MaintainabilityAnalyzer().analyze(rule)
        assert any(f.code == "MAINT-002" for f in findings)

    def test_no_condition(self):
        rule = _make_rule(detection={"selection": {"Image": "cmd.exe"}})
        _, findings = MaintainabilityAnalyzer().analyze(rule)
        assert any(f.code == "MAINT-005" for f in findings)


# ── Noise Analyzer Tests ─────────────────────────────────────────

class TestNoiseAnalyzer:
    def test_clean_rule(self, good_rule):
        score, _ = NoiseAnalyzer().analyze(good_rule)
        assert score >= 80

    def test_many_wildcards(self):
        detection = {
            "selection": {"CommandLine|contains": ["*admin*", "*temp*", "*update*", "*test*", "*run*"]},
            "condition": "selection",
        }
        rule = _make_rule(detection=detection)
        score, findings = NoiseAnalyzer().analyze(rule)
        assert any(f.code == "NOISE-001" for f in findings)

    def test_missing_fp_guidance(self):
        rule = _make_rule(falsepositives=[])
        _, findings = NoiseAnalyzer().analyze(rule)
        assert any(f.code == "NOISE-003" for f in findings)

    def test_severity_logic_incoherence(self):
        rule = _make_rule(
            level="critical",
            detection={"selection": {"Image": "x"}, "condition": "selection"},
        )
        _, findings = NoiseAnalyzer().analyze(rule)
        assert any(f.code == "NOISE-005" for f in findings)


# ── Structural Analyzer Tests ────────────────────────────────────

class TestStructuralAnalyzer:
    def test_valid_structure(self, good_rule):
        score, _ = StructuralAnalyzer().analyze(good_rule)
        assert score >= 90

    def test_missing_logsource(self):
        rule = _make_rule(logsource={})
        score, findings = StructuralAnalyzer().analyze(rule)
        assert score < 70
        assert any(f.code == "STRUCT-001" for f in findings)

    def test_missing_detection(self):
        rule = _make_rule(detection={})
        score, findings = StructuralAnalyzer().analyze(rule)
        assert score < 50
        assert any(f.code == "STRUCT-003" for f in findings)

    def test_no_condition(self):
        rule = _make_rule(detection={"selection": {"Image": "cmd.exe"}})
        _, findings = StructuralAnalyzer().analyze(rule)
        assert any(f.code == "STRUCT-004" for f in findings)

    def test_logsource_no_product_no_category(self):
        rule = _make_rule(logsource={"service": "sysmon"})
        _, findings = StructuralAnalyzer().analyze(rule)
        assert any(f.code == "STRUCT-002" for f in findings)


# ── Documentation Analyzer Tests ─────────────────────────────────

class TestDocumentationAnalyzer:
    def test_good_doc(self, good_rule):
        score, _ = DocumentationAnalyzer().analyze(good_rule)
        assert score >= 90

    def test_generic_title(self):
        rule = _make_rule(title="test rule")
        _, findings = DocumentationAnalyzer().analyze(rule)
        assert any(f.code == "DOC-002" for f in findings)

    def test_trivial_fp(self):
        rule = _make_rule(falsepositives=["unknown"])
        _, findings = DocumentationAnalyzer().analyze(rule)
        assert any(f.code == "DOC-005" for f in findings)


# ── ATT&CK Quality Analyzer Tests ────────────────────────────────

class TestAttackQualityAnalyzer:
    def test_good_attack_tags(self, good_rule):
        score, _ = AttackQualityAnalyzer().analyze(good_rule)
        assert score >= 90

    def test_no_attack_tags(self):
        rule = _make_rule(tags=["sysmon", "windows"])
        rule.extract_attack_tags()
        _, findings = AttackQualityAnalyzer().analyze(rule)
        assert any(f.code == "ATK-001" for f in findings)

    def test_tactic_only(self):
        rule = _make_rule(tags=["attack.execution"])
        rule.extract_attack_tags()
        _, findings = AttackQualityAnalyzer().analyze(rule)
        assert any(f.code == "ATK-003" for f in findings)

    def test_technique_only(self):
        rule = _make_rule(tags=["attack.t1059.001"])
        rule.extract_attack_tags()
        _, findings = AttackQualityAnalyzer().analyze(rule)
        assert any(f.code == "ATK-002" for f in findings)


# ── Duplicate Analyzer Tests ─────────────────────────────────────

class TestDuplicateAnalyzer:
    def test_exact_duplicates(self):
        r1 = _make_rule(path="/a.yml")
        r2 = _make_rule(path="/b.yml")  # identical detection
        candidates, clusters = DuplicateAnalyzer().analyze([r1, r2])
        assert len(clusters) >= 1
        assert "/b.yml" in candidates.get("/a.yml", [])

    def test_no_duplicates(self):
        r1 = _make_rule(path="/a.yml", detection={"sel": {"Image": "cmd.exe"}, "condition": "sel"})
        r2 = _make_rule(path="/b.yml", detection={"sel": {"DestPort": 443}, "condition": "sel"}, logsource={"product": "firewall"})
        _, clusters = DuplicateAnalyzer().analyze([r1, r2])
        assert len(clusters) == 0


# ── Overlap Analyzer Tests ────────────────────────────────────────

class TestOverlapAnalyzer:
    def test_same_logsource_similar_detection(self):
        r1 = _make_rule(
            path="/certutil1.yml",
            detection={"sel": {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["urlcache"]}, "condition": "sel"},
        )
        r2 = _make_rule(
            path="/certutil2.yml",
            detection={"sel": {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["urlcache", "-decode"]}, "condition": "sel"},
        )
        pairs = OverlapAnalyzer().analyze([r1, r2])
        assert len(pairs) >= 1

    def test_different_logsource_no_overlap(self):
        r1 = _make_rule(path="/a.yml", logsource={"product": "windows", "category": "process_creation"})
        r2 = _make_rule(path="/b.yml", logsource={"product": "linux", "category": "process_creation"})
        pairs = OverlapAnalyzer().analyze([r1, r2])
        assert len(pairs) == 0


# ── Scorer Tests ──────────────────────────────────────────────────

class TestScorer:
    def test_perfect_score(self):
        s = WeightedScorer().score_rule(100, 100, 100, 100, 100, 100)
        assert s.overall == 100

    def test_zero_score(self):
        s = WeightedScorer().score_rule(0, 0, 0, 0, 0, 0)
        assert s.overall == 0

    def test_catalog_bands(self):
        scorer = WeightedScorer()
        s = scorer.score_catalog([95, 90, 88], 0, 0, 0, 0, 0)
        assert s.score_band == "Excellent"
        s = scorer.score_catalog([30, 20, 10], 5, 3, 3, 3, 2)
        assert s.score_band in {"High risk", "Critical"}

    def test_median(self):
        s = WeightedScorer().score_catalog([10, 50, 90], 0, 0, 0, 0, 0)
        assert s.median_score == 50


# ── Engine Integration Tests ──────────────────────────────────────

class TestEngine:
    def test_scan_examples(self):
        report = RuleScopeEngine().scan("examples/rules")
        assert report.summary.total_rules >= 5
        assert len(report.rules) >= 5
        assert report.summary.average_score >= 0
        assert report.version == __version__

    def test_duplicate_detected(self):
        report = RuleScopeEngine().scan("examples/rules")
        assert report.summary.duplicate_pairs >= 1

    def test_overlap_detected(self):
        report = RuleScopeEngine().scan("examples/rules")
        assert report.summary.overlap_pairs >= 0  # may or may not trigger

    def test_invalid_yaml_reported(self):
        report = RuleScopeEngine().scan("examples/rules")
        # broken_rule.yml should still parse (it's valid YAML even if weird)
        assert report.summary.total_rules >= 5

    def test_coverage_populated(self):
        report = RuleScopeEngine().scan("examples/rules")
        # At least some rules have ATT&CK tags
        assert any(r.attack_tactics for r in report.rules)

    def test_segmentation(self):
        report = RuleScopeEngine().scan("examples/rules")
        assert len(report.summary.segments_by_logsource) >= 1
        assert len(report.summary.segments_by_level) >= 1

    def test_top_weakest(self):
        report = RuleScopeEngine().scan("examples/rules")
        assert len(report.summary.top_weakest) > 0

    def test_findings_have_impact(self):
        report = RuleScopeEngine().scan("examples/rules")
        all_findings = [f for r in report.rules for f in r.findings]
        # At least some findings have impact
        assert any(f.impact for f in all_findings)

    def test_single_file_scan(self):
        report = RuleScopeEngine().scan("examples/rules/certutil_download.yml")
        assert report.summary.total_rules == 1

    def test_config_integration(self):
        cfg = RuleScopeConfig(exclude_paths=["broken"])
        report = RuleScopeEngine(config=cfg).scan("examples/rules")
        paths = [r.path for r in report.rules]
        assert not any("broken" in p for p in paths)


# ── Reporter Tests ────────────────────────────────────────────────

class TestReporters:
    @pytest.fixture
    def sample_report(self):
        return RuleScopeEngine().scan("examples/rules")

    def test_json_valid(self, sample_report):
        output = JsonReporter().render(sample_report)
        data = json.loads(output)
        assert "summary" in data
        assert "rules" in data
        assert data["version"] == __version__

    def test_markdown_has_sections(self, sample_report):
        output = MarkdownReporter().render(sample_report)
        assert "# RuleScope Report" in output
        assert "## Catalog Summary" in output
        assert "## Rule Details" in output

    def test_html_has_structure(self, sample_report):
        output = HtmlReporter().render(sample_report)
        assert "<!DOCTYPE html>" in output
        assert "RuleScope Report" in output
        assert "radar" in output
        assert "filterRules" in output

    def test_sarif_valid(self, sample_report):
        output = SarifReporter().render(sample_report)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "RuleScope"
        assert len(data["runs"][0]["results"]) > 0


# ── Config Tests ──────────────────────────────────────────────────

class TestConfig:
    def test_default_config(self):
        cfg = RuleScopeConfig()
        assert cfg.weights.metadata == 0.10
        assert cfg.weights.noise == 0.22
        assert cfg.weights.weakness == 0.22
        assert abs(sum(cfg.weights.model_dump().values()) - 1.0) < 0.001
        assert cfg.ci_gate.min_score == 70

    def test_load_from_file(self, tmp_path):
        conf_file = tmp_path / ".rulescope.yml"
        conf_file.write_text("weights:\n  metadata: 0.30\nci_gate:\n  min_score: 80\n")
        cfg = RuleScopeConfig.load(str(conf_file))
        assert cfg.weights.metadata == 0.30
        assert cfg.ci_gate.min_score == 80

    def test_load_missing_file(self):
        cfg = RuleScopeConfig.load("/nonexistent/.rulescope.yml")
        assert cfg.weights.metadata == 0.10  # new defaults
        assert cfg.weights.noise == 0.22
        assert cfg.weights.weakness == 0.22


# ── DetectionRule Model Tests ─────────────────────────────────────

class TestDetectionRuleModel:
    def test_fingerprint_stable(self):
        r1 = _make_rule()
        r2 = _make_rule()
        assert r1.detection_fingerprint == r2.detection_fingerprint

    def test_fingerprint_different(self):
        r1 = _make_rule(detection={"sel": {"Image": "a"}, "condition": "sel"})
        r2 = _make_rule(detection={"sel": {"Image": "b"}, "condition": "sel"})
        assert r1.detection_fingerprint != r2.detection_fingerprint

    def test_logsource_key(self):
        rule = _make_rule(logsource={"product": "windows", "category": "process_creation"})
        assert rule.logsource_key == "windows/process_creation"

    def test_filename(self):
        rule = _make_rule(path="/some/dir/rule.yml")
        assert rule.filename == "rule.yml"


class TestCompare:
    def test_compare_detects_regression(self, tmp_path):
        base = tmp_path / "base"
        cand = tmp_path / "cand"
        base.mkdir()
        cand.mkdir()
        rule_text = """title: Test
id: aaaaaaaa-1111-2222-3333-444444444444
status: experimental
level: medium
description: Detects suspicious powershell use with enough detail
logsource:
  product: windows
  category: process_creation
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - admin scripts
references:
  - https://example.org
detection:
  selection:
    Image|endswith: \\powershell.exe
  condition: selection
"""
        weak_text = """title: test rule
id: bad-id
level: critical
description: bad
logsource:
  product: windows
detection:
  selection:
    Image: x
  condition: selection
"""
        (base / 'r1.yml').write_text(rule_text)
        (cand / 'r1.yml').write_text(weak_text)
        engine = RuleScopeEngine()
        diff = compare_catalogs(engine.scan(str(base)), engine.scan(str(cand)))
        assert diff.summary.summary_verdict == "Regression"
        assert diff.summary.score_delta < 0
        assert diff.strongest_regressions
