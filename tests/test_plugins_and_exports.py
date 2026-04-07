"""Tests for plugin system, navigator export, and reporter validation."""
from __future__ import annotations

import json

import pytest

from rulescope import __version__
from rulescope.analyzers.base import RuleAnalyzer
from rulescope.engine import RuleScopeEngine
from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule
from rulescope.reporters.navigator_export import export_navigator_layer


# ── Plugin system ────────────────────────────────────────────────

class DummyAnalyzer:
    """A custom analyzer that always adds a finding."""
    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        return 80, [Finding(
            code="PLUGIN-001",
            severity="info",
            category="custom",
            message="Plugin test finding.",
        )]


class TestPluginSystem:
    def test_register_analyzer(self):
        engine = RuleScopeEngine()
        analyzer = DummyAnalyzer()
        engine.register_analyzer("test_plugin", analyzer)
        assert "test_plugin" in engine._plugin_analyzers

    def test_plugin_findings_appear_in_scan(self, tmp_path):
        rule_file = tmp_path / "test.yml"
        rule_file.write_text("""
title: Plugin test rule
id: 12345678-1234-1234-1234-123456789abc
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: evil
  condition: selection
level: medium
status: test
description: A test rule for plugin validation.
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Admin scripts
author: test
date: 2024-01-01
references:
  - https://example.com
""")
        engine = RuleScopeEngine()
        engine.register_analyzer("test_plugin", DummyAnalyzer())
        report = engine.scan(str(tmp_path))
        assert len(report.rules) == 1
        codes = [f.code for f in report.rules[0].findings]
        assert "PLUGIN-001" in codes

    def test_protocol_check(self):
        assert isinstance(DummyAnalyzer(), RuleAnalyzer)

    def test_invalid_analyzer_rejected(self):
        engine = RuleScopeEngine()
        with pytest.raises(TypeError):
            engine.register_analyzer("bad", "not an analyzer")


# ── Navigator export ─────────────────────────────────────────────

class TestNavigatorExport:
    def test_basic_export(self, tmp_path):
        rule_file = tmp_path / "test.yml"
        rule_file.write_text("""
title: Navigator test
id: 12345678-1234-1234-1234-123456789abc
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: evil
  condition: selection
level: medium
status: test
description: Testing navigator export functionality.
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Admin scripts
author: test
date: 2024-01-01
references:
  - https://example.com
""")
        engine = RuleScopeEngine()
        report = engine.scan(str(tmp_path))
        layer_json = export_navigator_layer(report)
        layer = json.loads(layer_json)
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert len(layer["techniques"]) >= 1
        tech_ids = [t["techniqueID"] for t in layer["techniques"]]
        assert "T1059.001" in tech_ids

    def test_empty_catalog_export(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        engine = RuleScopeEngine()
        report = engine.scan(str(empty_dir))
        layer_json = export_navigator_layer(report)
        layer = json.loads(layer_json)
        assert layer["techniques"] == []

    def test_layer_metadata(self, tmp_path):
        rule_file = tmp_path / "test.yml"
        rule_file.write_text("""
title: Metadata test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: evil
  condition: selection
level: medium
tags:
  - attack.discovery
  - attack.t1082
""")
        engine = RuleScopeEngine()
        report = engine.scan(str(tmp_path))
        layer = json.loads(export_navigator_layer(report, name="Custom Layer"))
        assert layer["name"] == "Custom Layer"
        assert "gradient" in layer
        for tech in layer["techniques"]:
            assert "score" in tech
            assert "color" in tech
            assert "metadata" in tech


# ── Reporter validation ──────────────────────────────────────────

class TestReporterValidation:
    def _scan_examples(self):
        engine = RuleScopeEngine()
        return engine.scan("examples/rules")

    def test_html_report_valid(self):
        from rulescope.reporters.html_reporter import HtmlReporter
        report = self._scan_examples()
        html = HtmlReporter().render(report)
        assert "<!DOCTYPE html>" in html
        assert "RuleScope Report" in html
        assert "radar" in html  # radar chart present
        assert "filterRules" in html  # JS filter present
        assert str(report.summary.average_score) in html
        # Check all rule titles appear
        for rule in report.rules:
            if rule.title:
                assert rule.title in html

    def test_json_report_valid(self):
        from rulescope.reporters.json_reporter import JsonReporter
        report = self._scan_examples()
        output = JsonReporter().render(report)
        data = json.loads(output)
        assert "summary" in data
        assert "rules" in data
        assert data["version"] == __version__
        assert data["summary"]["total_rules"] == len(data["rules"])

    def test_sarif_report_valid(self):
        from rulescope.reporters.sarif_reporter import SarifReporter
        report = self._scan_examples()
        output = SarifReporter().render(report)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "RuleScope"
        for result in data["runs"][0]["results"]:
            assert "ruleId" in result
            assert "level" in result
            assert "locations" in result

    def test_markdown_report_valid(self):
        from rulescope.reporters.markdown_reporter import MarkdownReporter
        report = self._scan_examples()
        output = MarkdownReporter().render(report)
        assert "# RuleScope" in output
        assert str(report.summary.average_score) in output
        assert "Findings" in output or "findings" in output
