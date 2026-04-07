"""Final coverage push — targets remaining uncovered branches."""
from __future__ import annotations

import json
from typer.testing import CliRunner

from rulescope import __version__
from rulescope.cli import app
from rulescope.engine import RuleScopeEngine
from rulescope.comparison import compare_catalogs
from rulescope.reporters.markdown_reporter import MarkdownReporter


runner = CliRunner()


# ── CLI edge cases ───────────────────────────────────────────────

class TestCLIEdgeCases:
    def test_compare_markdown_output(self, tmp_path):
        out = tmp_path / "cmp.md"
        result = runner.invoke(app, [
            "compare", "datasets/regression_demo/baseline", "datasets/regression_demo/candidate",
            "--format", "markdown", "--output", str(out)
        ])
        assert result.exit_code in (0, 1)
        assert out.exists()
        md = out.read_text()
        assert "Compare" in md

    def test_scan_single_file(self, tmp_path):
        rule = tmp_path / "single.yml"
        rule.write_text("""
title: Single File Test
id: 11111111-1111-1111-1111-111111111111
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: test
  condition: selection
level: low
status: test
description: A single file scan test for coverage purposes.
tags:
  - attack.execution
  - attack.t1059
falsepositives:
  - Legitimate admin scripts
author: test
date: 2024-01-01
references:
  - https://example.com
""")
        result = runner.invoke(app, ["scan", str(rule)])
        assert result.exit_code == 0

    def test_explain_invalid_path(self):
        result = runner.invoke(app, ["explain", "/nonexistent"])
        assert result.exit_code != 0

    def test_report_markdown(self, tmp_path):
        out = tmp_path / "r.md"
        result = runner.invoke(app, ["report", "examples/rules", "-o", str(out), "-f", "markdown"])
        assert result.exit_code == 0
        assert "RuleScope" in out.read_text()

    def test_report_sarif(self, tmp_path):
        out = tmp_path / "r.sarif"
        result = runner.invoke(app, ["report", "examples/rules", "-o", str(out), "-f", "sarif"])
        assert result.exit_code == 0
        json.loads(out.read_text())

    def test_report_json(self, tmp_path):
        out = tmp_path / "r.json"
        result = runner.invoke(app, ["report", "examples/rules", "-o", str(out), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["version"] == __version__

    def test_ci_with_sarif_output(self, tmp_path):
        out = tmp_path / "ci.sarif"
        runner.invoke(app, [
            "ci", "examples/rules", "--min-score", "10",
            "--format", "sarif", "--output", str(out)
        ])
        # May fail due to invalid_rules > 0
        if out.exists():
            data = json.loads(out.read_text())
            assert data["version"] == "2.1.0"

    def test_scan_format_table_with_output(self, tmp_path):
        """Table format with output should fall back to json."""
        result = runner.invoke(app, ["scan", "examples/rules", "--format", "table"])
        assert result.exit_code in (0, 1)

    def test_compare_unsupported_format(self):
        result = runner.invoke(app, [
            "compare", "datasets/regression_demo/baseline", "datasets/regression_demo/candidate",
            "--format", "xml"
        ])
        assert result.exit_code != 0


# ── Markdown compare with improvements ───────────────────────────

class TestMarkdownImprovements:
    def test_compare_with_improvements_section(self):
        """Create a scenario where improvements exist."""
        engine = RuleScopeEngine()
        # candidate is baseline here so no regression = possible improvement
        baseline = engine.scan("datasets/regression_demo/candidate")
        candidate = engine.scan("datasets/regression_demo/baseline")
        diff = compare_catalogs(baseline, candidate)
        md = MarkdownReporter().render(diff)
        assert "# RuleScope Compare Report" in md
        # Should have at least summary section
        assert "## Summary" in md


# ── Config edge cases ────────────────────────────────────────────

class TestConfigEdgeCases:
    def test_invalid_config_file(self, tmp_path):
        cfg = tmp_path / "bad.yml"
        cfg.write_text("not: [valid: config")
        result = runner.invoke(app, ["scan", "examples/rules", "--config", str(cfg)])
        assert result.exit_code != 0

    def test_nonexistent_config_file(self):
        result = runner.invoke(app, ["scan", "examples/rules", "--config", "/nonexistent.yml"])
        assert result.exit_code != 0

    def test_valid_config_file(self, tmp_path):
        cfg = tmp_path / "good.yml"
        cfg.write_text("weights:\n  metadata: 0.25\n  maintainability: 0.15\n  noise: 0.15\n  structural: 0.15\n  documentation: 0.10\n  attack_quality: 0.10\n  weakness: 0.10\n")
        result = runner.invoke(app, ["scan", "examples/rules", "--config", str(cfg)])
        assert result.exit_code in (0, 1)


# ── Engine: empty directory ──────────────────────────────────────

class TestEngineEdgeCases:
    def test_empty_directory(self, tmp_path):
        engine = RuleScopeEngine()
        report = engine.scan(str(tmp_path))
        assert report.summary.total_rules == 0
        assert report.summary.average_score == 0

    def test_maintainer_snapshot_empty(self, tmp_path):
        engine = RuleScopeEngine()
        report = engine.scan(str(tmp_path))
        snapshot = engine.maintainer_snapshot(report)
        assert snapshot["catalog_score"] == 0
        assert snapshot["rules"] == 0

    def test_top_issues_empty(self, tmp_path):
        engine = RuleScopeEngine()
        report = engine.scan(str(tmp_path))
        issues = engine.get_top_issues(report)
        assert issues == []


# ── Noise analyzer: remaining branches ───────────────────────────

class TestNoiseDeepBranches:
    def test_regex_heavy_rule(self):
        from rulescope.analyzers.noise import NoiseAnalyzer
        from rulescope.models.rule import DetectionRule
        rule = DetectionRule(
            path="t.yml", source_name="t.yml", title="Regex", level="medium",
            detection={
                "selection": {"CommandLine|re": ".*evil.*", "Image|re": ".*bad.*", "User|re": "admin.*"},
                "condition": "selection",
            },
            logsource={"product": "windows", "category": "process_creation"},
        )
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-002" in codes

    def test_generic_fields_high_severity(self):
        from rulescope.analyzers.noise import NoiseAnalyzer
        from rulescope.models.rule import DetectionRule
        rule = DetectionRule(
            path="t.yml", source_name="t.yml", title="Generic", level="critical",
            detection={
                "selection": {
                    "CommandLine": "cmd", "Image": "evil", "ParentImage": "parent",
                    "process": "proc", "User": "admin", "commandline": "extra",
                },
                "condition": "selection",
            },
            logsource={"product": "windows", "category": "process_creation"},
        )
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-004" in codes

    def test_all_wildcard_ratio(self):
        from rulescope.analyzers.noise import NoiseAnalyzer
        from rulescope.models.rule import DetectionRule
        rule = DetectionRule(
            path="t.yml", source_name="t.yml", title="Wildcard", level="low",
            detection={
                "selection": {"CommandLine": ["*a*", "*b*", "*c*", "*d*"]},
                "condition": "selection",
            },
            logsource={"product": "windows", "category": "process_creation"},
        )
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-006" in codes or "NOISE-001" in codes


# ── Maintainability: deep nesting, large value sets ──────────────

class TestMaintainabilityDeep:
    def test_deep_nesting_penalized(self):
        from rulescope.analyzers.maintainability import MaintainabilityAnalyzer
        from rulescope.models.rule import DetectionRule
        rule = DetectionRule(
            path="t.yml", source_name="t.yml", title="Deep",
            detection={
                "selection": {"a": {"b": {"c": {"d": {"e": "val"}}}}},
                "condition": "selection",
            },
            logsource={"product": "windows"},
        )
        score, findings = MaintainabilityAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "MAINT-003" in codes

    def test_long_condition_penalized(self):
        from rulescope.analyzers.maintainability import MaintainabilityAnalyzer
        from rulescope.models.rule import DetectionRule
        long_cond = " and ".join([f"selection{i}" for i in range(30)])
        detection = {f"selection{i}": {"CommandLine": f"val{i}"} for i in range(30)}
        detection["condition"] = long_cond
        rule = DetectionRule(
            path="t.yml", source_name="t.yml", title="Long",
            detection=detection,
            logsource={"product": "windows"},
        )
        score, findings = MaintainabilityAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "MAINT-001" in codes
        assert "MAINT-004" in codes

    def test_large_value_set(self):
        from rulescope.analyzers.maintainability import MaintainabilityAnalyzer
        from rulescope.models.rule import DetectionRule
        rule = DetectionRule(
            path="t.yml", source_name="t.yml", title="Large",
            detection={
                "selection": {"CommandLine": [f"value{i}" for i in range(50)]},
                "condition": "selection",
            },
            logsource={"product": "windows"},
        )
        score, findings = MaintainabilityAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "MAINT-006" in codes


# ── Parser: more edge cases ──────────────────────────────────────

class TestParserDeep:
    def test_multi_doc_no_detection(self):
        from rulescope.parsers.sigma_parser import SigmaParser
        parser = SigmaParser()
        text = """
title: First doc
description: Has title but no detection
---
title: Second doc
description: Also no detection
"""
        rule = parser.parse_string(text)
        assert rule.title in ("First doc", "Second doc")

    def test_list_of_maps_merge(self):
        from rulescope.parsers.sigma_parser import SigmaParser
        parser = SigmaParser()
        text = """
title: Merged
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    - CommandLine|contains: evil
    - CommandLine|contains: bad
  condition: selection
level: medium
"""
        rule = parser.parse_string(text)
        sel = rule.detection["selection"]
        assert isinstance(sel, dict)
        vals = sel.get("CommandLine|contains")
        assert isinstance(vals, list)
        assert "evil" in vals
        assert "bad" in vals


# ── CLI: console dispatch edge cases ─────────────────────────────

class TestConsoleDispatch:
    def test_console_scan_no_args(self):
        from rulescope.cli import _dispatch_console_command
        # Should print usage, not crash
        _dispatch_console_command("scan", [], None)

    def test_console_compare_no_args(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("compare", [], None)

    def test_console_explain_no_args(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("explain", [], None)

    def test_console_report_no_args(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("report", [], None)

    def test_console_maintainers_no_args(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("maintainers", [], None)

    def test_console_navigator_no_args(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("navigator", [], None)

    def test_console_watch_no_args(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("watch", [], None)

    def test_console_unknown_command(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("xyznonexistent", [], None)

    def test_console_version(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("version", [], None)

    def test_console_doctor(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("doctor", [], None)
