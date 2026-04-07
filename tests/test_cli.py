"""CLI tests via typer.testing.CliRunner."""
from __future__ import annotations

import json

from typer.testing import CliRunner

from rulescope.cli import app
from rulescope import __version__

runner = CliRunner()


class TestScanCommand:
    def test_scan_table(self):
        result = runner.invoke(app, ["scan", "examples/rules"])
        assert result.exit_code == 0
        assert "RuleScope" in result.output
        assert "/100" in result.output

    def test_scan_json(self, tmp_path):
        out = tmp_path / "out.json"
        result = runner.invoke(app, ["scan", "examples/rules", "--format", "json", "--output", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "summary" in data
        assert "rules" in data

    def test_scan_html(self, tmp_path):
        out = tmp_path / "out.html"
        result = runner.invoke(app, ["scan", "examples/rules", "--format", "html", "--output", str(out)])
        assert result.exit_code == 0
        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "radar" in html

    def test_scan_sarif(self, tmp_path):
        out = tmp_path / "out.sarif"
        result = runner.invoke(app, ["scan", "examples/rules", "--format", "sarif", "--output", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_scan_markdown(self, tmp_path):
        out = tmp_path / "out.md"
        result = runner.invoke(app, ["scan", "examples/rules", "--format", "markdown", "--output", str(out)])
        assert result.exit_code == 0
        assert "RuleScope" in out.read_text()

    def test_scan_json_stdout_is_valid(self):
        result = runner.invoke(app, ["scan", "datasets/medium_realistic", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "summary" in data


    def test_scan_top_issues(self):
        result = runner.invoke(app, ["scan", "examples/rules", "--top-issues", "3"])
        assert result.exit_code == 0

    def test_scan_invalid_path(self):
        result = runner.invoke(app, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_invalid_format(self):
        result = runner.invoke(app, ["scan", "examples/rules", "--format", "xml"])
        assert result.exit_code != 0

    def test_scan_enforce_budget(self):
        result = runner.invoke(app, ["scan", "examples/rules", "--enforce-budget"])
        # examples/rules budget fails, so exit code should be 1
        assert result.exit_code == 1


class TestCompareCommand:
    def test_compare_table(self):
        result = runner.invoke(app, ["compare", "datasets/regression_demo/baseline", "datasets/regression_demo/candidate"])
        assert result.exit_code == 0
        assert "Compare" in result.output or "Regression" in result.output or "delta" in result.output

    def test_compare_json(self, tmp_path):
        out = tmp_path / "cmp.json"
        result = runner.invoke(app, ["compare", "datasets/regression_demo/baseline", "datasets/regression_demo/candidate", "--format", "json", "--output", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "summary" in data

    def test_compare_json_stdout_is_valid(self):
        result = runner.invoke(app, ["compare", "datasets/regression_demo/baseline", "datasets/regression_demo/candidate", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "summary" in data


    def test_compare_fail_on_regression(self):
        result = runner.invoke(app, ["compare", "datasets/regression_demo/baseline", "datasets/regression_demo/candidate", "--fail-on-regression"])
        assert result.exit_code == 1

    def test_compare_invalid_path(self):
        result = runner.invoke(app, ["compare", "/nonexistent", "datasets/regression_demo/candidate"])
        assert result.exit_code != 0


class TestExplainCommand:
    def test_explain_single(self):
        result = runner.invoke(app, ["explain", "examples/rules"])
        assert result.exit_code == 0
        assert "Explain" in result.output or "score" in result.output

    def test_explain_all(self):
        result = runner.invoke(app, ["explain", "examples/rules", "--all", "--max-rules", "2"])
        assert result.exit_code == 0


class TestReportCommand:
    def test_report_html(self, tmp_path):
        out = tmp_path / "report.html"
        result = runner.invoke(app, ["report", "examples/rules", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text()

    def test_report_json(self, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(app, ["report", "examples/rules", "--output", str(out), "--format", "json"])
        assert result.exit_code == 0
        json.loads(out.read_text())


class TestMaintainersCommand:
    def test_maintainers(self):
        result = runner.invoke(app, ["maintainers", "examples/rules"])
        assert result.exit_code == 0
        assert "Maintainers" in result.output or "Score" in result.output or "score" in result.output


class TestNavigatorCommand:
    def test_navigator_export(self, tmp_path):
        out = tmp_path / "layer.json"
        result = runner.invoke(app, ["navigator", "examples/rules", "--output", str(out)])
        assert result.exit_code == 0
        layer = json.loads(out.read_text())
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer


class TestCICommand:
    def test_ci_pass(self, tmp_path):
        # Create a clean rule that will pass all gates
        rule_dir = tmp_path / "rules"
        rule_dir.mkdir()
        (rule_dir / "good.yml").write_text("""
title: Good Rule For CI
id: 12345678-1234-1234-1234-123456789abc
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: evil
  filter:
    User: SYSTEM
  condition: selection and not filter
level: medium
status: test
description: A well-formed test rule for CI gate validation purposes.
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Admin scripts performing maintenance
author: test
date: 2024-01-01
references:
  - https://example.com/reference
""")
        result = runner.invoke(app, ["ci", str(rule_dir), "--min-score", "10"])
        assert result.exit_code == 0

    def test_ci_fail(self):
        result = runner.invoke(app, ["ci", "examples/rules", "--min-score", "99"])
        assert result.exit_code == 1


class TestDoctorCommand:
    def test_doctor(self):
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "RuleScope" in result.output


class TestVersionCommand:
    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in result.output
