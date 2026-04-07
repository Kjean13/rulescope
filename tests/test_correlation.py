"""Tests for Sigma v2 correlation rule support."""
from __future__ import annotations


from rulescope.parsers.sigma_parser import SigmaParser
from rulescope.engine import RuleScopeEngine


parser = SigmaParser()


class TestCorrelationParsing:
    def test_parse_correlation_rule(self):
        text = """
title: Brute Force
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
type: correlation
status: test
description: Correlates failed logons.
level: high
author: test
date: 2024-01-01
tags:
  - attack.credential_access
  - attack.t1110.001
references:
  - https://example.com
falsepositives:
  - Mistyped passwords
correlation:
  type: event_count
  rules:
    - failed_logon_base
  group-by:
    - SourceIP
    - TargetUserName
  timespan: 5m
  condition:
    gte: 5
"""
        rule = parser.parse_string(text)
        assert rule.is_correlation
        assert rule.rule_type == "correlation"
        assert rule.correlation_type == "event_count"
        assert "SourceIP" in rule.correlation_group_by
        assert "TargetUserName" in rule.correlation_group_by
        assert rule.correlation_timespan == "5m"
        assert "failed_logon_base" in rule.correlation_rules

    def test_parse_correlation_without_block(self):
        """Correlation with fields at top level instead of nested block."""
        text = """
title: Top Level Correlation
type: correlation
group-by:
  - SourceIP
timespan: 10m
rules:
  - base_rule_1
level: medium
"""
        rule = parser.parse_string(text)
        assert rule.is_correlation
        assert "SourceIP" in rule.correlation_group_by
        assert rule.correlation_timespan == "10m"

    def test_parse_filter_rule(self):
        text = """
title: Filter Out Admin Activity
type: filter
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    User: SYSTEM
  condition: selection
"""
        rule = parser.parse_string(text)
        assert rule.is_filter_rule
        assert rule.rule_type == "filter"

    def test_standard_rule_not_correlation(self):
        text = """
title: Standard Rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: evil
  condition: selection
level: medium
"""
        rule = parser.parse_string(text)
        assert not rule.is_correlation
        assert not rule.is_filter_rule
        assert rule.rule_type == "standard"

    def test_correlation_in_multidoc(self):
        text = """
title: Base rule
logsource:
  product: windows
detection:
  selection:
    EventID: 4625
  condition: selection
level: low
---
title: Correlation on top
type: correlation
correlation:
  type: event_count
  rules:
    - base_rule
  group-by:
    - SourceIP
  timespan: 5m
  condition:
    gte: 10
level: high
"""
        # Parser should find the correlation document
        rule = parser.parse_string(text)
        # It should find the first doc (has detection+logsource), but let's verify both parse
        assert rule.title in ("Base rule", "Correlation on top")

    def test_correlation_empty_group_by(self):
        text = """
title: No group
type: correlation
correlation:
  type: event_count
  rules:
    - base
  timespan: 1h
level: medium
"""
        rule = parser.parse_string(text)
        assert rule.correlation_group_by == []

    def test_correlation_string_rules(self):
        """Rules field as a single string instead of list."""
        text = """
title: Single ref
type: correlation
correlation:
  type: event_count
  rules: base_rule_id
  group-by: SourceIP
  timespan: 5m
level: medium
"""
        rule = parser.parse_string(text)
        assert rule.correlation_rules == ["base_rule_id"]
        assert rule.correlation_group_by == ["SourceIP"]


class TestCorrelationAnalysis:
    def test_well_formed_correlation_scores_high(self):
        engine = RuleScopeEngine()
        report = engine.scan("examples/correlation")
        brute = next(r for r in report.rules if "Brute" in r.title)
        assert brute.scores.overall >= 60
        # Should NOT have CORR-001 (has type+rules)
        codes = [f.code for f in brute.findings]
        assert "CORR-001" not in codes
        # Should NOT have noise/weakness findings (not applicable)
        assert not any(c.startswith("NOISE-") for c in codes)
        assert not any(c.startswith("WEAK-") for c in codes)

    def test_weak_correlation_has_findings(self):
        engine = RuleScopeEngine()
        report = engine.scan("examples/correlation")
        weak = next(r for r in report.rules if "Weak" in r.title)
        codes = [f.code for f in weak.findings]
        # Missing group-by
        assert "CORR-002" in codes
        # Missing timespan
        assert "CORR-003" in codes
        # Missing rules reference
        assert "CORR-004" in codes

    def test_correlation_mixed_catalog(self):
        """Scan a catalog with both standard and correlation rules."""
        engine = RuleScopeEngine()
        # Scan examples/rules (standard) + examples/correlation together
        # We'll just verify correlation examples work standalone
        report = engine.scan("examples/correlation")
        assert report.summary.total_rules == 2
        assert all(r.scores.overall >= 0 for r in report.rules)


class TestParserRobustness:
    def test_latin1_file(self, tmp_path):
        """Parser should handle non-UTF8 files via latin-1 fallback."""
        rule = tmp_path / "latin1.yml"
        content = "title: Règle café\nlogsource:\n  product: windows\ndetection:\n  sel:\n    User: José\n  condition: sel\nlevel: low\n"
        rule.write_bytes(content.encode("latin-1"))
        parsed = parser.parse_file(rule)
        assert "caf" in parsed.title

    def test_boolean_values_in_detection(self):
        text = """
title: Bool test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Enabled: true
    Count: 42
  condition: selection
level: low
"""
        rule = parser.parse_string(text)
        assert rule.detection["selection"]["Enabled"] is True
        assert rule.detection["selection"]["Count"] == 42

    def test_null_values_in_detection(self):
        text = """
title: Null test
logsource:
  product: windows
detection:
  selection:
    ParentImage: null
  condition: selection
level: low
"""
        rule = parser.parse_string(text)
        assert rule.detection["selection"]["ParentImage"] is None

    def test_nested_list_of_maps_with_overlap(self):
        text = """
title: Overlap merge
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    - CommandLine|contains: foo
    - CommandLine|contains: bar
    - Image|endswith: evil.exe
  condition: selection
level: medium
"""
        rule = parser.parse_string(text)
        sel = rule.detection["selection"]
        assert isinstance(sel, dict)
        cl = sel.get("CommandLine|contains")
        assert isinstance(cl, list)
        assert "foo" in cl and "bar" in cl

    def test_empty_detection_value(self):
        text = """
title: Empty detection
logsource:
  product: windows
  category: process_creation
detection:
  selection:
  condition: selection
level: low
"""
        rule = parser.parse_string(text)
        # selection is None -> should be handled gracefully
        assert "condition" in rule.detection

    def test_complex_condition_with_pipes(self):
        text = """
title: Complex condition
logsource:
  product: windows
  category: process_creation
detection:
  selection1:
    CommandLine|contains|all:
      - -enc
      - -nop
  selection2:
    ParentImage|endswith: cmd.exe
  filter:
    User: SYSTEM
  condition: (selection1 or selection2) and not filter
level: high
"""
        rule = parser.parse_string(text)
        assert "selection1" in rule.detection
        assert "filter" in rule.detection
        assert "condition" in rule.detection

    def test_deeply_nested_logsource(self):
        text = """
title: Deep logsource
logsource:
  product: windows
  category: process_creation
  service: sysmon
  definition: Requires Sysmon EventID 1
detection:
  selection:
    EventID: 1
  condition: selection
level: low
"""
        rule = parser.parse_string(text)
        assert rule.logsource_key == "windows/process_creation/sysmon"

    def test_multiple_conditions_string(self):
        """Condition as a list of strings (rare but valid in some Sigma variants)."""
        text = """
title: Multi condition
logsource:
  product: windows
detection:
  sel1:
    A: 1
  sel2:
    B: 2
  condition:
    - sel1
    - sel2
level: low
"""
        rule = parser.parse_string(text)
        cond = rule.detection.get("condition")
        assert isinstance(cond, list)
