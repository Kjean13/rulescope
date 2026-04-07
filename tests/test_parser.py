"""Tests for parser improvements: multi-doc YAML, list-of-maps normalization."""
from __future__ import annotations

import pytest

from rulescope.parsers.sigma_parser import SigmaParser, SigmaParserError


parser = SigmaParser()


class TestMultiDocYaml:
    def test_single_doc_still_works(self):
        text = """
title: Simple Rule
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
        assert rule.title == "Simple Rule"
        assert rule.logsource["product"] == "windows"

    def test_multi_doc_selects_rule_document(self):
        text = """
# First document: metadata only
action: global
title: Global Config
---
title: Actual Rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: evil
  condition: selection
level: high
"""
        rule = parser.parse_string(text)
        assert rule.title == "Actual Rule"
        assert rule.level == "high"
        assert "selection" in rule.detection

    def test_multi_doc_prefers_detection_logsource(self):
        text = """
title: No detection
description: Just metadata
---
title: Has detection
logsource:
  product: linux
detection:
  sel:
    CommandLine: whoami
  condition: sel
level: low
---
title: Third doc
"""
        rule = parser.parse_string(text)
        assert rule.title == "Has detection"
        assert rule.logsource["product"] == "linux"


class TestListOfMapsNormalization:
    def test_list_of_maps_selector_normalized(self):
        text = """
title: List of maps
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    - CommandLine|contains: evil
    - Image|endswith: bad.exe
  condition: selection
level: medium
"""
        rule = parser.parse_string(text)
        # Should be merged into a single dict for analysis
        sel = rule.detection.get("selection")
        assert isinstance(sel, dict)
        # Both fields should be present
        fields = list(sel.keys())
        assert any("CommandLine" in f for f in fields)
        assert any("Image" in f for f in fields)

    def test_standard_dict_selector_unchanged(self):
        text = """
title: Dict selector
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: evil
    Image|endswith: bad.exe
  condition: selection
level: medium
"""
        rule = parser.parse_string(text)
        sel = rule.detection.get("selection")
        assert isinstance(sel, dict)
        assert "CommandLine|contains" in sel
        assert "Image|endswith" in sel


class TestParserEdgeCases:
    def test_empty_yaml_raises(self):
        with pytest.raises(SigmaParserError):
            parser.parse_string("")

    def test_non_mapping_raises(self):
        with pytest.raises(SigmaParserError):
            parser.parse_string("- just\n- a\n- list\n")

    def test_keyword_list_selector_preserved(self):
        text = """
title: Keyword rule
logsource:
  product: windows
  category: process_creation
detection:
  keywords:
    - evil
    - bad
    - malware
  condition: keywords
level: low
"""
        rule = parser.parse_string(text)
        kw = rule.detection.get("keywords")
        assert isinstance(kw, list)
        assert "evil" in kw

    def test_missing_detection_still_parses(self):
        text = """
title: No detection
logsource:
  product: windows
level: medium
"""
        rule = parser.parse_string(text)
        assert rule.title == "No detection"
        assert rule.detection == {}


class TestGlobalMerge:
    """Multi-doc YAML with global document merge."""

    def test_global_metadata_merges_into_rule(self):
        text = """
author: Global Author
status: test
tags:
  - attack.execution
---
title: My Rule
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    CommandLine: evil
  condition: sel
level: high
"""
        rule = parser.parse_string(text)
        assert rule.title == "My Rule"
        assert rule.author == "Global Author"
        assert rule.status == "test"
        assert "attack.execution" in rule.tags

    def test_global_logsource_merges_recursively(self):
        text = """
logsource:
  product: windows
---
title: Inherits logsource
logsource:
  category: process_creation
detection:
  sel:
    Image: cmd.exe
  condition: sel
level: medium
"""
        rule = parser.parse_string(text)
        # Both product (from global) and category (from rule) should be present
        assert rule.logsource.get("product") == "windows"
        assert rule.logsource.get("category") == "process_creation"

    def test_global_tags_concatenate(self):
        text = """
tags:
  - attack.execution
---
title: Tag merge
logsource:
  product: windows
detection:
  sel:
    Image: cmd.exe
  condition: sel
level: medium
tags:
  - attack.t1059
"""
        rule = parser.parse_string(text)
        assert "attack.execution" in rule.tags
        assert "attack.t1059" in rule.tags

    def test_rule_scalar_overrides_global_scalar(self):
        text = """
level: low
author: Global Author
---
title: Override test
level: critical
logsource:
  product: windows
detection:
  sel:
    Image: cmd.exe
  condition: sel
"""
        rule = parser.parse_string(text)
        assert rule.level == "critical"
        assert rule.author == "Global Author"

    def test_single_doc_no_merge_needed(self):
        """Single document should work identically to before."""
        text = """
title: Single
logsource:
  product: linux
detection:
  sel:
    CommandLine: whoami
  condition: sel
level: low
"""
        rule = parser.parse_string(text)
        assert rule.title == "Single"

    def test_two_docs_both_with_detection_no_merge(self):
        """If both docs have detection, first is not a global — pick best."""
        text = """
title: Doc1
logsource:
  product: windows
detection:
  sel:
    Image: a.exe
  condition: sel
level: low
---
title: Doc2
logsource:
  product: linux
detection:
  sel:
    CommandLine: b
  condition: sel
level: high
"""
        rule = parser.parse_string(text)
        # Both have detection+logsource; first wins
        assert rule.title == "Doc1"


class TestLatinFallback:
    def test_latin1_file_parses(self, tmp_path):
        """Files encoded in latin-1 should parse via fallback."""
        content = "title: Règle spéciale\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: cmd.exe\n  condition: sel\nlevel: medium\n"
        p = tmp_path / "latin.yml"
        p.write_bytes(content.encode("latin-1"))
        rule = parser.parse_file(p)
        assert "sp" in rule.title  # "spéciale" may render differently but must not crash


class TestCorrelationParsing:
    def test_explicit_correlation_type(self):
        text = """
title: Brute Force Correlation
type: correlation
correlation:
  type: event_count
  rules:
    - failed_login
  group-by:
    - source_ip
  timespan: 5m
  condition:
    gte: 10
level: high
"""
        rule = parser.parse_string(text)
        assert rule.is_correlation
        assert rule.correlation_type == "event_count"
        assert "source_ip" in rule.correlation_group_by
        assert rule.correlation_timespan == "5m"

    def test_implicit_correlation_from_block(self):
        text = """
title: Implicit Correlation
correlation:
  rules:
    - base_rule
  group-by:
    - user
  timespan: 10m
  condition:
    gte: 5
level: medium
"""
        rule = parser.parse_string(text)
        assert rule.is_correlation
        assert rule.correlation.get("type") == "event_count"

    def test_correlation_top_level_fields_merged(self):
        text = """
title: Top Level Fields
type: correlation
group-by:
  - hostname
timespan: 1h
rules:
  - rule_a
  - rule_b
level: high
"""
        rule = parser.parse_string(text)
        assert rule.is_correlation
        assert "hostname" in rule.correlation_group_by
        assert rule.correlation_timespan == "1h"
        assert "rule_a" in rule.correlation_rules

    def test_value_count_correlation(self):
        text = """
title: Value Count
type: correlation
correlation:
  rules:
    - base
  group-by:
    - src_ip
  timespan: 15m
  condition:
    field: dst_ip
level: high
"""
        rule = parser.parse_string(text)
        assert rule.correlation.get("type") == "value_count"


class TestFilterRuleParsing:
    def test_filter_rule_type(self):
        text = """
title: Global Filter
type: filter
logsource:
  product: windows
detection:
  sel:
    User: SYSTEM
  condition: sel
"""
        rule = parser.parse_string(text)
        assert rule.is_filter_rule
        assert rule.rule_type == "filter"


class TestListOfMapsDuplicateFields:
    def test_duplicate_fields_accumulated_not_lost(self):
        """When list-of-maps selectors repeat the same field, values must accumulate."""
        text = """
title: Dup fields
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    - CommandLine|contains: evil
    - CommandLine|contains: bad
    - CommandLine|contains: malware
  condition: selection
level: medium
"""
        rule = parser.parse_string(text)
        sel = rule.detection["selection"]
        cl = sel["CommandLine|contains"]
        # All three values must be present (accumulated)
        assert isinstance(cl, list)
        assert len(cl) == 3
        assert "evil" in cl
        assert "bad" in cl
        assert "malware" in cl


class TestDeepMerge:
    def test_deep_merge_dicts(self):
        from rulescope.parsers.sigma_parser import _deep_merge
        base = {"a": 1, "nested": {"x": 10}}
        overlay = {"b": 2, "nested": {"y": 20}}
        result = _deep_merge(base, overlay)
        assert result == {"a": 1, "b": 2, "nested": {"x": 10, "y": 20}}

    def test_deep_merge_lists_concatenate(self):
        from rulescope.parsers.sigma_parser import _deep_merge
        base = {"tags": ["a", "b"]}
        overlay = {"tags": ["c"]}
        result = _deep_merge(base, overlay)
        assert result["tags"] == ["a", "b", "c"]

    def test_deep_merge_scalar_override(self):
        from rulescope.parsers.sigma_parser import _deep_merge
        base = {"level": "low", "keep": True}
        overlay = {"level": "high"}
        result = _deep_merge(base, overlay)
        assert result["level"] == "high"
        assert result["keep"] is True

    def test_deep_merge_does_not_mutate_base(self):
        from rulescope.parsers.sigma_parser import _deep_merge
        base = {"a": 1, "nested": {"x": 10}}
        overlay = {"nested": {"y": 20}}
        _deep_merge(base, overlay)
        assert "y" not in base["nested"]
