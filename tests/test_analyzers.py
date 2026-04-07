"""Tests for analyzer improvements."""
from __future__ import annotations


from rulescope.analyzers.noise import NoiseAnalyzer
from rulescope.analyzers.structural import StructuralAnalyzer
from rulescope.analyzers.weakness import WeaknessAnalyzer
from rulescope.models.rule import DetectionRule


def _rule(**kwargs) -> DetectionRule:
    defaults = dict(
        path="test.yml", source_name="test.yml", title="Test Rule",
        level="medium", status="test",
        logsource={"product": "windows", "category": "process_creation"},
        detection={"selection": {"CommandLine|contains": "evil"}, "condition": "selection"},
    )
    defaults.update(kwargs)
    return DetectionRule(**defaults)


# ── NoiseAnalyzer: leading wildcards ─────────────────────────────

class TestNoiseLeadingWildcards:
    def test_leading_wildcards_penalized(self):
        rule = _rule(detection={
            "selection": {
                "CommandLine": ["*evil.exe", "*bad.dll"],
                "Image": "*\\temp\\*",
            },
            "condition": "selection",
        })
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-007" in codes

    def test_trailing_wildcards_not_penalized_as_leading(self):
        rule = _rule(detection={
            "selection": {
                "CommandLine": ["C:\\Windows\\*", "evil.exe*"],
            },
            "condition": "selection",
        })
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-007" not in codes


# ── StructuralAnalyzer: condition coherence ──────────────────────

class TestStructuralCoherence:
    def test_undefined_selection_detected(self):
        rule = _rule(detection={
            "selection": {"CommandLine": "evil"},
            "condition": "selection and not typo_filter",
        })
        score, findings = StructuralAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "STRUCT-007" in codes

    def test_unreferenced_selection_detected(self):
        rule = _rule(detection={
            "selection": {"CommandLine": "evil"},
            "filter_admin": {"User": "SYSTEM"},
            "condition": "selection",
        })
        score, findings = StructuralAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "STRUCT-008" in codes

    def test_valid_condition_no_coherence_issues(self):
        rule = _rule(detection={
            "selection": {"CommandLine": "evil"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        })
        score, findings = StructuralAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "STRUCT-007" not in codes
        assert "STRUCT-008" not in codes

    def test_them_keyword_skips_check(self):
        rule = _rule(detection={
            "selection1": {"CommandLine": "evil"},
            "selection2": {"Image": "bad.exe"},
            "condition": "1 of them",
        })
        score, findings = StructuralAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "STRUCT-007" not in codes
        assert "STRUCT-008" not in codes

    def test_wildcard_ref_skips_unreferenced_check(self):
        rule = _rule(detection={
            "selection_a": {"CommandLine": "evil"},
            "selection_b": {"Image": "bad.exe"},
            "condition": "1 of selection*",
        })
        score, findings = StructuralAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "STRUCT-008" not in codes


# ── WeaknessAnalyzer: negation and filter patterns ───────────────

class TestWeaknessNegation:
    def test_pure_negation_detected(self):
        rule = _rule(detection={
            "filter": {"User": "SYSTEM"},
            "condition": "not filter",
        })
        score, findings = WeaknessAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "WEAK-006" in codes

    def test_proper_negation_not_flagged(self):
        rule = _rule(detection={
            "selection": {"CommandLine": "evil"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        })
        score, findings = WeaknessAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "WEAK-006" not in codes

    def test_filter_only_rule_detected(self):
        rule = _rule(detection={
            "filter_admin": {"User": "SYSTEM"},
            "filter_service": {"User": "SERVICE"},
            "condition": "not filter_admin and not filter_service",
        })
        score, findings = WeaknessAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "WEAK-007" in codes

    def test_selection_and_filter_not_flagged(self):
        rule = _rule(detection={
            "selection": {"CommandLine": "evil"},
            "filter_admin": {"User": "SYSTEM"},
            "condition": "selection and not filter_admin",
        })
        score, findings = WeaknessAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "WEAK-007" not in codes


# ── NoiseAnalyzer: list-of-dicts detection and edge cases ────────

class TestNoiseEdgeCases:
    def test_leading_wildcards_in_list_of_dicts_detection(self):
        """Leading wildcards inside list-of-dicts selectors should be counted."""
        rule = _rule(detection={
            "selection": [
                {"CommandLine": "*evil.exe"},
                {"Image": "*bad.dll"},
                {"ParentImage": "*temp*"},
            ],
            "condition": "selection",
        })
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-007" in codes

    def test_high_wildcard_ratio_triggers_noise006(self):
        """Nearly all values being wildcards triggers NOISE-006."""
        rule = _rule(detection={
            "selection": {
                "CommandLine": ["cmd*a*z*", "cmd*b*z*", "cmd*c*z*"],
            },
            "condition": "selection",
        })
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-006" in codes

    def test_generic_fields_at_high_severity(self):
        """Generic field names at high severity trigger NOISE-004."""
        rule = _rule(
            level="high",
            detection={
                "selection": {
                    "commandline": "evil",
                    "image": "bad.exe",
                    "parentimage": "cmd.exe",
                    "process": "svchost",
                    "user": "admin",
                },
                "condition": "selection",
            },
        )
        score, findings = NoiseAnalyzer().analyze(rule)
        codes = [f.code for f in findings]
        assert "NOISE-004" in codes


# ── Semantic duplicate and weakness regression tests ─────────────────

class TestSemanticDuplicateAnalyzer:
    def test_textual_similarity_without_same_event_surface_not_duplicate(self):
        from rulescope.analyzers.duplicates import DuplicateAnalyzer

        left = _rule(
            path="left.yml",
            title="Mimikatz execution by file name",
            detection={"selection": {"OriginalFileName": "mimikatz.exe"}, "condition": "selection"},
        )
        right = _rule(
            path="right.yml",
            title="Mimikatz password strings on command line",
            detection={"selection": {"CommandLine|contains": "password"}, "condition": "selection"},
        )
        candidates, clusters = DuplicateAnalyzer().analyze([left, right])
        assert candidates == {}
        assert clusters == []

    def test_same_event_surface_with_different_wording_detected(self):
        from rulescope.analyzers.duplicates import DuplicateAnalyzer

        left = _rule(
            path="left.yml",
            title="Suspicious certutil download",
            description="downloads a file with certutil",
            detection={
                "image": {"Image|endswith": "\\certutil.exe"},
                "cli": {"CommandLine|contains": ["urlcache", "http"]},
                "condition": "all of them",
            },
        )
        right = _rule(
            path="right.yml",
            title="Certutil remote retrieval",
            description="retrieves remote payload with certutil",
            detection={
                "proc": {"OriginalFileName": "CertUtil.exe"},
                "args": {"CommandLine|contains": ["http", "urlcache"]},
                "condition": "all of them",
            },
        )
        candidates, clusters = DuplicateAnalyzer().analyze([left, right])
        assert "right.yml" in candidates.get("left.yml", [])
        assert any(set(cluster) == {"left.yml", "right.yml"} for cluster in clusters)


class TestSemanticWeaknessPrecision:
    def test_precise_originalfilename_scores_better_than_generic_contains(self):
        analyzer = WeaknessAnalyzer()
        precise = _rule(detection={"selection": {"OriginalFileName": "mimikatz.exe"}, "condition": "selection"})
        vague = _rule(detection={"selection": {"CommandLine|contains": "pass"}, "condition": "selection"})
        precise_score, precise_findings = analyzer.analyze(precise)
        vague_score, vague_findings = analyzer.analyze(vague)
        assert precise_score > vague_score
        assert "WEAK-009" not in {f.code for f in precise_findings}
        assert "WEAK-008" in {f.code for f in vague_findings} or "WEAK-009" in {f.code for f in vague_findings}

    def test_deprecated_status_caps_score(self):
        analyzer = WeaknessAnalyzer()
        rule = _rule(
            status="deprecated",
            detection={
                "selection": {"OriginalFileName": "mimikatz.exe", "Image|endswith": "\\mimikatz.exe"},
                "condition": "selection",
            },
        )
        score, _ = analyzer.analyze(rule)
        assert score <= 55
