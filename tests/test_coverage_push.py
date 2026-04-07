"""Targeted tests to push coverage above 90%."""
from __future__ import annotations

import pytest

from rulescope.engine import RuleScopeEngine
from rulescope.scorers.weighted_score import WeightedScorer
from rulescope.parsers.sigma_parser import SigmaParser, SigmaParserError


# ── WeightedScorer.compute_segments (previously 0% covered) ─────

class TestScorerSegments:
    def test_compute_segments(self):
        engine = RuleScopeEngine()
        report = engine.scan("examples/rules")
        scorer = WeightedScorer()
        segments = scorer.compute_segments(report.rules, lambda r: r.logsource_key or "(unknown)")
        assert len(segments) >= 1
        for seg in segments:
            assert seg.rule_count >= 1
            assert 0 <= seg.average_score <= 100

    def test_catalog_bands(self):
        scorer = WeightedScorer()
        assert scorer._band(95) == "Excellent"
        assert scorer._band(80) == "Good"
        assert scorer._band(65) == "Needs work"
        assert scorer._band(45) == "High risk"
        assert scorer._band(20) == "Critical"


# ── Navigator edge cases ─────────────────────────────────────────

class TestNavigatorEdgeCases:
    def test_score_to_color_thresholds(self):
        from rulescope.reporters.navigator_export import _score_to_color
        assert _score_to_color(80) == "#66cc66"
        assert _score_to_color(60) == "#ffcc00"
        assert _score_to_color(30) == "#ff6666"
        assert _score_to_color(75) == "#66cc66"
        assert _score_to_color(49) == "#ff6666"


# ── Parser: file read error ──────────────────────────────────────

class TestParserFileErrors:
    def test_unreadable_file(self, tmp_path):
        bad_file = tmp_path / "bad.yml"
        bad_file.write_bytes(b'\x80\x81\x82')  # invalid utf-8
        parser = SigmaParser()
        # Should raise SigmaParserError, not crash
        with pytest.raises(SigmaParserError):
            parser.parse_file(bad_file)

    def test_nonexistent_file(self, tmp_path):
        parser = SigmaParser()
        with pytest.raises(SigmaParserError):
            parser.parse_file(tmp_path / "nonexistent.yml")


# ── Markdown reporter: catalog with all optional sections ────────

class TestMarkdownFullCoverage:
    def test_catalog_with_all_sections(self):
        from rulescope.reporters.markdown_reporter import MarkdownReporter
        engine = RuleScopeEngine()
        report = engine.scan("examples/rules")
        md = MarkdownReporter().render(report)
        # Budget failures
        if not report.summary.budget_result.passed:
            assert "Governance Budget" in md
        # Duplicates
        if report.duplicate_clusters:
            assert "Duplicate Clusters" in md
        # Overlap
        if report.overlap_pairs:
            assert "Overlap Pairs" in md
        # Debt categories
        if report.summary.debt.categories:
            assert "Technical Debt" in md
        # Remediations
        if report.summary.debt.top_recommendations:
            assert "Remediations" in md
        # Coverage
        if report.summary.coverage:
            assert "ATT&CK Coverage" in md
        # Rule details
        assert "## Rule Details" in md
        for rule in report.rules[:3]:
            if rule.findings:
                assert rule.findings[0].code in md


# ── i18n: env detection ──────────────────────────────────────────

class TestI18nEnvDetection:
    def test_detect_fr_from_env(self, monkeypatch):
        from rulescope.i18n import detect_system_lang
        monkeypatch.setenv("RULESCOPE_LANG", "fr")
        assert detect_system_lang() == "fr"

    def test_detect_en_from_env(self, monkeypatch):
        from rulescope.i18n import detect_system_lang
        monkeypatch.setenv("RULESCOPE_LANG", "en")
        assert detect_system_lang() == "en"

    def test_detect_from_locale(self, monkeypatch):
        from rulescope.i18n import detect_system_lang
        monkeypatch.delenv("RULESCOPE_LANG", raising=False)
        monkeypatch.setenv("LANG", "fr_FR.UTF-8")
        assert detect_system_lang() == "fr"

    def test_default_english(self, monkeypatch):
        from rulescope.i18n import detect_system_lang
        monkeypatch.delenv("RULESCOPE_LANG", raising=False)
        monkeypatch.setenv("LANG", "C")
        assert detect_system_lang() == "en"
