"""Tests for the catalog health score redesign.

Covers:
- raw_average_score / catalog_health_score separation
- relative penalty formula behaviour
- score_band based on catalog_health_score
- backward-compat: average_score == raw_average_score
- edge cases: empty catalog, single rule, all-invalid
- large-catalog fairness: same % of issues → same penalty regardless of size
- JSON / Markdown output exposes both metrics
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from rulescope.scorers.weighted_score import WeightedScorer
from rulescope.engine import RuleScopeEngine


# ── Helpers ──────────────────────────────────────────────────────────────────

def catalog(scores, *, dup=0, ovl=0, noise=0, weak=0, wmeta=0, invalid=0):
    """Shorthand for WeightedScorer().score_catalog(...)."""
    return WeightedScorer().score_catalog(
        rule_scores=scores,
        duplicate_pairs=dup,
        overlap_pairs=ovl,
        weak_metadata_rules=wmeta,
        high_noise_rules=noise,
        invalid_rules=invalid,
        weak_rules=weak,
    )


# ── Field presence ────────────────────────────────────────────────────────────

class TestFieldPresence:
    def test_raw_average_score_field_exists(self):
        s = catalog([90, 95, 88])
        assert hasattr(s, "raw_average_score")

    def test_catalog_health_score_field_exists(self):
        s = catalog([90, 95, 88])
        assert hasattr(s, "catalog_health_score")

    def test_average_score_backward_compat_equals_raw(self):
        """average_score must stay == raw_average_score for backward compat."""
        s = catalog([80, 90, 70])
        assert s.average_score == s.raw_average_score

    def test_both_fields_in_valid_range(self):
        s = catalog([75, 80, 85], dup=5, ovl=20, noise=2, weak=10)
        assert 0 <= s.raw_average_score <= 100
        assert 0 <= s.catalog_health_score <= 100


# ── Raw average correctness ───────────────────────────────────────────────────

class TestRawAverage:
    def test_clean_catalog_raw_equals_mean(self):
        s = catalog([90, 80, 70])
        assert s.raw_average_score == 80

    def test_raw_unaffected_by_penalties(self):
        """Penalties must NOT touch raw_average_score."""
        clean  = catalog([90, 90, 90])
        noisy  = catalog([90, 90, 90], dup=50, ovl=500, noise=10, weak=30, invalid=5)
        assert clean.raw_average_score == noisy.raw_average_score == 90

    def test_single_rule(self):
        s = catalog([77])
        assert s.raw_average_score == 77

    def test_empty_catalog(self):
        s = catalog([])
        assert s.raw_average_score == 0
        assert s.catalog_health_score == 0


# ── Penalty direction ─────────────────────────────────────────────────────────

class TestPenaltyDirection:
    def test_no_issues_no_penalty(self):
        s = catalog([95, 97, 96])
        assert s.catalog_health_score == s.raw_average_score

    def test_health_lte_raw(self):
        s = catalog([90] * 100, dup=10, ovl=200, noise=5, weak=20)
        assert s.catalog_health_score <= s.raw_average_score

    def test_more_issues_lower_health(self):
        few  = catalog([90] * 200, dup=2,  ovl=10,  noise=0, weak=5)
        many = catalog([90] * 200, dup=30, ovl=500, noise=10, weak=50)
        assert many.catalog_health_score < few.catalog_health_score

    def test_health_never_negative(self):
        s = catalog([10] * 50, dup=100, ovl=1000, noise=20, weak=50, invalid=20)
        assert s.catalog_health_score >= 0

    def test_invalid_rules_penalised_most(self):
        """invalid_rules carry the heaviest per-unit weight."""
        with_invalid  = catalog([90] * 100, invalid=10)
        with_weak     = catalog([90] * 100, weak=10)
        assert with_invalid.catalog_health_score <= with_weak.catalog_health_score


# ── Relative penalty fairness ─────────────────────────────────────────────────

class TestRelativePenaltyFairness:
    def test_same_dup_rate_same_penalty(self):
        """10% duplicate rate on 100-rule and 1000-rule catalogs → same penalty."""
        small = catalog([90] * 100,  dup=10)
        large = catalog([90] * 1000, dup=100)
        assert small.catalog_health_score == large.catalog_health_score

    def test_same_weak_rate_same_penalty(self):
        small = catalog([90] * 50,  weak=5)
        large = catalog([90] * 500, weak=50)
        assert small.catalog_health_score == large.catalog_health_score

    def test_same_noise_rate_same_penalty(self):
        small = catalog([90] * 100,  noise=5)
        large = catalog([90] * 1000, noise=50)
        assert small.catalog_health_score == large.catalog_health_score

    def test_large_catalog_not_unfairly_penalised(self):
        """A 3000-rule catalog at 96 avg with ~10% issues should score >= 80."""
        s = catalog([96] * 3000, dup=300, ovl=37000, noise=9, weak=550)
        assert s.catalog_health_score >= 80, (
            f"Large HQ catalog got {s.catalog_health_score} — penalty too aggressive"
        )


# ── Score band ────────────────────────────────────────────────────────────────

class TestScoreBand:
    def test_band_based_on_health_not_raw(self):
        """score_band must reflect catalog_health_score, not raw average."""
        s = catalog([96] * 3000, dup=300, ovl=37000, noise=9, weak=550)
        # health should be >= 75 → Good or Excellent
        assert s.score_band in {"Excellent", "Good"}, (
            f"Expected Good/Excellent but got {s.score_band} "
            f"(health={s.catalog_health_score})"
        )

    def test_clean_catalog_excellent(self):
        s = catalog([95, 97, 93])
        assert s.score_band == "Excellent"

    def test_degraded_catalog_high_risk_or_critical(self):
        s = catalog([60] * 100, dup=30, ovl=500, noise=15, weak=50, invalid=10)
        assert s.score_band in {"High risk", "Critical"}

    @pytest.mark.parametrize("avg,expected_band", [
        (95, "Excellent"),
        (82, "Good"),
        (65, "Needs work"),
        (45, "High risk"),
        (20, "Critical"),
    ])
    def test_band_thresholds(self, avg, expected_band):
        # No penalties → health == raw → band purely from avg
        s = catalog([avg])
        assert s.score_band == expected_band


# ── JSON output ───────────────────────────────────────────────────────────────

class TestJsonOutput:
    def test_json_report_has_both_fields(self):
        report = RuleScopeEngine().scan("examples/rules")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            from rulescope.reporters.json_reporter import JsonReporter
            out.write_text(JsonReporter().render(report), encoding="utf-8")
            data = json.loads(out.read_text())
        summary = data["summary"]
        assert "average_score" in summary
        assert "raw_average_score" in summary
        assert "catalog_health_score" in summary

    def test_json_average_score_equals_raw(self):
        report = RuleScopeEngine().scan("examples/rules")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            from rulescope.reporters.json_reporter import JsonReporter
            out.write_text(JsonReporter().render(report), encoding="utf-8")
            data = json.loads(out.read_text())
        s = data["summary"]
        assert s["average_score"] == s["raw_average_score"]

    def test_json_health_lte_raw(self):
        report = RuleScopeEngine().scan("examples/rules")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            from rulescope.reporters.json_reporter import JsonReporter
            out.write_text(JsonReporter().render(report), encoding="utf-8")
            data = json.loads(out.read_text())
        s = data["summary"]
        assert s["catalog_health_score"] <= s["average_score"]


# ── Markdown output ───────────────────────────────────────────────────────────

class TestMarkdownOutput:
    def test_markdown_contains_rule_score_label(self):
        report = RuleScopeEngine().scan("examples/rules")
        from rulescope.reporters.markdown_reporter import MarkdownReporter
        md = MarkdownReporter().render(report)
        assert "Average Rule Score" in md or "Score moyen par règle" in md

    def test_markdown_contains_health_score_label(self):
        report = RuleScopeEngine().scan("examples/rules")
        from rulescope.reporters.markdown_reporter import MarkdownReporter
        md = MarkdownReporter().render(report)
        assert "Catalog Health Score" in md or "Score de santé catalogue" in md

    def test_markdown_contains_both_values(self):
        report = RuleScopeEngine().scan("examples/rules")
        from rulescope.reporters.markdown_reporter import MarkdownReporter
        md = MarkdownReporter().render(report)
        raw = str(report.summary.average_score)
        health = str(report.summary.catalog_health_score)
        assert raw in md
        assert health in md
