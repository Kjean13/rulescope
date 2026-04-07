"""End-to-end tests + i18n tests + markdown compare coverage."""
from __future__ import annotations

import json


from rulescope import __version__
from rulescope.engine import RuleScopeEngine
from rulescope.i18n import get_lang, set_lang, t
from rulescope.reporters.html_reporter import HtmlReporter
from rulescope.reporters.json_reporter import JsonReporter
from rulescope.reporters.markdown_reporter import MarkdownReporter
from rulescope.reporters.sarif_reporter import SarifReporter
from rulescope.reporters.navigator_export import export_navigator_layer
from rulescope.comparison import compare_catalogs


# ── End-to-end: scan → compare → report → navigator ─────────────

class TestEndToEnd:
    """Full pipeline: scan two datasets, compare, export all formats."""

    def test_full_pipeline(self, tmp_path):
        engine = RuleScopeEngine()

        # Scan both datasets
        baseline_report = engine.scan("datasets/regression_demo/baseline")
        candidate_report = engine.scan("datasets/regression_demo/candidate")
        assert baseline_report.summary.total_rules >= 1
        assert candidate_report.summary.total_rules >= 1

        # Compare
        diff = compare_catalogs(baseline_report, candidate_report)
        assert diff.summary.summary_verdict in {"Regression", "Improved", "Mixed"}

        # JSON export
        json_out = JsonReporter().render(baseline_report)
        data = json.loads(json_out)
        assert data["version"] == __version__
        assert data["summary"]["total_rules"] == baseline_report.summary.total_rules

        # HTML export
        html_out = HtmlReporter().render(baseline_report)
        assert "<!DOCTYPE html>" in html_out
        assert "radar" in html_out

        # SARIF export
        sarif_out = SarifReporter().render(baseline_report)
        sarif_data = json.loads(sarif_out)
        assert sarif_data["version"] == "2.1.0"

        # Markdown export (catalog)
        md_out = MarkdownReporter().render(baseline_report)
        assert "# RuleScope Report" in md_out
        assert "## Rule Details" in md_out

        # Markdown export (compare)
        md_compare = MarkdownReporter().render(diff)
        assert "# RuleScope Compare Report" in md_compare
        assert diff.summary.summary_verdict in md_compare

        # Navigator export
        layer_json = export_navigator_layer(baseline_report)
        layer = json.loads(layer_json)
        assert layer["domain"] == "enterprise-attack"

        # Write all to disk to verify I/O
        (tmp_path / "report.json").write_text(json_out)
        (tmp_path / "report.html").write_text(html_out)
        (tmp_path / "report.sarif").write_text(sarif_out)
        (tmp_path / "report.md").write_text(md_out)
        (tmp_path / "compare.md").write_text(md_compare)
        (tmp_path / "layer.json").write_text(layer_json)

        # Verify all files exist and are non-empty
        for name in ["report.json", "report.html", "report.sarif", "report.md", "compare.md", "layer.json"]:
            assert (tmp_path / name).stat().st_size > 100

    def test_medium_realistic_dataset(self):
        """Scan the larger dataset to exercise more code paths."""
        engine = RuleScopeEngine()
        report = engine.scan("datasets/medium_realistic")
        assert report.summary.total_rules >= 3
        assert report.summary.debt.total_findings > 0

        # Coverage should be populated
        if any(r.attack_tactics for r in report.rules):
            assert len(report.summary.coverage) > 0

        # Segments
        assert len(report.summary.segments_by_logsource) > 0
        assert len(report.summary.segments_by_level) > 0

        # Top issues
        issues = engine.get_top_issues(report, limit=5)
        assert len(issues) >= 1

        # Maintainer snapshot
        snapshot = engine.maintainer_snapshot(report)
        assert "catalog_score" in snapshot
        assert "worst_rules" in snapshot


# ── Markdown compare coverage (previously untested) ──────────────

class TestMarkdownCompareReport:
    def test_compare_markdown_has_all_sections(self):
        engine = RuleScopeEngine()
        baseline = engine.scan("datasets/regression_demo/baseline")
        candidate = engine.scan("datasets/regression_demo/candidate")
        diff = compare_catalogs(baseline, candidate)
        md = MarkdownReporter().render(diff)

        assert "# RuleScope Compare Report" in md
        assert "## Summary" in md
        assert "Catalog score" in md
        assert "Duplicate pairs" in md

        # Should have takeaways
        if diff.summary.key_takeaways:
            assert "## Takeaways" in md

        # Should have regressions section
        if diff.strongest_regressions:
            assert "## Strongest Regressions" in md
            for reg in diff.strongest_regressions[:2]:
                assert reg.path.split("/")[-1] in md

        # Should have improvements section if any
        if diff.strongest_improvements:
            assert "## Strongest Improvements" in md

    def test_compare_markdown_semantic_changes(self):
        engine = RuleScopeEngine()
        baseline = engine.scan("datasets/regression_demo/baseline")
        candidate = engine.scan("datasets/regression_demo/candidate")
        diff = compare_catalogs(baseline, candidate)
        md = MarkdownReporter().render(diff)

        # Semantic changes should appear as sub-items
        for reg in diff.strongest_regressions:
            if reg.semantic_changes:
                assert reg.semantic_changes[0].summary[:20] in md
                break


# ── i18n ─────────────────────────────────────────────────────────

class TestI18n:
    def setup_method(self):
        set_lang("en")  # Reset to default before each test

    def test_default_language_is_english(self):
        assert get_lang() == "en"

    def test_switch_to_french(self):
        set_lang("fr")
        assert get_lang() == "fr"
        assert t("governance_budget") == "Budget de gouvernance"
        assert t("priority_actions") == "Actions prioritaires"
        assert t("weakest_rules") == "Règles les plus faibles"

    def test_english_strings(self):
        set_lang("en")
        assert t("governance_budget") == "Governance budget"
        assert t("priority_actions") == "Priority actions"
        assert t("weakest_rules") == "Weakest rules"

    def test_unknown_key_returns_key(self):
        assert t("nonexistent_key_xyz") == "nonexistent_key_xyz"

    def test_format_variables(self):
        set_lang("en")
        result = t("invalid_path", label="baseline")
        assert "baseline" in result

    def test_switch_back_and_forth(self):
        set_lang("fr")
        assert "gouvernance" in t("governance_budget").lower()
        set_lang("en")
        assert "governance" in t("governance_budget").lower()

    def test_invalid_lang_falls_back_to_english(self):
        set_lang("xx")
        assert get_lang() == "en"
        assert t("governance_budget") == "Governance budget"

    def test_french_console_strings(self):
        set_lang("fr")
        intro = t("intro_text")
        assert "gouvernance" in intro.lower() or "détection" in intro.lower()
        tips = t("tips_text")
        assert "Utilisez" in tips

    def test_all_keys_have_both_languages(self):
        """Every key in the i18n table must have both en and fr."""
        from rulescope.i18n import STRINGS
        for key, translations in STRINGS.items():
            assert "en" in translations, f"Key '{key}' missing English"
            assert "fr" in translations, f"Key '{key}' missing French"
            assert len(translations["en"]) > 0, f"Key '{key}' has empty English"
            assert len(translations["fr"]) > 0, f"Key '{key}' has empty French"


class TestI18nCLI:
    """Test CLI with --lang flag."""

    def test_scan_french(self):
        from typer.testing import CliRunner
        from rulescope.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["scan", "examples/rules", "--lang", "fr"])
        assert result.exit_code in (0, 1)  # may fail budget
        # French strings should appear
        output = result.output
        assert any(w in output for w in ["Pilier", "Piliers moyens", "Budget de gouvernance", "Actions prioritaires", "gouvernance"])

    def test_scan_english(self):
        from typer.testing import CliRunner
        from rulescope.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["scan", "examples/rules", "--lang", "en"])
        assert result.exit_code in (0, 1)
        output = result.output
        assert "Governance budget" in output or "Average pillars" in output


class TestI18nLocalization:
    """Test localize_finding, localize_report_for_render, and translate_text French paths."""

    def test_localize_finding_french(self):
        from rulescope.i18n import localize_finding, set_lang
        from rulescope.models.finding import Finding
        set_lang("fr")
        try:
            f = Finding(
                code="META-001",
                severity="medium",
                category="metadata",
                message="Rule is missing important metadata fields.",
                recommendation="Populate the missing metadata to improve maintainability and portability.",
                impact="Missing 3 field(s) reduces traceability and automation readiness.",
            )
            localized = localize_finding(f)
            # Should translate the message to French
            assert localized.code == "META-001"
            # Original finding should be unchanged
            assert f.message == "Rule is missing important metadata fields."
        finally:
            set_lang("en")

    def test_localize_finding_english_passthrough(self):
        from rulescope.i18n import localize_finding, set_lang
        from rulescope.models.finding import Finding
        set_lang("en")
        f = Finding(code="META-001", severity="medium", category="metadata", message="Test.")
        result = localize_finding(f)
        assert result is f  # English returns the original object

    def test_translate_text_french_dynamic_patterns(self):
        from rulescope.i18n import translate_text, set_lang
        set_lang("fr")
        try:
            # Test dynamic regex patterns
            assert "Corrigez" in translate_text("Fix 5 invalid or structurally broken rules first.")
            assert "Revoyez" in translate_text("Review 3 duplicate clusters to reduce redundant detections.")
            assert "Ajustez" in translate_text("Tune or narrow 7 high-noise rules before production rollout.")
            assert "Complétez" in translate_text("Complete metadata on 4 weakly documented rules.")
            assert "Durcissez" in translate_text("Harden 2 analytically weak rules before promoting them to production severity.")
            assert "Renforcez" in translate_text("Strengthen fragile ATT&CK coverage in: discovery, execution.")
            assert "Écart" in translate_text("Catalog score delta: +5 points.")
            assert "Régressions" in translate_text("Semantic regressions detected: 3.")
            # Test static translations
            assert "baissé" in translate_text("Quality dropped materially; review the changed rules before merge.")
            # Test passthrough for unknown text
            unknown = "Some completely unknown text for testing."
            assert translate_text(unknown) == unknown
        finally:
            set_lang("en")

    def test_translate_text_english_passthrough(self):
        from rulescope.i18n import translate_text, set_lang
        set_lang("en")
        text = "Fix 5 invalid or structurally broken rules first."
        assert translate_text(text) == text

    def test_localize_report_for_render_french(self):
        from rulescope.i18n import localize_report_for_render, set_lang
        engine = RuleScopeEngine()
        report = engine.scan("examples/rules")
        set_lang("fr")
        try:
            localized = localize_report_for_render(report)
            # Should be a deep copy, not the same object
            assert localized is not report
            assert len(localized.rules) == len(report.rules)
        finally:
            set_lang("en")

    def test_localize_report_for_render_english_passthrough(self):
        from rulescope.i18n import localize_report_for_render, set_lang
        engine = RuleScopeEngine()
        report = engine.scan("examples/rules")
        set_lang("en")
        result = localize_report_for_render(report)
        assert result is report  # English returns the original



    def test_compare_french_labels_and_semantic_text(self):
        from typer.testing import CliRunner
        from rulescope.cli import app
        runner = CliRunner()
        result = runner.invoke(app, ["compare", "datasets/regression_demo/baseline", "datasets/regression_demo/candidate", "--lang", "fr"])
        assert result.exit_code in (0, 1)
        output = result.output
        assert "Métrique" in output
        assert "Réf." in output
        assert "Cand." in output
        assert "Régressions sémantiques" in output
        assert "jokers supplémentaires" in output or "contains" in output or "sélective" in output

    def test_compare_markdown_french(self):
        from rulescope.engine import RuleScopeEngine
        from rulescope.comparison import compare_catalogs
        from rulescope.i18n import set_lang
        from rulescope.reporters.markdown_reporter import MarkdownReporter
        set_lang("fr")
        try:
            engine = RuleScopeEngine()
            diff = compare_catalogs(engine.scan("datasets/regression_demo/baseline"), engine.scan("datasets/regression_demo/candidate"))
            md = MarkdownReporter().render(diff)
            assert "# Rapport de comparaison RuleScope" in md
            assert "## Résumé" in md
            assert "## Points clés" in md
        finally:
            set_lang("en")


def test_catalog_markdown_french_full_headers():
    from rulescope.engine import RuleScopeEngine
    from rulescope.i18n import set_lang
    from rulescope.reporters.markdown_reporter import MarkdownReporter
    set_lang("fr")
    try:
        md = MarkdownReporter().render(RuleScopeEngine().scan("examples/rules"))
        assert "# Rapport RuleScope" in md
        assert "## Résumé du catalogue" in md
        assert "| Métrique | Valeur |" in md
        assert "## Détail des règles" in md
    finally:
        set_lang("en")


def test_benchmark_markdown_french_headers():
    from rulescope.benchmark import run_benchmark, render_benchmark_markdown
    from rulescope.i18n import set_lang
    set_lang("fr")
    try:
        md = render_benchmark_markdown(run_benchmark("examples/rules"))
        assert "# Rapport de benchmark RuleScope" in md
        assert "## Résumé" in md
        assert "| Métrique | Valeur |" in md
        assert "## Répartition des scores" in md
    finally:
        set_lang("en")
