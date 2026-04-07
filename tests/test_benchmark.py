"""Tests for the benchmark module."""
from __future__ import annotations


from typer.testing import CliRunner

from rulescope.benchmark import run_benchmark, render_benchmark_markdown
from rulescope.cli import app
from rulescope.i18n import set_lang

runner = CliRunner()


class TestBenchmarkModule:
    def setup_method(self):
        set_lang("en")

    def test_benchmark_examples(self):
        result = run_benchmark("examples/rules")
        assert result.total_files >= 7
        assert result.parsed_ok >= 6
        assert result.total_time_ms > 0
        assert result.rules_per_second > 0
        assert result.average_score > 0
        assert sum(result.score_distribution.values()) == result.total_files
        assert len(result.finding_distribution) >= 1

    def test_benchmark_correlation(self):
        result = run_benchmark("examples/correlation")
        assert result.total_files == 2
        assert result.correlation_rules >= 1

    def test_benchmark_empty(self, tmp_path):
        result = run_benchmark(str(tmp_path))
        assert result.total_files == 0
        assert result.total_time_ms == 0
        assert result.rules_per_second == 0

    def test_benchmark_markdown_render(self):
        result = run_benchmark("examples/rules")
        md = render_benchmark_markdown(result)
        assert "# RuleScope Benchmark Report" in md
        assert "Performance" in md
        assert "Score Distribution" in md
        assert "rules/sec" in md.lower() or "Rules/second" in md
        assert str(result.total_files) in md
        assert "Finding Distribution" in md

    def test_benchmark_markdown_has_logsources(self):
        result = run_benchmark("examples/rules")
        md = render_benchmark_markdown(result)
        assert "Top Logsources" in md

    def test_benchmark_with_failures(self):
        result = run_benchmark("examples/rules")
        if result.parse_failures > 0:
            assert len(result.top_failure_reasons) >= 1


class TestBenchmarkCLI:
    def setup_method(self):
        set_lang("en")

    def test_benchmark_command(self, tmp_path):
        out = tmp_path / "bench.md"
        result = runner.invoke(app, ["benchmark", "examples/rules", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        md = out.read_text()
        assert "RuleScope Benchmark" in md

    def test_benchmark_invalid_path(self):
        result = runner.invoke(app, ["benchmark", "/nonexistent"])
        assert result.exit_code != 0

    def test_benchmark_console_dispatch_no_args(self):
        from rulescope.cli import _dispatch_console_command
        _dispatch_console_command("benchmark", [], None)
