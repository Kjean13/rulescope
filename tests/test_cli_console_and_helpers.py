from __future__ import annotations


import pytest
from typer.testing import CliRunner

from rulescope.cli import (
    _extract_int_option,
    _extract_str_option,
    _render_catalog,
    _render_compare,
    _severity_color,
    app,
)
from rulescope.comparison import compare_catalogs
from rulescope.config.settings import RuleScopeConfig
from rulescope.engine import RuleScopeEngine

runner = CliRunner()


def test_console_help_and_exit() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="/help\n/exit\n")
    assert result.exit_code == 0
    assert "RuleScope Console Commands" in result.stdout
    assert "Exiting RuleScope console" in result.stdout


def test_console_runs_intro_and_tips() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="/intro\n/tips\n/exit\n")
    assert result.exit_code == 0
    assert "governance console for detection rules" in result.stdout
    assert "Console tips" in result.stdout


def test_extract_option_helpers() -> None:
    args = ["--format", "json", "--top-issues=5"]
    assert _extract_str_option(args, "--format", "table") == "json"
    assert _extract_int_option(args, "--top-issues", 0) == 5
    assert _extract_int_option(["--top-issues", "oops"], "--top-issues", 3) == 3


def test_renderers_and_severity_color() -> None:
    engine = RuleScopeEngine(config=RuleScopeConfig())
    catalog = engine.scan("datasets/regression_demo/candidate")
    compare = compare_catalogs(engine.scan("datasets/regression_demo/baseline"), catalog)
    assert '"summary"' in _render_catalog(catalog, "json")
    assert "<html" in _render_catalog(catalog, "html").lower()
    assert "runs" not in _render_catalog(catalog, "markdown").lower()
    assert '"runs"' not in _render_compare(compare, "json")
    assert _severity_color("critical") == "bright_red"
    assert _severity_color("unknown") == "white"


@pytest.mark.parametrize("command", [["maintainers", "datasets/medium_realistic"], ["doctor"], ["ci", "datasets/regression_demo/baseline", "--min-score", "10"]])
def test_additional_commands_execute(command: list[str]) -> None:
    result = runner.invoke(app, command)
    assert result.exit_code == 0


def test_console_lang_switch() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="lang fr\nlang en\n/exit\n")
    assert result.exit_code == 0
    assert "Language switched" in result.stdout or "Langue changée" in result.stdout


def test_console_version_and_doctor() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="version\ndoctor\n/exit\n")
    assert result.exit_code == 0
    assert "RuleScope" in result.stdout


def test_console_unknown_command() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="notacommand\n/exit\n")
    assert result.exit_code == 0
    assert "Unknown command" in result.stdout or "Commande inconnue" in result.stdout


def test_console_scan_dispatch() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="scan examples/rules --top-issues 3\n/exit\n")
    assert result.exit_code == 0
    assert "RuleScope" in result.stdout


def test_console_explain_dispatch() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="explain examples/rules\n/exit\n")
    assert result.exit_code == 0
    assert "Explain" in result.stdout or "Rule:" in result.stdout


def test_console_compare_dispatch() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="compare datasets/regression_demo/baseline datasets/regression_demo/candidate\n/exit\n")
    assert result.exit_code == 0
    assert "Compare" in result.stdout or "Verdict" in result.stdout or "delta" in result.stdout.lower()


def test_console_navigator_dispatch(tmp_path) -> None:
    out = tmp_path / "nav.json"
    result = runner.invoke(app, ["console", "--lang", "en"], input=f"navigator examples/rules --output {out}\n/exit\n")
    assert result.exit_code == 0


def test_console_report_dispatch(tmp_path) -> None:
    out = tmp_path / "report.html"
    result = runner.invoke(app, ["console", "--lang", "en"], input=f"report examples/rules --output {out}\n/exit\n")
    assert result.exit_code == 0


def test_console_missing_args_shows_usage() -> None:
    result = runner.invoke(app, ["console", "--lang", "en"], input="scan\nexplain\ncompare\nreport\nci\nmaintainers\nnavigator\nwatch\nbenchmark\n/exit\n")
    assert result.exit_code == 0
    # Each no-arg command should show usage
    assert result.stdout.count("Usage:") >= 5
