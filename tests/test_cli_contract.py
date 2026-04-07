from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from rulescope.cli import app

runner = CliRunner()


def test_scan_invalid_path_returns_2() -> None:
    result = runner.invoke(app, ["scan", "./does-not-exist"])
    assert result.exit_code == 2
    assert "Invalid target path" in result.stdout


def test_compare_invalid_format_returns_2() -> None:
    result = runner.invoke(
        app,
        [
            "compare",
            "datasets/regression_demo/baseline",
            "datasets/regression_demo/candidate",
            "--format",
            "html",
        ],
    )
    assert result.exit_code == 2
    assert "Unsupported compare format" in result.stdout


def test_scan_json_output_writes_file(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", "datasets/medium_realistic", "--format", "json", "--output", str(output)],
    )
    assert result.exit_code == 0
    assert output.exists()
    assert '"summary"' in output.read_text(encoding="utf-8")


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "RuleScope" in result.stdout
