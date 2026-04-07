from __future__ import annotations

"""CLI entry point — interactive console by default, subcommands available.

Running `rulescope` with no arguments launches the interactive console.
Subcommands (scan, compare, explain, report, ci, maintainers, navigator,
watch, benchmark, doctor, version) remain available for scripting, CI,
and testing. Supports --lang en|fr and RULESCOPE_LANG env.
"""

import platform
import shlex
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from rulescope import __version__
from rulescope.comparison import compare_catalogs
from rulescope.config.settings import RuleScopeConfig
from rulescope.engine import RuleScopeEngine
from rulescope.explain import RuleExplainer
from rulescope.i18n import get_lang, init_lang, pillar_label, score_band_label, severity_label, set_lang, t, translate_text
from rulescope.reporters.html_reporter import HtmlReporter
from rulescope.reporters.json_reporter import JsonReporter
from rulescope.reporters.markdown_reporter import MarkdownReporter
from rulescope.reporters.sarif_reporter import SarifReporter
from rulescope.reporters.navigator_export import export_navigator_layer

def _help_text(en: str, fr: str) -> str:
    return f"{en} / {fr}"


def _activate_lang(lang: str | None = None) -> str:
    if not isinstance(lang, str):
        return get_lang()
    return init_lang(lang)


app = typer.Typer(
    name="rulescope",
    help=_help_text(
        "RuleScope — governance engine for detection catalogs. Run without arguments to launch the interactive console.",
        "RuleScope — moteur de gouvernance pour catalogues de détection. Lancez sans argument pour ouvrir la console interactive.",
    ),
    add_completion=False,
    invoke_without_command=True,
)
console = Console()

CATALOG_FORMATS = {"table", "json", "markdown", "html", "sarif"}
COMPARE_FORMATS = {"table", "json", "markdown"}
FORMAT_ALIASES = {"md": "markdown", "htm": "html"}

WELCOME_ART = r"""
██████╗ ██╗   ██╗██╗     ███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██║   ██║██║     ██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝██║   ██║██║     █████╗  ███████╗██║     ██║   ██║██████╔╝█████╗
██╔══██╗██║   ██║██║     ██╔══╝  ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
██║  ██║╚██████╔╝███████╗███████╗███████║╚██████╗╚██████╔╝██║     ███████╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
"""


# ── Default: launch console when no subcommand is given ─────────


@app.callback(invoke_without_command=True)
def default_console(
    ctx: typer.Context,
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    """Launch the interactive RuleScope console (default when no subcommand is given)."""
    init_lang(lang)
    if ctx.invoked_subcommand is None:
        _run_console_loop(config=None, lang=lang, prompt_for_language=lang is None)


# ── Subcommands (available for scripting, CI, and tests) ────────


@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to a Sigma rule file or directory."),
    format: str = typer.Option("table", "--format", "-f", help="Output format: json, markdown, html, sarif, table"),
    output: str | None = typer.Option(None, "--output", "-o", help="Optional output file path."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    top_issues: int = typer.Option(0, "--top-issues", help="Show top findings directly in terminal output."),
    enforce_budget: bool = typer.Option(False, "--enforce-budget", help="Exit non-zero if governance budget fails."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    _run_scan(target=target, format=format, output=output, config=config, top_issues=top_issues, enforce_budget=enforce_budget)


@app.command()
def compare(
    baseline: str = typer.Argument(..., help="Baseline rules path."),
    candidate: str = typer.Argument(..., help="Candidate rules path."),
    format: str = typer.Option("table", "--format", "-f", help="Output format: json, markdown, table"),
    output: str | None = typer.Option(None, "--output", "-o", help="Optional output file path."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    fail_on_regression: bool = typer.Option(False, "--fail-on-regression", help="Exit non-zero when comparison verdict is Regression."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    _run_compare(
        baseline=baseline,
        candidate=candidate,
        format=format,
        output=output,
        config=config,
        fail_on_regression=fail_on_regression,
    )


@app.command()
def explain(
    target: str = typer.Argument(..., help="Path to a Sigma rule file or directory. If a directory is given, the weakest rule is explained."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    all: bool = typer.Option(False, "--all", help="Explain several weak rules instead of only the weakest one."),
    max_rules: int = typer.Option(3, "--max-rules", help="Maximum number of rules to explain when --all is used."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    _run_explain(target=target, config=config, explain_all=all, max_rules=max_rules)


@app.command()
def ci(
    target: str = typer.Argument(..., help="Path to a Sigma rule file or directory."),
    min_score: int = typer.Option(70, "--min-score", help="Minimum acceptable catalog score."),
    max_duplicates: int = typer.Option(999, "--max-duplicates", help="Maximum duplicate pairs allowed."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    format: str = typer.Option("table", "--format", "-f", help="Output format for CI artifact."),
    output: str | None = typer.Option(None, "--output", "-o", help="Optional output file path for CI artifacts."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    _run_ci(target=target, min_score=min_score, max_duplicates=max_duplicates, format=format, output=output, config=config)


@app.command()
def report(
    target: str = typer.Argument(..., help="Path to a Sigma rule file or directory."),
    output: str = typer.Option("rulescope_report.html", "--output", "-o", help="Output file path."),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, markdown, json, sarif"),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    _run_report(target=target, output=output, format=format, config=config)


@app.command(name="maintainers")
def maintainers_cmd(
    target: str = typer.Argument(..., help="Path to a Sigma rule file or directory."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    cfg = _load_config(config)
    _ensure_existing_path(target, "target")
    engine = RuleScopeEngine(config=cfg)
    rpt = engine.scan(target)
    _print_maintainers(engine.maintainer_snapshot(rpt))


@app.command(name="navigator")
def navigator_cmd(
    target: str = typer.Argument(..., help="Path to a Sigma rule file or directory."),
    output: str = typer.Option("rulescope_navigator.json", "--output", "-o", help="Output file path for the Navigator layer."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    """Export an ATT&CK Navigator layer JSON from the scan results."""
    _activate_lang(lang)
    _run_navigator(target=target, output=output, config=config)


@app.command(name="watch")
def watch_cmd(
    target: str = typer.Argument(..., help="Path to a Sigma rule file or directory to watch."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    interval: float = typer.Option(1.0, "--interval", "-i", help="Polling interval in seconds."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    """Watch a file or directory and re-scan on every change."""
    _activate_lang(lang)
    _run_watch(target=target, interval=interval, config=config)


@app.command(name="benchmark")
def benchmark_cmd(
    target: str = typer.Argument(..., help="Path to a Sigma rule catalog to benchmark."),
    output: str = typer.Option("rulescope_benchmark.md", "--output", "-o", help="Output file path."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    """Benchmark RuleScope against a real Sigma catalog and report performance."""
    _activate_lang(lang)
    _run_benchmark(target=target, output=output, config=config)


@app.command(name="doctor")
def doctor_cmd(
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    _run_doctor()


@app.command(name="console")
def console_cmd(
    config: str | None = typer.Option(None, "--config", "-c", help="Path to .rulescope.yml config file."),
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    """Explicitly launch the interactive RuleScope console."""
    _activate_lang(lang)
    _run_console_loop(config=config, lang=lang, prompt_for_language=lang is None)


@app.command(name="version")
def version_cmd(
    lang: str | None = typer.Option(None, "--lang", help=_help_text("Language: en or fr.", "Langue : en ou fr.")),
) -> None:
    _activate_lang(lang)
    console.print(f"[bold]RuleScope[/bold] {__version__}")


def _prompt_for_language() -> None:
    console.print(
        Panel(
            t("language_prompt_body"),
            title=f"[bold]{t('language_prompt_title')}[/bold]",
            border_style="bright_blue",
            expand=False,
        )
    )
    choice = Prompt.ask(
        f"[bold cyan]{t('language_prompt')}[/bold cyan]",
        choices=["1", "2", "en", "fr", ""],
        default="",
    )
    normalized = choice.lower().strip()
    if normalized in {"2", "fr"}:
        set_lang("fr")
        console.print(f"[green]{t('language_selected_fr')}[/green]")
    else:
        set_lang("en")
        console.print(f"[green]{t('language_selected_en')}[/green]")
    console.print()


# ── Console interactive loop ────────────────────────────────────


def _run_console_loop(config: str | None = None, lang: str | None = None, prompt_for_language: bool = False) -> None:
    if lang:
        set_lang(lang)
    elif prompt_for_language:
        _prompt_for_language()
    _print_console_home()
    current_config = config
    while True:
        try:
            raw = Prompt.ask("[bold cyan]rulescope[/bold cyan][white]>[/white]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print(f"\n[dim]{t('exiting_console')}[/dim]")
            raise typer.Exit() from None
        if not raw:
            continue
        if raw.startswith("/"):
            raw = raw[1:]
        if raw in {"exit", "quit"}:
            console.print(f"[dim]{t('exiting_console')}[/dim]")
            break
        if raw == "clear":
            console.clear()
            _print_console_home()
            continue
        if raw in {"help", "?"}:
            _print_console_commands()
            continue
        if raw == "intro":
            console.print(Panel(t("intro_text"), title=f"[bold]{t('introduce_yourself')}[/bold]", border_style="bright_blue"))
            continue
        if raw == "tips":
            console.print(Panel(t("tips_text"), title=f"[bold]{t('tips')}[/bold]", border_style="bright_blue"))
            continue
        if raw.startswith("lang "):
            new_lang = raw.split(" ", 1)[1].strip().lower()
            set_lang(new_lang)
            console.print(f"[green]{t('lang_switched_fr' if get_lang() == 'fr' else 'lang_switched_en')}[/green]")
            console.print(f"[dim]{t('redrawing_interface')}[/dim]")
            console.clear()
            _print_console_home()
            continue
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            console.print(f"[red]Invalid command:[/red] {exc}")
            continue
        if not parts:
            continue
        command, *args = parts
        try:
            _dispatch_console_command(command, args, current_config)
        except typer.Exit as exc:
            if exc.exit_code not in (0, None):
                console.print(f"[red]Command exited with code {exc.exit_code}.[/red]")
        except Exception as exc:  # pragma: no cover - interactive safeguard
            console.print(f"[red]Command failed:[/red] {exc}")


def _dispatch_console_command(command: str, args: list[str], config: str | None) -> None:
    if command == "scan":
        if not args:
            console.print("[yellow]Usage:[/yellow] scan <path> [--top-issues N] [--format FORMAT] [--output FILE]")
            return
        target = args[0]
        top_issues = _extract_int_option(args[1:], "--top-issues", 0)
        fmt = _extract_str_option(args[1:], "--format", "table", "-f")
        output = _extract_str_option(args[1:], "--output", None, "-o")
        enforce_budget = "--enforce-budget" in args[1:]
        _run_scan(target=target, format=fmt, output=output, config=config, top_issues=top_issues, enforce_budget=enforce_budget)
        return
    if command == "compare":
        if len(args) < 2:
            console.print("[yellow]Usage:[/yellow] compare <baseline> <candidate> [--fail-on-regression]")
            return
        fmt = _extract_str_option(args[2:], "--format", "table", "-f")
        output = _extract_str_option(args[2:], "--output", None, "-o")
        _run_compare(
            baseline=args[0],
            candidate=args[1],
            format=fmt,
            output=output,
            config=config,
            fail_on_regression="--fail-on-regression" in args[2:],
        )
        return
    if command == "explain":
        if not args:
            console.print("[yellow]Usage:[/yellow] explain <rule-or-folder> [--all] [--max-rules N]")
            return
        explain_all = "--all" in args[1:]
        max_rules = _extract_int_option(args[1:], "--max-rules", 3)
        _run_explain(target=args[0], config=config, explain_all=explain_all, max_rules=max_rules)
        return
    if command == "report":
        if not args:
            console.print("[yellow]Usage:[/yellow] report <path> [--output FILE] [--format FORMAT]")
            return
        output = _extract_str_option(args[1:], "--output", "rulescope_report.html", "-o")
        fmt = _extract_str_option(args[1:], "--format", "html", "-f")
        _run_report(target=args[0], output=output, format=fmt, config=config)
        return
    if command == "ci":
        if not args:
            console.print("[yellow]Usage:[/yellow] ci <path> [--min-score N] [--max-duplicates N] [--format FORMAT] [--output FILE]")
            return
        _run_ci(
            target=args[0],
            min_score=_extract_int_option(args[1:], "--min-score", 70),
            max_duplicates=_extract_int_option(args[1:], "--max-duplicates", 999),
            format=_extract_str_option(args[1:], "--format", "table", "-f"),
            output=_extract_str_option(args[1:], "--output", None, "-o"),
            config=config,
        )
        return
    if command == "version":
        version_cmd()
        return
    if command == "maintainers":
        if not args:
            console.print("[yellow]Usage:[/yellow] maintainers <path>")
            return
        maintainers_cmd(target=args[0], config=config)
        return
    if command == "doctor":
        doctor_cmd()
        return
    if command == "navigator":
        if not args:
            console.print("[yellow]Usage:[/yellow] navigator <path> [--output FILE]")
            return
        output = _extract_str_option(args[1:], "--output", "rulescope_navigator.json", "-o")
        _run_navigator(target=args[0], output=output, config=config)
        return
    if command == "watch":
        if not args:
            console.print("[yellow]Usage:[/yellow] watch <path> [--interval N]")
            return
        interval = float(_extract_str_option(args[1:], "--interval", "1.0", "-i") or "1.0")
        _run_watch(target=args[0], interval=interval, config=config)
        return
    if command == "benchmark":
        if not args:
            console.print(f"[yellow]{t('benchmark_usage')}[/yellow]")
            return
        output = _extract_str_option(args[1:], "--output", "rulescope_benchmark.md", "-o")
        _run_benchmark(target=args[0], output=output, config=config)
        return
    console.print(f"[red]{t('unknown_command')}:[/red] {command}. {t('unknown_shell_hint')}")


# ── Option parsing helpers ──────────────────────────────────────


def _extract_str_option(args: list[str], option: str, default: str | None, *aliases: str) -> str | None:
    names = (option, *aliases)
    for index, value in enumerate(args):
        if value in names and index + 1 < len(args):
            return args[index + 1]
        for name in names:
            if value.startswith(f"{name}="):
                return value.split("=", 1)[1]
    return default


def _extract_int_option(args: list[str], option: str, default: int) -> int:
    value = _extract_str_option(args, option, None)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


# ── Command implementations ─────────────────────────────────────


def _run_scan(
    target: str,
    format: str = "table",
    output: str | None = None,
    config: str | None = None,
    top_issues: int = 0,
    enforce_budget: bool = False,
) -> None:
    cfg = _load_config(config)
    _ensure_existing_path(target, "target")
    fmt = _validate_catalog_format(format)
    engine = RuleScopeEngine(config=cfg)
    rpt = engine.scan(target)
    if fmt == "table":
        _print_dashboard(rpt, engine=engine, top_issues=top_issues)
        if enforce_budget and not rpt.summary.budget_result.passed:
            raise typer.Exit(code=1)
        return
    rendered = _render_catalog(rpt, fmt)
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
        console.print(f"[green]{t('report_written_to')}[/green] {output}")
    else:
        if fmt == "json":
            print(rendered)
        else:
            console.print(rendered)
    if enforce_budget and not rpt.summary.budget_result.passed:
        raise typer.Exit(code=1)


def _run_compare(
    baseline: str,
    candidate: str,
    format: str = "table",
    output: str | None = None,
    config: str | None = None,
    fail_on_regression: bool = False,
) -> None:
    cfg = _load_config(config)
    _ensure_existing_path(baseline, "baseline")
    _ensure_existing_path(candidate, "candidate")
    fmt = _validate_compare_format(format)
    engine = RuleScopeEngine(config=cfg)
    diff = compare_catalogs(engine.scan(baseline), engine.scan(candidate))
    if fmt == "table":
        _print_compare(diff)
        if fail_on_regression and diff.summary.summary_verdict == "Regression":
            raise typer.Exit(code=1)
        return
    rendered = _render_compare(diff, fmt)
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
        console.print(f"[green]{t('compare_report_written_to')}[/green] {output}")
    else:
        if fmt == "json":
            print(rendered)
        else:
            console.print(rendered)
    if fail_on_regression and diff.summary.summary_verdict == "Regression":
        raise typer.Exit(code=1)


def _run_explain(target: str, config: str | None = None, explain_all: bool = False, max_rules: int = 3) -> None:
    cfg = _load_config(config)
    path = _ensure_existing_path(target, "target")
    rpt = RuleScopeEngine(config=cfg).scan(target)
    if not rpt.rules:
        console.print(f"[red]{t('no_rules_found')}[/red]")
        raise typer.Exit(code=1)
    sorted_rules = sorted(rpt.rules, key=lambda item: item.scores.overall)
    explainer = RuleExplainer()
    selected = sorted_rules[: max(1, max_rules)] if explain_all else [sorted_rules[0]]

    if path.is_dir() and explain_all:
        scope_text = t("explain_scope_all", count=len(selected), total=len(sorted_rules))
    elif path.is_dir():
        scope_text = t("explain_scope_single", total=len(sorted_rules))
    else:
        scope_text = t("explain_scope_file")
    console.print(Panel(scope_text, title=f"[bold]{t('explain_scope_title')}[/bold]", border_style="cyan"))

    for index, rule in enumerate(selected, start=1):
        if explain_all:
            title = t("explain_panel_title_all", index=index, total=len(selected))
        else:
            title = t("explain_panel_title_single")
        console.print(Panel(explainer.explain(rule), title=f"[bold]{title}[/bold]", border_style="bright_blue"))


def _run_report(target: str, output: str, format: str, config: str | None) -> None:
    cfg = _load_config(config)
    _ensure_existing_path(target, "target")
    _validate_catalog_format(format)
    catalog_report = RuleScopeEngine(config=cfg).scan(target)
    Path(output).write_text(_render_catalog(catalog_report, format.lower().strip()), encoding="utf-8")
    console.print(f"[green]{t('report_written_to')}[/green] {output}")
    console.print(
        f"[dim]{t('report_summary_line', total=catalog_report.summary.total_rules, score=catalog_report.summary.average_score, band=score_band_label(catalog_report.summary.score_band))}[/dim]"
    )


def _run_ci(
    target: str,
    min_score: int = 70,
    max_duplicates: int = 999,
    format: str = "table",
    output: str | None = None,
    config: str | None = None,
) -> None:
    cfg = _load_config(config)
    _ensure_existing_path(target, "target")
    fmt = _validate_catalog_format(format)
    engine = RuleScopeEngine(config=cfg)
    rpt = engine.scan(target)
    failures = []
    if rpt.summary.average_score < min_score:
        failures.append(f"Catalog score {rpt.summary.average_score} < threshold {min_score}")
    if rpt.summary.duplicate_pairs > max_duplicates:
        failures.append(f"Duplicate pairs {rpt.summary.duplicate_pairs} > limit {max_duplicates}")
    if rpt.summary.invalid_rules > cfg.ci_gate.max_invalid_rules:
        failures.append(f"Invalid rules {rpt.summary.invalid_rules} > limit {cfg.ci_gate.max_invalid_rules}")

    if fmt == "json" and output is None:
        print(_render_catalog(rpt, "json"))
        raise typer.Exit(code=1 if failures else 0)

    _print_dashboard(rpt, engine=engine)
    if output:
        out_fmt = "json" if fmt == "table" else fmt
        Path(output).write_text(_render_catalog(rpt, out_fmt), encoding="utf-8")
        console.print(f"[dim]{t('report_exported_to')} {output}[/dim]")
    if failures:
        console.print()
        for failure in failures:
            console.print(f"[red]{t('gate_fail')}:[/red] {failure}")
        raise typer.Exit(code=1)
    console.print(f"\n[green]{t('all_gates_passed')}[/green]")


def _run_navigator(target: str, output: str, config: str | None) -> None:
    cfg = _load_config(config)
    _ensure_existing_path(target, "target")
    engine = RuleScopeEngine(config=cfg)
    catalog_report = engine.scan(target)
    layer_json = export_navigator_layer(catalog_report)
    Path(output).write_text(layer_json, encoding="utf-8")
    console.print(f"[green]{t('navigator_written_to')}[/green] {output}")
    console.print(
        f"[dim]{t('navigator_summary_line', total=catalog_report.summary.total_rules, mapped=sum(1 for r in catalog_report.rules if r.attack_techniques))}[/dim]"
    )


def _run_watch(target: str, interval: float, config: str | None) -> None:
    cfg = _load_config(config)
    _ensure_existing_path(target, "target")
    from rulescope.watcher import run_watch
    run_watch(target=target, config=cfg, interval=interval)


def _run_benchmark(target: str, output: str, config: str | None) -> None:
    cfg = _load_config(config)
    _ensure_existing_path(target, "target")
    from rulescope.benchmark import run_benchmark, render_benchmark_markdown

    console.print(f"[bold]{t('benchmark_running')}[/bold] {target}...")
    result = run_benchmark(target, config=cfg)
    md = render_benchmark_markdown(result)
    Path(output).write_text(md, encoding="utf-8")
    console.print(f"[green]{t('report_written_to')}[/green] {output}")
    console.print(f"[dim]{_benchmark_summary_text(result.total_files, result.parsed_ok, result.parse_failures, result.total_time_ms, result.rules_per_second)}[/dim]")


def _run_doctor() -> None:
    table = Table(title=t("doctor_title"), header_style="bold bright_cyan", box=None)
    table.add_column(t("item"), style="cyan")
    table.add_column(t("value"), style="white")
    table.add_row(t("rulescope_version"), __version__)
    table.add_row("Python", sys.version.split()[0])
    table.add_row("Executable", sys.executable)
    table.add_row(t("platform"), platform.platform())
    console.print(table)


# ── Config and validation helpers ───────────────────────────────


def _load_config(config: str | None) -> RuleScopeConfig:
    if config is not None and not Path(config).is_file():
        console.print(f"[red]{t('config_error')}:[/red] file not found: {config}")
        raise typer.Exit(code=2)
    try:
        return RuleScopeConfig.load(config)
    except ValueError as exc:
        console.print(f"[red]{t('config_error')}:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _benchmark_summary_text(total: int, parsed: int, failures: int, time_ms: float, rate: float) -> str:
    if get_lang() == "fr":
        fichier = "fichier" if total == 1 else "fichiers"
        analyse = "analysé" if parsed == 1 else "analysés"
        echec = "échec" if failures == 1 else "échecs"
        return f"{total} {fichier}, {parsed} {analyse}, {failures} {echec}, {time_ms} ms au total, {rate} règles/s"
    file_word = "file" if total == 1 else "files"
    failure_word = "failure" if failures == 1 else "failures"
    return f"{total} {file_word}, {parsed} parsed, {failures} {failure_word}, {time_ms}ms total, {rate} rules/sec"


def _ensure_existing_path(path_value: str, label: str) -> Path:
    path = Path(path_value)
    if not path.exists():
        console.print(f"[red]{t('invalid_path', label=label)}:[/red] {path_value}")
        raise typer.Exit(code=2)
    return path


def _validate_catalog_format(fmt: str) -> str:
    normalized = FORMAT_ALIASES.get(fmt.lower().strip(), fmt.lower().strip())
    if normalized not in CATALOG_FORMATS:
        console.print(f"[red]{t('unsupported_format')}:[/red] {fmt}. Choose one of: {', '.join(sorted(CATALOG_FORMATS))}.")
        raise typer.Exit(code=2)
    return normalized


def _validate_compare_format(fmt: str) -> str:
    normalized = FORMAT_ALIASES.get(fmt.lower().strip(), fmt.lower().strip())
    if normalized not in COMPARE_FORMATS:
        console.print(f"[red]{t('unsupported_compare_format')}:[/red] {fmt}. Choose one of: {', ' .join(sorted(COMPARE_FORMATS))}.")
        raise typer.Exit(code=2)
    return normalized


# ── Renderers ───────────────────────────────────────────────────


def _render_catalog(report: Any, fmt: str) -> str:
    if fmt == "json":
        return JsonReporter().render(report)
    if fmt == "html":
        return HtmlReporter().render(report)
    if fmt == "sarif":
        return SarifReporter().render(report)
    return MarkdownReporter().render(report)


def _render_compare(report: Any, fmt: str) -> str:
    if fmt == "json":
        return JsonReporter().render(report)
    return MarkdownReporter().render(report)


# ── Console UI ──────────────────────────────────────────────────


def _print_console_home() -> None:
    console.print(f"[bold bright_cyan]{t('welcome_banner')}\n{WELCOME_ART}[/bold bright_cyan]")
    console.print(
        Panel(
            t("did_you_know"),
            border_style="white",
            expand=False,
        )
    )
    console.print(t("console_help"))
    console.print()
    console.print(Panel(t("intro_text"), title=f"[bold]{t('introduce_yourself')}[/bold]", border_style="bright_blue"))


def _print_console_commands() -> None:
    table = Table(title=t("console_commands_title"), header_style="bold bright_cyan", box=None)
    table.add_column(t("command"), style="cyan")
    table.add_column(t("purpose"), style="white")
    table.add_row("scan <path> [--top-issues N]", t("cmd_scan"))
    table.add_row("explain <rule-or-folder> [--all]", t("cmd_explain"))
    table.add_row("compare <baseline> <candidate>", t("cmd_compare"))
    table.add_row("report <path> --output report.html", t("cmd_report"))
    table.add_row("ci <path> [--min-score N]", t("cmd_ci"))
    table.add_row("maintainers <path>", t("cmd_maintainers"))
    table.add_row("navigator <path> --output layer.json", t("cmd_navigator"))
    table.add_row("watch <path> [--interval N]", t("cmd_watch"))
    table.add_row("benchmark <path> [--output FILE]", t("cmd_benchmark"))
    table.add_row("doctor", t("cmd_doctor"))
    table.add_row("version", t("cmd_version"))
    table.add_row("/lang en|fr", t("cmd_lang"))
    table.add_row("/intro", t("product_overview"))
    table.add_row("/tips", t("tips"))
    table.add_row("/clear", t("clear"))
    table.add_row("/exit", t("quit"))
    console.print(table)


# ── Dashboard / print functions ─────────────────────────────────


def _print_dashboard(report, engine: RuleScopeEngine, top_issues: int = 0) -> None:
    s = report.summary
    band_color = "green" if s.average_score >= 75 else "yellow" if s.average_score >= 50 else "red"
    console.print(
        Panel(
            f"[bold {band_color}]{s.average_score}/100[/bold {band_color}] {score_band_label(s.score_band)}\n"
            f"[dim]{t('target')}: {report.target} | {s.total_rules} {t('rules_analyzed')} | {t('median')} {s.median_score}[/dim]",
            title="[bold]RuleScope[/bold]",
            border_style="bright_blue",
        )
    )

    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column(t("metric"), style="dim")
    table.add_column(t("value"), justify="right")
    table.add_row(t("duplicate_pairs"), str(s.duplicate_pairs))
    table.add_row(t("overlap_pairs"), str(s.overlap_pairs))
    table.add_row(t("high_noise_rules"), str(s.high_noise_rules))
    table.add_row(t("weak_metadata"), str(s.weak_metadata_rules))
    table.add_row(t("weak_rules"), str(s.weak_rules))
    table.add_row(t("invalid_rules"), str(s.invalid_rules))
    table.add_row(t("total_findings"), str(s.debt.total_findings))
    console.print(table)

    pillars = Table(title=t("average_pillars"), show_header=True, header_style="bold magenta", box=None)
    pillars.add_column(t("pillar"))
    pillars.add_column(t("score"), justify="right")
    for name, value in s.average_pillars.model_dump().items():
        pillars.add_row(pillar_label(name), str(value))
    console.print(pillars)

    budget = s.budget_result
    budget_text = t("budget_passed") if budget.passed else t("budget_failed")
    budget_color = "green" if budget.passed else "red"
    console.print(f"\n[bold]{t('governance_budget')}:[/bold] [{budget_color}]{budget_text}[/{budget_color}]")
    if budget.failures:
        for failure in budget.failures:
            console.print(f"  [red]-[/red] {failure}")

    if s.priority_actions:
        console.print(f"\n[bold]{t('priority_actions')}:[/bold]")
        for action in s.priority_actions:
            console.print(f"  [yellow]-[/yellow] {translate_text(action)}")

    if s.top_weakest:
        console.print(f"\n[bold]{t('weakest_rules')}:[/bold]")
        for item in s.top_weakest[:5]:
            console.print(f"  [bright_red]-[/bright_red] {item}")

    if s.debt.top_recommendations:
        console.print(f"\n[bold]{t('most_frequent_remediations')}:[/bold]")
        for rec in s.debt.top_recommendations[:5]:
            console.print(f"  [cyan]-[/cyan] {translate_text(rec.recommendation)} ({rec.count})")

    if top_issues > 0:
        console.print(f"\n[bold]{t('top_issues')}:[/bold]")
        for title, code, message, severity in engine.get_top_issues(report, limit=top_issues):
            sev = severity.upper() if get_lang() == "en" else severity_label(severity).upper()
            console.print(f"  [{_severity_color(severity)}]-[/] {sev} {code} · {title} · {translate_text(message)}")


def _print_compare(report) -> None:
    s = report.summary
    color = "green" if s.summary_verdict == "Improved" else "red" if s.summary_verdict == "Regression" else "yellow"
    console.print(
        Panel(
            f"[bold {color}]{s.summary_verdict}[/bold {color}]\n"
            f"[dim]{s.baseline_target} -> {s.candidate_target}[/dim]",
            title=f"[bold]{'Comparaison RuleScope' if get_lang() == 'fr' else 'RuleScope Compare'}[/bold]",
            border_style="bright_blue",
        )
    )
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column(t("metric"))
    table.add_column(t("value"), justify="right")
    table.add_row(t("compare_score_delta"), f"{s.score_delta:+d}")
    table.add_row(t("compare_duplicate_delta"), f"{s.duplicate_delta:+d}")
    table.add_row(t("compare_overlap_delta"), f"{s.overlap_delta:+d}")
    table.add_row(t("compare_weak_rule_delta"), f"{s.weak_rule_delta:+d}")
    table.add_row(t("compare_changed_rules"), str(s.changed_rules))
    table.add_row(t("compare_improved_rules"), str(s.improved_rules))
    table.add_row(t("compare_regressed_rules"), str(s.regressed_rules))
    table.add_row(t("compare_semantic_regressions"), str(s.semantic_regressions))
    table.add_row(t("compare_semantic_improvements"), str(s.semantic_improvements))
    table.add_row(t("compare_new_critical"), str(s.introduced_critical_findings))
    console.print(table)
    if s.key_takeaways:
        console.print(f"\n[bold]{t('takeaways')}:[/bold]")
        for item in s.key_takeaways:
            console.print(f"  [cyan]-[/cyan] {translate_text(item)}")
    if report.strongest_regressions:
        reg = Table(title=t("strongest_regressions"), header_style="bold bright_red", box=None)
        reg.add_column(t("rule"), style="white")
        reg.add_column(t("baseline_short"), justify="right")
        reg.add_column(t("candidate_short"), justify="right")
        reg.add_column(t("delta"), justify="right")
        for item in report.strongest_regressions[:5]:
            reg.add_row(item.title or item.path, str(item.baseline_score), str(item.candidate_score), f"{item.delta:+d}")
        console.print(reg)
        for item in report.strongest_regressions[:3]:
            if item.semantic_changes:
                console.print(f"[bold red]{item.title or item.path}[/bold red]")
                for change in item.semantic_changes[:3]:
                    detail = f" · {change.detail}" if change.detail else ""
                    console.print(f"  [red]-[/red] {translate_text(change.summary)}{detail}")
    if report.strongest_improvements:
        imp = Table(title=t("strongest_improvements"), header_style="bold green", box=None)
        imp.add_column(t("rule"), style="white")
        imp.add_column(t("baseline_short"), justify="right")
        imp.add_column(t("candidate_short"), justify="right")
        imp.add_column(t("delta"), justify="right")
        for item in report.strongest_improvements[:5]:
            imp.add_row(item.title or item.path, str(item.baseline_score), str(item.candidate_score), f"{item.delta:+d}")
        console.print(imp)


def _print_maintainers(snapshot: dict[str, Any]) -> None:
    console.print(
        Panel(
            f"[bold bright_cyan]{t('catalog_governance_view')}[/bold bright_cyan]\n"
            f"[dim]Score {snapshot['catalog_score']}/100 | {snapshot['rules']} {t('rules_analyzed')}[/dim]",
            title="[bold]RuleScope Maintainers[/bold]",
            border_style="bright_blue",
        )
    )
    hotspots = Table(title=t("worst_rules"), header_style="bold bright_red", box=None)
    is_fr = get_lang() == "fr"
    hotspots.add_column("Règle" if is_fr else "Rule")
    hotspots.add_column(t("score"), justify="right")
    hotspots.add_column("Constats" if is_fr else "Findings", justify="right")
    hotspots.add_column("Catégories" if is_fr else "Categories")
    for item in snapshot["worst_rules"]:
        hotspots.add_row(item["title"], str(item["score"]), str(item["findings"]), ", ".join(item["top_categories"]))
    console.print(hotspots)

    categories = Table(title=t("category_hotspots"), header_style="bold magenta", box=None)
    categories.add_column("Catégorie" if is_fr else "Category")
    categories.add_column("Nombre" if is_fr else "Count", justify="right")
    categories.add_column("Critique" if is_fr else "Critical", justify="right")
    categories.add_column("Élevé" if is_fr else "High", justify="right")
    for item in snapshot["category_hotspots"]:
        categories.add_row(item["category"], str(item["count"]), str(item["critical"]), str(item["high"]))
    console.print(categories)

    logsources = Table(title=t("logsource_hotspots"), header_style="bold yellow", box=None)
    logsources.add_column("Logsource")
    logsources.add_column("Règles" if is_fr else "Rules", justify="right")
    logsources.add_column("Score moy." if is_fr else "Avg score", justify="right")
    logsources.add_column("Pire" if is_fr else "Worst", justify="right")
    for item in snapshot["worst_logsources"]:
        logsources.add_row(item["segment"], str(item["rule_count"]), str(item["average_score"]), str(item["worst_score"]))
    console.print(logsources)

    if snapshot["top_recommendations"]:
        console.print(f"\n[bold]{t('top_recurring_actions')}:[/bold]")
        for item in snapshot["top_recommendations"]:
            console.print(f"  [cyan]-[/cyan] {item['recommendation']} ({item['count']})")


def _severity_color(severity: str) -> str:
    return {
        "critical": "bright_red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "white",
    }.get(severity, "white")


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
