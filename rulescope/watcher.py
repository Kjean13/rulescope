from __future__ import annotations

"""Compact file watcher for iterative rule development.

Polls YAML targets for changes and re-runs the scan with a compact,
stable terminal display focused on score deltas and actionable metrics.
"""

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from rulescope.config.settings import RuleScopeConfig
from rulescope.engine import RuleScopeEngine
from rulescope.i18n import t, translate_text

console = Console()


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    size: int
    mtime_ns: int
    digest: str


def _iter_watch_targets(root: Path) -> list[Path]:
    if root.is_dir():
        return [
            path
            for path in sorted(root.rglob("*"))
            if path.is_file() and path.suffix.lower() in (".yml", ".yaml")
        ]
    return [root]


def _digest_file(path: Path) -> str:
    hasher = hashlib.sha1()
    hasher.update(path.read_bytes())
    return hasher.hexdigest()


def _collect_watch_snapshot(root: Path) -> tuple[FileSnapshot, ...]:
    snapshots: list[FileSnapshot] = []
    for path in _iter_watch_targets(root):
        try:
            stat = path.stat()
            snapshots.append(
                FileSnapshot(
                    path=str(path.resolve()),
                    size=stat.st_size,
                    mtime_ns=stat.st_mtime_ns,
                    digest=_digest_file(path),
                )
            )
        except OSError:
            continue
    return tuple(snapshots)


def _hash_files(root: Path) -> str:
    hasher = hashlib.md5()
    for snapshot in _collect_watch_snapshot(root):
        hasher.update(snapshot.path.encode())
        hasher.update(str(snapshot.size).encode())
        hasher.update(str(snapshot.mtime_ns).encode())
        hasher.update(snapshot.digest.encode())
    return hasher.hexdigest()


def _changed_paths(previous: tuple[FileSnapshot, ...], current: tuple[FileSnapshot, ...]) -> list[str]:
    previous_by_path = {item.path: item for item in previous}
    current_by_path = {item.path: item for item in current}
    changed: list[str] = []
    for path in sorted(set(previous_by_path) | set(current_by_path)):
        if previous_by_path.get(path) != current_by_path.get(path):
            changed.append(Path(path).name)
    return changed


def _score_style(score: int) -> str:
    if score >= 75:
        return "green"
    if score >= 50:
        return "yellow"
    return "red"


def _severity_dot(severity: str) -> str:
    return {
        "critical": "[bright_red]●[/bright_red]",
        "high": "[red]●[/red]",
        "medium": "[yellow]●[/yellow]",
        "low": "[cyan]●[/cyan]",
    }.get(severity, "[white]●[/white]")


def _delta_text(current: int, previous: int | None) -> str:
    if previous is None:
        return t("watch_no_previous_scan")
    delta = current - previous
    if delta == 0:
        return t("watch_no_change")
    sign = "+" if delta > 0 else ""
    return f"{sign}{delta}"


def _build_summary_table(summary: dict[str, Any]) -> Table:
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column(style="white")
    table.add_row(t("watch_path"), str(summary["target"]))
    table.add_row(t("watch_rules"), str(summary["rules"]))
    table.add_row(t("watch_invalid"), str(summary["invalid"]))
    table.add_row(t("watch_duplicates"), str(summary["duplicates"]))
    table.add_row(t("watch_overlap"), str(summary["overlap"]))
    table.add_row(t("watch_weak"), str(summary["weak"]))
    return table


def _build_changes_table(delta: dict[str, Any]) -> Table:
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column(style="white")
    table.add_row(t("watch_delta"), delta["score"])
    table.add_row(t("watch_new_findings"), str(delta["findings"]))
    table.add_row(t("watch_new_invalid"), str(delta["invalid"]))
    table.add_row(t("watch_new_critical"), str(delta["critical"]))
    table.add_row(t("watch_rescan_reason"), delta["reason"])
    return table


def _build_top_issues(engine: RuleScopeEngine, report) -> Table:
    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column(style="white")
    table.add_column(style="dim")
    issues = engine.get_top_issues(report, limit=5)
    if not issues:
        table.add_row("[green]●[/green]", t("watch_no_top_issues"))
        return table
    for title, code, message, severity in issues:
        table.add_row(f"{_severity_dot(severity)} [bold]{code}[/bold] {title}", translate_text(message))
    return table


def _build_rescan_reason(scan_count: int, changed_paths: list[str]) -> str:
    if scan_count <= 1:
        return t("watch_reason_initial")
    if not changed_paths:
        return t("watch_reason_manual")
    preview = ", ".join(changed_paths[:3])
    if len(changed_paths) > 3:
        preview += ", ..."
    return t("watch_reason_changed", files=preview)


def _render_watch(
    report,
    engine: RuleScopeEngine,
    scan_count: int,
    previous_snapshot: dict[str, Any] | None,
    changed_paths: list[str],
) -> tuple[RenderableType, dict[str, Any]]:
    s = report.summary
    current_snapshot = {
        "score": s.average_score,
        "findings": s.debt.total_findings,
        "invalid": s.invalid_rules,
        "critical": sum(1 for r in report.rules for f in r.findings if f.severity.lower() == "critical"),
        "target": report.target,
        "rules": s.total_rules,
        "duplicates": s.duplicate_pairs,
        "overlap": s.overlap_pairs,
        "weak": s.weak_rules,
    }
    delta = {
        "score": _delta_text(current_snapshot["score"], None if previous_snapshot is None else previous_snapshot["score"]),
        "findings": current_snapshot["findings"] - (0 if previous_snapshot is None else previous_snapshot["findings"]),
        "invalid": current_snapshot["invalid"] - (0 if previous_snapshot is None else previous_snapshot["invalid"]),
        "critical": current_snapshot["critical"] - (0 if previous_snapshot is None else previous_snapshot["critical"]),
        "reason": _build_rescan_reason(scan_count, changed_paths),
    }
    color = _score_style(s.average_score)
    header = Panel(
        f"[bold]{t('watch_path')}:[/bold] {report.target}   •   [bold]{t('watch_scan')}[/bold] #{scan_count}   •   "
        f"[bold]{t('score')}[/bold] [{color}]{s.average_score}/100[/{color}] ({s.score_band})",
        title=f"[bold bright_cyan]{t('watch_compact_title')}[/bold bright_cyan]",
        border_style="bright_blue",
    )
    summary_panel = Panel(_build_summary_table(current_snapshot), title=f"[bold]{t('watch_summary')}[/bold]", border_style="cyan")
    changes_panel = Panel(_build_changes_table(delta), title=f"[bold]{t('watch_changes')}[/bold]", border_style="cyan")
    issues_panel = Panel(_build_top_issues(engine, report), title=f"[bold]{t('watch_top_issues')}[/bold]", border_style="cyan")
    footer = Panel(f"[dim]{t('watching_for_changes')}[/dim]", border_style="bright_blue")
    return Group(header, summary_panel, changes_panel, issues_panel, footer), current_snapshot


def _watch_once(
    root: Path,
    target: str,
    engine: RuleScopeEngine,
    scan_count: int,
    previous_snapshot: dict[str, Any] | None,
    previous_fs_snapshot: tuple[FileSnapshot, ...] | None,
) -> tuple[RenderableType | None, dict[str, Any] | None, tuple[FileSnapshot, ...], int, list[str]]:
    current_fs_snapshot = _collect_watch_snapshot(root)
    changed_paths = [] if previous_fs_snapshot is None else _changed_paths(previous_fs_snapshot, current_fs_snapshot)
    if previous_fs_snapshot is not None and not changed_paths:
        return None, previous_snapshot, current_fs_snapshot, scan_count, []

    next_scan_count = scan_count + 1
    report = engine.scan(target)
    renderable, current_snapshot = _render_watch(
        report,
        engine,
        next_scan_count,
        previous_snapshot,
        changed_paths,
    )
    return renderable, current_snapshot, current_fs_snapshot, next_scan_count, changed_paths


def run_watch(target: str, config: RuleScopeConfig | None = None, interval: float = 1.0) -> None:
    cfg = config or RuleScopeConfig()
    engine = RuleScopeEngine(config=cfg)
    root = Path(target).resolve()
    previous_snapshot: dict[str, Any] | None = None
    previous_fs_snapshot: tuple[FileSnapshot, ...] | None = None
    scan_count = 0
    last_renderable: RenderableType = Panel(
        translate_text("Waiting for first scan..."),
        title=f"[bold bright_cyan]{t('watch_compact_title')}[/bold bright_cyan]",
        border_style="bright_blue",
    )

    try:
        with Live(last_renderable, console=console, refresh_per_second=4, screen=False, auto_refresh=False) as live:
            while True:
                try:
                    renderable, previous_snapshot, previous_fs_snapshot, scan_count, _ = _watch_once(
                        root=root,
                        target=str(root),
                        engine=engine,
                        scan_count=scan_count,
                        previous_snapshot=previous_snapshot,
                        previous_fs_snapshot=previous_fs_snapshot,
                    )
                    if renderable is not None:
                        last_renderable = renderable
                        live.update(last_renderable, refresh=True)
                        live.refresh()
                except Exception as exc:  # pragma: no cover
                    last_renderable = Panel(
                        f"[red]Scan error:[/red] {exc}",
                        title=f"[bold bright_cyan]{t('watch_compact_title')}[/bold bright_cyan]",
                        border_style="red",
                    )
                    live.update(last_renderable, refresh=True)
                    live.refresh()
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print(f"\n[dim]{t('watch_stopped')}[/dim]")
