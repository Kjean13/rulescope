from __future__ import annotations

"""Benchmark module for measuring RuleScope performance on real catalogs.

Run `rulescope benchmark <path>` to get parse rates, analysis time,
rules/sec throughput, score distribution, and finding breakdown.
Designed to validate that the tool scales on 1000+ rule catalogs.
"""

import time
from collections.abc import Iterable
from dataclasses import dataclass, field

from rulescope.config.settings import RuleScopeConfig
from rulescope.engine import RuleScopeEngine
from rulescope.i18n import get_lang, score_band_label, t
from rulescope.utils.files import find_rule_files


@dataclass
class BenchmarkResult:
    """Results of a benchmark run."""
    target: str = ""
    total_files: int = 0
    parsed_ok: int = 0
    parse_failures: int = 0
    correlation_rules: int = 0
    filter_rules: int = 0
    standard_rules: int = 0
    total_findings: int = 0
    average_score: int = 0           # raw per-rule average (unpenalized)
    catalog_health_score: int = 0    # penalized catalog-level risk score
    median_score: int = 0
    score_band: str = ""
    duplicate_clusters: int = 0
    overlap_pairs: int = 0
    parse_time_ms: float = 0.0
    analysis_time_ms: float = 0.0
    total_time_ms: float = 0.0
    rules_per_second: float = 0.0
    score_distribution: dict[str, int] = field(default_factory=dict)
    finding_distribution: dict[str, int] = field(default_factory=dict)
    top_failure_reasons: list[str] = field(default_factory=list)
    logsource_breakdown: dict[str, int] = field(default_factory=dict)


def run_benchmark(target: str, config: RuleScopeConfig | None = None) -> BenchmarkResult:
    """Run a full benchmark scan on a rule catalog."""
    cfg = config or RuleScopeConfig()
    result = BenchmarkResult(target=target)

    # Count files
    files = find_rule_files(target, exclude_patterns=cfg.exclude_paths)
    result.total_files = len(files)

    if not files:
        return result

    # Time the full scan
    engine = RuleScopeEngine(config=cfg)

    t0 = time.perf_counter()
    report = engine.scan(target)
    t1 = time.perf_counter()

    result.total_time_ms = round((t1 - t0) * 1000, 1)
    result.rules_per_second = round(result.total_files / max(0.001, t1 - t0), 1)

    # Extract stats
    result.parsed_ok = sum(1 for r in report.rules if not any(f.code == "PARSE-001" for f in r.findings))
    result.parse_failures = sum(1 for r in report.rules if any(f.code == "PARSE-001" for f in r.findings))

    # Count rule types from report data (no re-parsing needed)
    for r in report.rules:
        if r.rule_type == "correlation":
            result.correlation_rules += 1
        elif r.rule_type == "filter":
            result.filter_rules += 1
        else:
            result.standard_rules += 1

    result.total_findings = report.summary.debt.total_findings
    result.average_score = report.summary.average_score
    result.catalog_health_score = report.summary.catalog_health_score
    result.median_score = report.summary.median_score
    result.score_band = report.summary.score_band
    result.duplicate_clusters = report.summary.duplicate_pairs
    result.overlap_pairs = report.summary.overlap_pairs

    # Score distribution
    dist = {"90-100": 0, "75-89": 0, "50-74": 0, "25-49": 0, "0-24": 0}
    for r in report.rules:
        s = r.scores.overall
        if s >= 90:
            dist["90-100"] += 1
        elif s >= 75:
            dist["75-89"] += 1
        elif s >= 50:
            dist["50-74"] += 1
        elif s >= 25:
            dist["25-49"] += 1
        else:
            dist["0-24"] += 1
    result.score_distribution = dist

    # Finding distribution by category
    cat_dist: dict[str, int] = {}
    for r in report.rules:
        for f in r.findings:
            cat = f.category or "general"
            cat_dist[cat] = cat_dist.get(cat, 0) + 1
    result.finding_distribution = dict(sorted(cat_dist.items(), key=lambda x: -x[1]))

    # Logsource breakdown
    ls_dist: dict[str, int] = {}
    for r in report.rules:
        key = r.logsource_key or "(unknown)"
        ls_dist[key] = ls_dist.get(key, 0) + 1
    result.logsource_breakdown = dict(sorted(ls_dist.items(), key=lambda x: -x[1])[:15])

    # Top parse failure reasons
    failures = []
    for r in report.rules:
        for f in r.findings:
            if f.code == "PARSE-001":
                failures.append(f"{r.path}: {f.evidence[:80]}")
    result.top_failure_reasons = failures[:10]

    return result


def render_benchmark_markdown(result: BenchmarkResult) -> str:
    """Render a benchmark result as Markdown."""
    is_fr = get_lang() == "fr"
    lines = [
        "# Rapport de benchmark RuleScope" if is_fr else "# RuleScope Benchmark Report",
        "",
        f"**{'Cible' if is_fr else 'Target'}:** `{result.target}`",
        "",
        "## Résumé" if is_fr else "## Summary",
        "",
        f"| {t('metric')} | {t('value')} |",
        "|--------|-------|",
        f"| {'Nombre total de fichiers' if is_fr else 'Total files'} | {result.total_files} |",
        f"| {'Analysés correctement' if is_fr else 'Parsed OK'} | {result.parsed_ok} |",
        f"| {'Échecs de parsing' if is_fr else 'Parse failures'} | {result.parse_failures} |",
        f"| {'Règles standard' if is_fr else 'Standard rules'} | {result.standard_rules} |",
        f"| {'Règles de corrélation' if is_fr else 'Correlation rules'} | {result.correlation_rules} |",
        f"| {'Règles filtre' if is_fr else 'Filter rules'} | {result.filter_rules} |",
        f"| {'Taux de parsing' if is_fr else 'Parse rate'} | {round(result.parsed_ok / max(1, result.total_files) * 100, 1)}% |",
        "",
        "## Qualité" if is_fr else "## Quality",
        "",
        f"| {t('metric')} | {t('value')} |",
        "|--------|-------|",
        f"| {'Score moyen par règle' if is_fr else 'Average Rule Score'} | **{result.average_score}/100** |",
        f"| {'Score de santé catalogue' if is_fr else 'Catalog Health Score'} | **{result.catalog_health_score}/100** ({score_band_label(result.score_band)}) |",
        f"| {'Score médian' if is_fr else 'Median score'} | {result.median_score} |",
        f"| {'Nombre total de constats' if is_fr else 'Total findings'} | {result.total_findings} |",
        f"| {'Groupes de doublons' if is_fr else 'Duplicate clusters'} | {result.duplicate_clusters} |",
        f"| {'Paires de chevauchement' if is_fr else 'Overlap pairs'} | {result.overlap_pairs} |",
        "",
        "## Performance" if is_fr else "## Performance",
        "",
        f"| {t('metric')} | {t('value')} |",
        "|--------|-------|",
        f"| {'Temps total' if is_fr else 'Total time'} | {result.total_time_ms} ms |",
        f"| {'Règles/seconde' if is_fr else 'Rules/second'} | {result.rules_per_second} |",
        f"| {'Temps par règle' if is_fr else 'Time per rule'} | {round(result.total_time_ms / max(1, result.total_files), 1)} ms |",
        "",
        "## Répartition des scores" if is_fr else "## Score Distribution",
        "",
        f"| {'Plage' if is_fr else 'Range'} | {'Nombre' if is_fr else 'Count'} | {'Pct' if is_fr else 'Pct'} |",
        "|-------|-------|-----|",
    ]
    for band, count in result.score_distribution.items():
        pct = round(count / max(1, result.total_files) * 100, 1)
        lines.append(f"| {band} | {count} | {pct}% |")

    lines.extend(["", "## Répartition des constats par catégorie" if is_fr else "## Finding Distribution by Category", "", f"| {'Catégorie' if is_fr else 'Category'} | {'Nombre' if is_fr else 'Count'} |", "|----------|-------|"])
    for cat, count in list(result.finding_distribution.items())[:10]:
        lines.append(f"| {cat} | {count} |")

    if result.logsource_breakdown:
        lines.extend(["", "## Principales sources de logs" if is_fr else "## Top Logsources", "", f"| {'Source de logs' if is_fr else 'Logsource'} | {'Règles' if is_fr else 'Rules'} |", "|-----------|-------|"])
        for ls, count in list(result.logsource_breakdown.items())[:10]:
            lines.append(f"| {ls} | {count} |")

    if result.top_failure_reasons:
        lines.extend(["", "## Échecs de parsing (échantillon)" if is_fr else "## Parse Failures (sample)", ""])
        for reason in result.top_failure_reasons[:5]:
            lines.append(f"- `{reason}`")

    lines.append("")
    return "\n".join(lines)


def _markdown_table(rows: Iterable[tuple[str, str]]) -> list[str]:
    lines = [f"| {t('metric')} | {t('value')} |", "|--------|-------|"]
    for left, right in rows:
        lines.append(f"| {left} | {right} |")
    return lines
