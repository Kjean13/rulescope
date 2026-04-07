from __future__ import annotations

"""Core scanning engine — the central pipeline.

Flow: parse YAML → run per-rule analyzers → run catalog-level analyzers
(duplicates, overlap, coverage) → score → build report.
Supports plugin analyzers via the RuleAnalyzer protocol.
"""

import sys
from collections import Counter, defaultdict
from pathlib import Path

from rulescope.analyzers.attack_quality import AttackQualityAnalyzer
from rulescope.analyzers.base import RuleAnalyzer
from rulescope.analyzers.coverage import CoverageAnalyzer
from rulescope.analyzers.documentation import DocumentationAnalyzer
from rulescope.analyzers.duplicates import DuplicateAnalyzer
from rulescope.analyzers.maintainability import MaintainabilityAnalyzer
from rulescope.analyzers.metadata import MetadataAnalyzer
from rulescope.analyzers.noise import NoiseAnalyzer
from rulescope.analyzers.overlap import OverlapAnalyzer
from rulescope.analyzers.structural import StructuralAnalyzer
from rulescope.analyzers.weakness import WeaknessAnalyzer
from rulescope.config.settings import GovernanceBudget, RuleScopeConfig
from rulescope.models.finding import Finding, SEVERITY_RANK
from rulescope.models.report import (
    BudgetResult,
    CatalogDebtSummary,
    CatalogReport,
    CategoryStat,
    RecommendationStat,
    RuleReport,
    ScoreBreakdown,
    SegmentScore,
    SemanticProfile,
)
from rulescope.models.rule import DetectionRule
from rulescope.parsers.sigma_parser import SigmaParser, SigmaParserError
from rulescope.scorers.weighted_score import WeightedScorer
from rulescope.utils.files import find_rule_files
from rulescope.utils.time import utc_now_iso


class RuleScopeEngine:
    """Core scanning engine: parse -> analyze -> score -> report.

    Supports plugin analyzers via ``register_analyzer(name, analyzer)``.
    Plugin analyzers must implement the ``RuleAnalyzer`` protocol.
    """

    def __init__(self, config: RuleScopeConfig | None = None) -> None:
        self.config = config or RuleScopeConfig()
        self.parser = SigmaParser()
        self.metadata = MetadataAnalyzer()
        self.maintainability = MaintainabilityAnalyzer()
        self.noise = NoiseAnalyzer()
        self.structural = StructuralAnalyzer()
        self.documentation = DocumentationAnalyzer()
        self.attack_quality = AttackQualityAnalyzer()
        self.weakness = WeaknessAnalyzer()
        self.duplicates = DuplicateAnalyzer()
        self.overlap = OverlapAnalyzer()
        self.coverage = CoverageAnalyzer()
        self.scorer = WeightedScorer(weights=self.config.weights_dict())
        self._plugin_analyzers: dict[str, RuleAnalyzer] = {}

        # Auto-discover plugin analyzers from entry points
        self._load_plugin_analyzers()

    def register_analyzer(self, name: str, analyzer: RuleAnalyzer) -> None:
        """Register a custom analyzer that will run on every rule.

        The analyzer must implement ``analyze(rule) -> (score, findings)``.
        Plugin findings will appear alongside built-in findings in all outputs.
        """
        if not isinstance(analyzer, RuleAnalyzer):
            raise TypeError(f"Analyzer must implement the RuleAnalyzer protocol, got {type(analyzer)}")
        self._plugin_analyzers[name] = analyzer

    def _load_plugin_analyzers(self) -> None:
        """Load analyzers from 'rulescope.analyzers' entry point group (optional)."""
        if sys.version_info >= (3, 12):
            from importlib.metadata import entry_points
            eps = entry_points(group="rulescope.analyzers")
        else:
            try:
                from importlib.metadata import entry_points
                all_eps = entry_points()
                eps = all_eps.get("rulescope.analyzers", [])
            except Exception:
                eps = []
        for ep in eps:
            try:
                analyzer_cls = ep.load()
                self._plugin_analyzers[ep.name] = analyzer_cls()
            except Exception:
                pass  # Silently skip broken plugins

    def scan(self, root: str) -> CatalogReport:
        # Step 1: discover all .yml/.yaml files, respecting exclude patterns
        files = find_rule_files(root, exclude_patterns=self.config.exclude_paths)
        parsed_rules: list[DetectionRule] = []
        parse_failures: list[RuleReport] = []

        for path in files:
            try:
                parsed_rules.append(self.parser.parse_file(path))
            except SigmaParserError as exc:
                fail_score = self.scorer.score_rule(0, 0, 0, 0, 0, 0, 0)
                parse_failures.append(
                    RuleReport(
                        path=str(path),
                        title=Path(path).name,
                        scores=fail_score,
                        findings=[
                            Finding(
                                code="PARSE-001",
                                severity="critical",
                                category="structural",
                                message="YAML parsing failed.",
                                evidence=str(exc),
                                recommendation="Fix the YAML syntax or unsupported structure.",
                                impact="Unparseable rules are completely non-functional.",
                            )
                        ],
                    )
                )

        # Step 2: catalog-level analysis — duplicates and overlaps across all rules
        duplicate_map, duplicate_clusters = self.duplicates.analyze(parsed_rules)
        overlap_pairs = self.overlap.analyze(parsed_rules)
        overlap_map: dict[str, list[str]] = defaultdict(list)
        for op in overlap_pairs:
            overlap_map[op.left].append(op.right)
            overlap_map[op.right].append(op.left)

        reports: list[RuleReport] = []
        weak_metadata_rules = 0
        high_noise_rules = 0
        invalid_rules = len(parse_failures)
        weak_rules = 0

        for rule in parsed_rules:
            # Correlation rules get a different analysis path
            if rule.is_correlation:
                scores, findings = self._analyze_correlation_rule(rule)
            else:
                meta_score, meta_findings = self.metadata.analyze(rule)
                maint_score, maint_findings = self.maintainability.analyze(rule)
                noise_score, noise_findings = self.noise.analyze(rule)
                struct_score, struct_findings = self.structural.analyze(rule)
                doc_score, doc_findings = self.documentation.analyze(rule)
                atk_score, atk_findings = self.attack_quality.analyze(rule)
                weak_score, weak_findings = self.weakness.analyze(rule)

                scores = self.scorer.score_rule(
                    meta_score, maint_score, noise_score, struct_score, doc_score, atk_score, weak_score
                )
                findings = (
                    meta_findings + maint_findings + noise_findings + struct_findings + doc_findings + atk_findings + weak_findings
                )

            # Run plugin analyzers
            plugin_findings: list[Finding] = []
            for _name, analyzer in self._plugin_analyzers.items():
                try:
                    _pscore, pfindings = analyzer.analyze(rule)
                    plugin_findings.extend(pfindings)
                except Exception:
                    pass  # Plugins should not break the pipeline

            findings.extend(plugin_findings)

            dup_cands = duplicate_map.get(rule.path, [])
            if dup_cands:
                findings.append(
                    Finding(
                        code="DUP-001",
                        severity="medium",
                        category="duplicate",
                        message="Rule has likely duplicate or highly similar peers.",
                        evidence=f"matches: {len(dup_cands)}",
                        recommendation="Review duplicated logic and consider merge or refactor.",
                        impact="Duplicate rules waste analyst attention and inflate coverage metrics.",
                    )
                )

            ovl_cands = overlap_map.get(rule.path, [])
            if ovl_cands:
                findings.append(
                    Finding(
                        code="OVL-001",
                        severity="low",
                        category="overlap",
                        message="Rule overlaps significantly with peers on the same logsource.",
                        evidence=f"overlapping rules: {len(ovl_cands)}",
                        recommendation="Review for merge candidates or document differentiation.",
                        impact="Overlapping rules generate redundant alerts on the same events.",
                    )
                )

            if scores.metadata < 70:
                weak_metadata_rules += 1
            if scores.noise < 70:
                high_noise_rules += 1
            if scores.structural < 70:
                invalid_rules += 1
            if scores.weakness < 70:
                weak_rules += 1

            reports.append(
                RuleReport(
                    path=rule.path,
                    title=rule.title,
                    rule_id=rule.rule_id,
                    level=rule.level,
                    status=rule.status,
                    logsource_key=rule.logsource_key,
                    scores=scores,
                    findings=findings,
                    duplicate_candidates=dup_cands,
                    overlap_candidates=ovl_cands,
                    attack_techniques=rule.attack_techniques,
                    attack_tactics=rule.attack_tactics,
                    semantic_profile=self._semantic_profile(rule),
                    rule_type=rule.rule_type,
                )
            )

        # Step 3: merge parse failures into the report list
        reports.extend(parse_failures)
        all_scores = [r.scores.overall for r in reports]
        summary = self.scorer.score_catalog(
            all_scores,
            duplicate_pairs=len(duplicate_clusters),
            overlap_pairs=len(overlap_pairs),
            weak_metadata_rules=weak_metadata_rules,
            high_noise_rules=high_noise_rules,
            invalid_rules=invalid_rules,
            weak_rules=weak_rules,
        )

        # Step 4: catalog-level scoring and summary generation
        sorted_reports = sorted(reports, key=lambda r: r.scores.overall)
        summary.top_weakest = [f"{r.title or r.path} ({r.scores.overall}/100)" for r in sorted_reports[:10]]
        summary.coverage = self.coverage.analyze(reports)
        summary.segments_by_logsource = self._segment_by(reports, lambda r: r.logsource_key or "(unknown)")
        summary.segments_by_level = self._segment_by(reports, lambda r: r.level or "(unknown)")
        summary.average_pillars = self._pillar_breakdown(reports)
        summary.debt = self._build_debt_summary(reports)
        summary.priority_actions = self._priority_actions(summary)
        summary.budget_result = self.evaluate_budget(summary)

        return CatalogReport(
            generated_at=utc_now_iso(),
            target=root,
            summary=summary,
            rules=reports,
            duplicate_clusters=duplicate_clusters,
            overlap_pairs=overlap_pairs,
        )

    def evaluate_budget(self, summary, budget: GovernanceBudget | None = None) -> BudgetResult:
        budget = budget or self.config.budget
        failures: list[str] = []
        if summary.average_score < budget.min_average_score:
            failures.append(f"average_score {summary.average_score} < {budget.min_average_score}")
        if summary.duplicate_pairs > budget.max_duplicate_clusters:
            failures.append(f"duplicate_clusters {summary.duplicate_pairs} > {budget.max_duplicate_clusters}")
        if summary.overlap_pairs > budget.max_overlap_pairs:
            failures.append(f"overlap_pairs {summary.overlap_pairs} > {budget.max_overlap_pairs}")
        if summary.high_noise_rules > budget.max_high_noise_rules:
            failures.append(f"high_noise_rules {summary.high_noise_rules} > {budget.max_high_noise_rules}")
        if summary.weak_metadata_rules > budget.max_weak_metadata_rules:
            failures.append(f"weak_metadata_rules {summary.weak_metadata_rules} > {budget.max_weak_metadata_rules}")
        if summary.invalid_rules > budget.max_invalid_rules:
            failures.append(f"invalid_rules {summary.invalid_rules} > {budget.max_invalid_rules}")
        return BudgetResult(passed=not failures, failures=failures)

    def get_top_issues(self, report: CatalogReport, limit: int = 20) -> list[tuple[str, str, str, str]]:
        ranked = []
        rank_to_label = {v: k for k, v in SEVERITY_RANK.items()}
        for rule in report.rules:
            for finding in rule.findings:
                ranked.append((SEVERITY_RANK.get(finding.severity, 0), rule.title or rule.path, finding.code, finding.message))
        ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
        return [(title, code, message, rank_to_label.get(sev, "info")) for sev, title, code, message in ranked[:limit]]


    def maintainer_snapshot(self, report: CatalogReport) -> dict:
        hotspot_rules = sorted(report.rules, key=lambda r: (-len(r.findings), r.scores.overall, r.title or r.path))[:5]
        category_hotspots = [
            {
                "category": item.category,
                "count": item.count,
                "critical": item.critical,
                "high": item.high,
            }
            for item in report.summary.debt.categories[:5]
        ]
        return {
            "catalog_score": report.summary.average_score,
            "rules": report.summary.total_rules,
            "worst_logsources": [seg.model_dump() for seg in report.summary.segments_by_logsource[:5]],
            "worst_levels": [seg.model_dump() for seg in report.summary.segments_by_level[:5]],
            "category_hotspots": category_hotspots,
            "worst_rules": [
                {
                    "title": r.title or r.path,
                    "path": r.path,
                    "score": r.scores.overall,
                    "findings": len(r.findings),
                    "top_categories": sorted({f.category for f in r.findings if f.category})[:3],
                }
                for r in hotspot_rules
            ],
            "top_recommendations": [rec.model_dump() for rec in report.summary.debt.top_recommendations[:5]],
        }

    def _analyze_correlation_rule(self, rule: DetectionRule) -> tuple:
        """Analyze a Sigma v2 correlation rule with adapted scoring.

        Correlation rules don't have traditional detection blocks, so
        structural/noise/weakness analyzers would produce false findings.
        We score them on metadata, documentation, ATT&CK, and correlation-specific checks.
        """
        from rulescope.models.report import RuleScore

        findings: list[Finding] = []

        # Metadata still applies
        meta_score, meta_findings = self.metadata.analyze(rule)
        findings.extend(meta_findings)

        # Documentation still applies
        doc_score, doc_findings = self.documentation.analyze(rule)
        findings.extend(doc_findings)

        # ATT&CK still applies
        atk_score, atk_findings = self.attack_quality.analyze(rule)
        findings.extend(atk_findings)

        # Correlation-specific checks
        corr = rule.correlation
        corr_score = 100

        if not corr.get("type") and not corr.get("rules"):
            corr_score -= 20
            findings.append(Finding(
                code="CORR-001",
                severity="high",
                category="correlation",
                message="Correlation rule has no type or rules reference.",
                recommendation="Add a correlation type (event_count, value_count, temporal) and reference the base rules.",
                impact="Incomplete correlation rules cannot be compiled by any backend.",
            ))

        if not corr.get("group-by"):
            corr_score -= 10
            findings.append(Finding(
                code="CORR-002",
                severity="medium",
                category="correlation",
                message="Correlation rule has no group-by fields.",
                recommendation="Add group-by fields to scope the correlation (e.g. source IP, user).",
                impact="Without group-by, correlation aggregates globally and loses context.",
            ))

        if not corr.get("timespan"):
            corr_score -= 10
            findings.append(Finding(
                code="CORR-003",
                severity="medium",
                category="correlation",
                message="Correlation rule has no timespan.",
                recommendation="Add a timespan (e.g. 5m, 1h) to bound the correlation window.",
                impact="Unbounded correlation windows are expensive and produce stale matches.",
            ))

        if not corr.get("rules") and not rule.detection:
            corr_score -= 15
            findings.append(Finding(
                code="CORR-004",
                severity="high",
                category="correlation",
                message="Correlation rule references no base rules and has no inline detection.",
                recommendation="Add a 'rules' list referencing the base detection rules by ID or name.",
                impact="A correlation without base rules has nothing to correlate.",
            ))

        # Weighted score — correlation uses meta/doc/atk/corr, skip noise/struct/weakness
        overall = round(
            meta_score * 0.25 + doc_score * 0.15 + atk_score * 0.15 + corr_score * 0.45
        )
        overall = max(0, min(100, overall))

        scores = RuleScore(
            metadata=meta_score,
            documentation=doc_score,
            attack_quality=atk_score,
            maintainability=corr_score,  # reuse maintainability slot for correlation quality
            noise=100,       # not applicable
            structural=100,  # not applicable
            weakness=100,    # not applicable
            overall=overall,
        )
        return scores, findings

    def _semantic_profile(self, rule: DetectionRule) -> SemanticProfile:
        detection = rule.detection or {}
        selectors = [v for k, v in detection.items() if k != "condition" and isinstance(v, dict)]
        field_names: set[str] = set()
        wildcard_count = 0
        contains_modifiers = 0
        exact_modifiers = 0
        for selector in selectors:
            for field, value in selector.items():
                field_l = field.lower()
                field_names.add(field.split("|")[0].lower())
                if "|contains" in field_l:
                    contains_modifiers += 1
                if any(token in field_l for token in ["|endswith", "|startswith", "|all"]):
                    exact_modifiers += 1
                if isinstance(value, str) and "*" in value:
                    wildcard_count += 1
                elif isinstance(value, list):
                    wildcard_count += sum(1 for item in value if isinstance(item, str) and "*" in item)
        condition = str(detection.get("condition") or "")
        complexity = sum(condition.count(token) for token in [" and ", " or ", " not "]) + condition.count("1 of") + condition.count("all of")
        return SemanticProfile(
            selector_count=len(selectors),
            field_count=len(field_names),
            wildcard_count=wildcard_count,
            contains_modifiers=contains_modifiers,
            exact_modifiers=exact_modifiers,
            condition_complexity=complexity,
            tactic_count=len(rule.attack_tactics),
            technique_count=len(rule.attack_techniques),
            logsource_key=rule.logsource_key,
        )

    def _segment_by(self, reports: list[RuleReport], key_fn) -> list[SegmentScore]:
        groups: dict[str, list[int]] = defaultdict(list)
        for r in reports:
            groups[key_fn(r)].append(r.scores.overall)
        return [
            SegmentScore(
                segment=seg,
                rule_count=len(scores),
                average_score=round(sum(scores) / len(scores)) if scores else 0,
                worst_score=min(scores) if scores else 0,
            )
            for seg, scores in sorted(groups.items())
        ]

    def _pillar_breakdown(self, reports: list[RuleReport]) -> ScoreBreakdown:
        if not reports:
            return ScoreBreakdown()
        return ScoreBreakdown(
            metadata=round(sum(r.scores.metadata for r in reports) / len(reports)),
            maintainability=round(sum(r.scores.maintainability for r in reports) / len(reports)),
            noise=round(sum(r.scores.noise for r in reports) / len(reports)),
            structural=round(sum(r.scores.structural for r in reports) / len(reports)),
            documentation=round(sum(r.scores.documentation for r in reports) / len(reports)),
            attack_quality=round(sum(r.scores.attack_quality for r in reports) / len(reports)),
            weakness=round(sum(r.scores.weakness for r in reports) / len(reports)),
        )

    def _build_debt_summary(self, reports: list[RuleReport]) -> CatalogDebtSummary:
        by_category: dict[str, Counter[str]] = defaultdict(Counter)
        rec_counter: Counter[str] = Counter()
        total = 0
        for report in reports:
            for finding in report.findings:
                total += 1
                category = finding.category or "general"
                by_category[category][finding.severity] += 1
                by_category[category]["count"] += 1
                if finding.recommendation:
                    rec_counter[finding.recommendation] += 1
        categories = [
            CategoryStat(
                category=cat,
                count=counts.get("count", 0),
                critical=counts.get("critical", 0),
                high=counts.get("high", 0),
                medium=counts.get("medium", 0),
                low=counts.get("low", 0),
                info=counts.get("info", 0),
            )
            for cat, counts in sorted(by_category.items(), key=lambda kv: (-kv[1].get("count", 0), kv[0]))
        ]
        recs = [RecommendationStat(recommendation=k, count=v) for k, v in rec_counter.most_common(7)]
        return CatalogDebtSummary(total_findings=total, categories=categories, top_recommendations=recs)

    def _priority_actions(self, summary) -> list[str]:
        actions: list[str] = []
        if summary.invalid_rules:
            actions.append(f"Fix {summary.invalid_rules} invalid or structurally broken rules first.")
        if summary.duplicate_pairs:
            actions.append(f"Review {summary.duplicate_pairs} duplicate clusters to reduce redundant detections.")
        if summary.high_noise_rules:
            actions.append(f"Tune or narrow {summary.high_noise_rules} high-noise rules before production rollout.")
        if summary.weak_metadata_rules:
            actions.append(f"Complete metadata on {summary.weak_metadata_rules} weakly documented rules.")
        if summary.weak_rules:
            actions.append(f"Harden {summary.weak_rules} analytically weak rules before promoting them to production severity.")
        fragile = [c for c in summary.coverage if c.fragile]
        if fragile:
            actions.append(f"Strengthen fragile ATT&CK coverage in: {', '.join(c.tactic for c in fragile[:3])}.")
        return actions[:5]
