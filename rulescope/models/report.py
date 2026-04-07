from __future__ import annotations

"""Report models — structured output for scan, compare, and coverage.

All models are Pydantic BaseModel for native JSON serialization.
CatalogReport is the top-level output of a scan; CompareReport
is the output of a baseline vs candidate comparison.
"""

from pydantic import BaseModel, Field

from rulescope.models.finding import Finding


class RuleScore(BaseModel):
    metadata: int = 0
    maintainability: int = 0
    noise: int = 0
    structural: int = 0
    documentation: int = 0
    attack_quality: int = 0
    weakness: int = 0
    overall: int = 0


class SemanticProfile(BaseModel):
    selector_count: int = 0
    field_count: int = 0
    wildcard_count: int = 0
    contains_modifiers: int = 0
    exact_modifiers: int = 0
    condition_complexity: int = 0
    tactic_count: int = 0
    technique_count: int = 0
    logsource_key: str = ""


class RuleReport(BaseModel):
    path: str
    title: str
    rule_id: str = ""
    level: str = ""
    status: str = ""
    logsource_key: str = ""
    scores: RuleScore
    findings: list[Finding] = Field(default_factory=list)
    duplicate_candidates: list[str] = Field(default_factory=list)
    overlap_candidates: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    semantic_profile: SemanticProfile = Field(default_factory=SemanticProfile)
    rule_type: str = "standard"  # "standard" | "correlation" | "filter"


class OverlapPair(BaseModel):
    left: str
    right: str
    similarity: int
    reason: str


class CoverageStat(BaseModel):
    tactic: str
    technique_count: int = 0
    rule_count: int = 0
    avg_quality: int = 0
    techniques: list[str] = Field(default_factory=list)
    quality_band: str = ""
    fragile: bool = False
    concentration_risk: bool = False


class SegmentScore(BaseModel):
    segment: str
    rule_count: int = 0
    average_score: int = 0
    worst_score: int = 0


class ScoreBreakdown(BaseModel):
    metadata: int = 0
    maintainability: int = 0
    noise: int = 0
    structural: int = 0
    documentation: int = 0
    attack_quality: int = 0
    weakness: int = 0


class CategoryStat(BaseModel):
    category: str
    count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class RecommendationStat(BaseModel):
    recommendation: str
    count: int = 0


class CatalogDebtSummary(BaseModel):
    total_findings: int = 0
    categories: list[CategoryStat] = Field(default_factory=list)
    top_recommendations: list[RecommendationStat] = Field(default_factory=list)


class BudgetResult(BaseModel):
    passed: bool = True
    failures: list[str] = Field(default_factory=list)


class CatalogSummary(BaseModel):
    total_rules: int = 0
    average_score: int = 0          # raw per-rule average (unpenalized)
    raw_average_score: int = 0      # alias: same as average_score
    catalog_health_score: int = 0   # penalized catalog-level risk score
    median_score: int = 0
    duplicate_pairs: int = 0
    overlap_pairs: int = 0
    high_noise_rules: int = 0
    weak_metadata_rules: int = 0
    invalid_rules: int = 0
    weak_rules: int = 0
    score_band: str = ""
    top_weakest: list[str] = Field(default_factory=list)
    coverage: list[CoverageStat] = Field(default_factory=list)
    segments_by_logsource: list[SegmentScore] = Field(default_factory=list)
    segments_by_level: list[SegmentScore] = Field(default_factory=list)
    average_pillars: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    debt: CatalogDebtSummary = Field(default_factory=CatalogDebtSummary)
    priority_actions: list[str] = Field(default_factory=list)
    budget_result: BudgetResult = Field(default_factory=BudgetResult)


class CatalogReport(BaseModel):
    version: str = "1.0.0"
    generated_at: str
    target: str
    summary: CatalogSummary
    rules: list[RuleReport] = Field(default_factory=list)
    duplicate_clusters: list[list[str]] = Field(default_factory=list)
    overlap_pairs: list[OverlapPair] = Field(default_factory=list)


class SemanticChange(BaseModel):
    code: str
    severity: str = "medium"
    summary: str
    detail: str = ""


class RuleDelta(BaseModel):
    path: str
    title: str = ""
    baseline_score: int = 0
    candidate_score: int = 0
    delta: int = 0
    semantic_changes: list[SemanticChange] = Field(default_factory=list)


class CompareSummary(BaseModel):
    baseline_target: str
    candidate_target: str
    baseline_score: int = 0
    candidate_score: int = 0
    score_delta: int = 0
    duplicate_delta: int = 0
    overlap_delta: int = 0
    weak_rule_delta: int = 0
    added_rules: int = 0
    removed_rules: int = 0
    changed_rules: int = 0
    improved_rules: int = 0
    regressed_rules: int = 0
    introduced_critical_findings: int = 0
    semantic_regressions: int = 0
    semantic_improvements: int = 0
    summary_verdict: str = ""
    key_takeaways: list[str] = Field(default_factory=list)


class CompareReport(BaseModel):
    version: str = "1.0.0"
    generated_at: str
    summary: CompareSummary
    strongest_improvements: list[RuleDelta] = Field(default_factory=list)
    strongest_regressions: list[RuleDelta] = Field(default_factory=list)
