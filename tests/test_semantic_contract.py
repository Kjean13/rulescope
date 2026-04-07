from __future__ import annotations

from rulescope.comparison import compare_catalogs
from rulescope.config.settings import RuleScopeConfig
from rulescope.engine import RuleScopeEngine


def test_compare_surfaces_semantic_regression() -> None:
    engine = RuleScopeEngine(config=RuleScopeConfig())
    baseline = engine.scan("datasets/regression_demo/baseline")
    candidate = engine.scan("datasets/regression_demo/candidate")
    report = compare_catalogs(baseline, candidate)
    assert report.summary.summary_verdict == "Regression"
    assert report.summary.semantic_regressions >= 1


def test_maintainer_snapshot_contains_hotspots() -> None:
    engine = RuleScopeEngine(config=RuleScopeConfig())
    report = engine.scan("datasets/medium_realistic")
    snapshot = engine.maintainer_snapshot(report)
    assert snapshot["catalog_score"] > 0
    assert snapshot["worst_rules"]
    assert snapshot["category_hotspots"]
    assert snapshot["worst_logsources"]
