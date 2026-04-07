# Roadmap

## v1.0 (current)
- Plugin analyzer system with RuleAnalyzer protocol (PEP 561 py.typed)
- ATT&CK Navigator layer export
- Professional HTML report with radar chart, filters, search
- Leading wildcard detection (SIEM performance)
- Condition ↔ selection coherence checks
- Negation and filter-only rule detection
- Multi-document YAML parsing
- List-of-maps selector normalization
- Sigma v2 correlation rule support (CORR-001 to CORR-004)
- Watch mode for iterative rule development
- Benchmark command for performance profiling
- Interactive console with language switching
- Internationalization: English and French
- 54 finding codes, 15 semantic diff codes
- 310 tests, coverage threshold 90%, strict ruff linting

## Near term
- Richer duplicate clustering explanations
- Baseline history and drift tracking over time
- GitHub Action published on Marketplace
- Benchmark documentation (performance at 100/500/1000/3000 rules)
- PyPI publication

## Later
- Dead-rule indicators with telemetry inputs
- Team-level governance dashboards
- Web API for integration with CI/CD platforms
- SIEM portability scoring (backend-specific compilation risk)
