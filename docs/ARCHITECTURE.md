# RuleScope v1.0 — Architecture

## Design Philosophy

RuleScope is built on four principles:

1. **Explainable scoring** — every finding has a code, severity, impact, and recommendation. No magic numbers.
2. **Deterministic analysis** — no AI dependency. Pure static analysis. Reproducible results.
3. **CI-native** — designed from day one for pipeline integration with exit codes, SARIF output, and configurable thresholds.
4. **Extensible** — plugin analyzers via the `RuleAnalyzer` protocol allow custom checks without modifying core.
5. **Semantically grounded** — duplicate and weakness analyzers reason on event surface, field precision, and value specificity instead of plain YAML wording.

## Engine Flow

```
┌─────────────┐
│  YAML files  │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│   SigmaParser    │  Parse & normalize into DetectionRule
│  (multi-doc,     │  (handles list-of-maps, keyword lists,
│   list-of-maps)  │   multi-document YAML)
└──────┬──────────┘
       │
       ▼
┌──────────────────────────────────────────┐
│          Per-Rule Analyzers              │
│  ┌────────────┐  ┌──────────────────┐   │
│  │ Metadata    │  │ Maintainability  │   │
│  │ Structural  │  │ Noise            │   │
│  │ Documentation│ │ ATT&CK Quality  │   │
│  │ Weakness    │  │ [Plugin ...]     │   │
│  └────────────┘  └──────────────────┘   │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────┐
│          Catalog-Level Analyzers         │
│  ┌──────────────┐  ┌────────────────┐   │
│  │ Duplicates    │  │ Overlaps       │   │
│  │ Coverage      │  │ Segmentation   │   │
│  └──────────────┘  └────────────────┘   │
└──────────────────┬───────────────────────┘
                   │
                   ▼
┌─────────────┐
│ WeightedScorer │  7-axis weighted scoring
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────┐
│              Reporters                   │
│  JSON │ Markdown │ HTML │ SARIF │ Table  │
│              Navigator Layer             │
└──────────────────────────────────────────┘
```

## Scoring Model (7 axes)

| Axis | Weight | Analyzer |
|------|--------|----------|
| Metadata quality | 20% | MetadataAnalyzer |
| Maintainability | 17% | MaintainabilityAnalyzer |
| Noise risk | 17% | NoiseAnalyzer |
| Structural integrity | 14% | StructuralAnalyzer |
| Documentation quality | 10% | DocumentationAnalyzer |
| ATT&CK tagging hygiene | 12% | AttackQualityAnalyzer |
| Analytical weakness | 10% | WeaknessAnalyzer |

Weights are configurable via `.rulescope.yml`.

## Plugin System

Custom analyzers implement the `RuleAnalyzer` protocol:

```python
class RuleAnalyzer(Protocol):
    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]: ...
```

Plugins are loaded via:
1. `engine.register_analyzer(name, instance)` at runtime
2. `rulescope.analyzers` setuptools entry point group (auto-discovered)

## Finding Codes

### Metadata (META-xxx)
- META-001: Missing required fields
- META-002: Invalid UUID
- META-003: Non-standard status
- META-004: Non-standard level
- META-005: Short description
- META-006: Few tags
- META-007: Missing date

### Maintainability (MAINT-xxx)
- MAINT-001: Too many selection blocks
- MAINT-002: Complex condition
- MAINT-003: Deep nesting
- MAINT-004: Long condition string
- MAINT-005: Missing condition
- MAINT-006: Large value set

### Noise (NOISE-xxx)
- NOISE-001: Excessive wildcards
- NOISE-002: Regex heavy
- NOISE-003: Missing FP guidance
- NOISE-004: Generic fields + high severity
- NOISE-005: Thin logic + high severity
- NOISE-006: All-wildcard detection
- NOISE-007: Leading wildcards (SIEM performance killer)

### Structural (STRUCT-xxx)
- STRUCT-001: Missing logsource
- STRUCT-002: No product/category
- STRUCT-003: Missing detection
- STRUCT-004: No condition
- STRUCT-005: Empty selections
- STRUCT-006: Long title
- STRUCT-007: Condition references undefined selections
- STRUCT-008: Selection defined but never referenced

### Weakness (WEAK-xxx)
- WEAK-001: Single selector block
- WEAK-002: Wildcard-heavy values
- WEAK-003: Contains-only matching
- WEAK-004: Low field diversity
- WEAK-005: Severity > detection strength
- WEAK-006: Pure negation condition
- WEAK-007: Filter-only rule without positive selection
- WEAK-008: Vague primary values
- WEAK-009: Low semantic precision

### Documentation (DOC-xxx)
- DOC-001: Uncapitalized title
- DOC-002: Generic title
- DOC-003: Terse description
- DOC-004: Short description
- DOC-005: Trivial FP entries
- DOC-006: Non-URL references

### ATT&CK (ATK-xxx)
- ATK-001: No ATT&CK tags
- ATK-002: Technique without tactic
- ATK-003: Tactic without technique
- ATK-004: Unknown tactic
- ATK-005: Malformed technique ID
- ATK-006: No sub-techniques

### Catalog (DUP/OVL/PARSE)
- DUP-001: Duplicate candidate (semantic event-surface similarity)
- OVL-001: Overlap candidate
- PARSE-001: YAML parse failure

### Correlation (CORR-xxx)
- CORR-001: No correlation type or rules reference
- CORR-002: No group-by fields
- CORR-003: No timespan
- CORR-004: No base rules and no inline detection

## Configuration

Place `.rulescope.yml` in your project root. See the included example.

## CI Integration

```bash
# Basic gate
rulescope ci ./rules --min-score 70

# With SARIF export for GitHub Advanced Security
rulescope ci ./rules --min-score 70 --format sarif --output results.sarif

# ATT&CK Navigator layer for coverage dashboards
rulescope navigator ./rules -o coverage.json
```

## Roadmap

- Near term: GitHub Action published on Marketplace, benchmark documentation at scale
- Later: Dead-rule indicators with telemetry inputs, web dashboard, team governance views, historical drift tracking
