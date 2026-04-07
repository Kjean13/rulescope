# Changelog

## [1.0.0] — 2026-03-23

### Final v1.0 stabilization

- **Semantic duplicate detection** — replaced lexical near-duplicate matching with structured event-surface similarity across fields, modifiers, normalized values, and condition logic.
- **Intent-aware weakness scoring** — weakness now scores field precision × modifier strength × value specificity, which distinguishes strong anchors such as `OriginalFileName: mimikatz.exe` from vague patterns like `CommandLine|contains: pass`.
- **Empirical lifecycle calibration** — weakness scoring now uses Sigma lifecycle status as a field signal: `deprecated` / `unsupported` cap the score and `experimental` rules cannot appear artificially perfect.
- **Release freeze cleanup** — version, docs, and release commands aligned on `v1.0.0`; release validation documented around `python -m pytest -q`, `ruff`, and `python -m build`.

### Performance (deterministic scale patch)

- Replaced naïve pairwise duplicate/overlap passes with exact pruning + exact semantic scoring.
- Candidate generation is now strictly grouped by logsource and field-family compatibility.
- Added deterministic upper-bound pruning before expensive semantic scoring.
- Preserved exact final duplicate/overlap decisions while reducing pairwise blow-ups on large catalogs.
- Replaced hot-path `difflib.SequenceMatcher` value matching with deterministic cached token/path similarity to remove the main SigmaHQ-scale bottleneck.
- Condition similarity is now token-based and cached, avoiding repeated expensive string-alignment work in overlap and duplicate scoring.

### Fixed

- **ATK-004 false positives** — `AttackQualityAnalyzer` now normalises hyphens to underscores
  before tactic lookup. SigmaHQ uses `defense-evasion`; the lookup table used `defense_evasion`.
  This eliminated ~2 264 spurious findings (2 329 → 65) on the SigmaHQ catalog.

- **WEAK-003 never fired on multi-selector rules** — The old condition (`selector_count <= 2`)
  excluded the majority of SigmaHQ rules that use `all of selection_*` with 3+ selectors.
  Replaced with an anchor-based check: fires when *no* positive selector contains an anchored
  field (`endswith`, `startswith`, exact match, `OriginalFileName`, etc.).
  Reduces false negatives by ~40% on real-world catalogs.

- **WEAK-004 field-diversity counted modifiers as distinct fields** — `CommandLine|contains`
  and `CommandLine|startswith` were counted as two different fields. Now strips the modifier
  before uniqueness check, correctly catching multi-selector rules that all target the same
  base field.

- **Overlap threshold too permissive (36 995 pairs on SigmaHQ)** — Detection similarity
  threshold raised from 65 % to 75 %; field-overlap threshold raised from 0.75 to 0.85.
  Reduces spurious overlap pairs by ~2 843 on the SigmaHQ catalog.

- **Scoring weights skewed toward structural axes** — `metadata + maintainability + structural`
  previously held 51 % of the total weight, creating a score floor of 51/100 for any
  well-formed YAML file regardless of detection quality. Weights redistributed:
  `noise` and `weakness` each raised to 22 %; structural axes reduced proportionally.
  `score_band` now reflects operational quality rather than YAML hygiene.

- **NOISE-008** — Very short substrings (< 4 chars) on `CommandLine`-class fields are now
  flagged. Patterns like `' -p '`, `'cmd'`, `' -i'` match an extremely broad surface in any
  real environment and were silently passing. Exempt: file extensions, known unambiguous flags.

- **NOISE-009** — `CommandLine|contains` lists with more than 20 entries (IOC-dump style) are
  now penalised. These generate high FP rates and degrade SIEM pipeline performance.

- **NOISE-010** — OR-storm pattern detected: `1 of selection_*` with ≥ 6 selectors at
  `high`/`critical` severity. Each OR branch fires independently, inflating alert volume.

- **Overlap field_overlap standalone trigger removed** — pairs triggered solely by
  `field_overlap ≥ 0.85` (without meeting the detection similarity threshold) were producing
  ~30 000 spurious pairs on same-logsource rule groups. Field overlap is now only reported as
  supplementary context when detection similarity already meets the threshold (75 %).

- **CODE_SUGGESTIONS registry** updated for NOISE-008, NOISE-009, NOISE-010 (required by
  `explain` command and the finding registry contract test).

### Added

- **`raw_average_score` and `catalog_health_score` fields** on `CatalogSummary` and
  `BenchmarkResult`. `average_score` is now the unpenalized per-rule mean;
  `catalog_health_score` carries the catalog-level penalty (duplicates, overlaps, etc.).
  Both fields are exposed in all output formats (JSON, Markdown, HTML, benchmark).

- **Relative penalty formula** in `WeightedScorer.score_catalog` — penalties are now
  expressed as a percentage of the catalog size, so large catalogs are judged on the
  same scale as small ones.

- **`tests/test_catalog_health_score.py`** — 31 new tests covering field presence,
  raw/penalized score separation, relative penalty fairness, score-band logic, and
  JSON/Markdown output correctness.

## Earlier internal milestones

### Initial public release — production-grade governance engine

**Release refinements included in this frozen 1.0.0 build**
- Hardened language initialization so CLI behavior is deterministic in tests and automation.
- Aligned CLI language handling across `scan`, `compare`, `explain`, `report`, `ci`, `navigator`, `benchmark`, `doctor`, `console`, and `version`.
- Made `ci --format json` usable on stdout for shell automation.
- Improved visible FR wording across benchmark, markdown, navigator, dashboard, and report summaries.
- Refreshed README and release docs with clear positioning and real catalog use cases.

**Core features**
- Scan a Sigma rule catalog and score quality across 7 axes: metadata, noise, structure, ATT&CK mapping, maintainability, weakness, and documentation.
- Explain weak rules with prioritized, analyst-friendly remediation guidance.
- Compare baseline vs candidate rule packs with semantic regression detection.
- Report in HTML (radar chart, executive summary, severity filters, rule search), Markdown, JSON, and SARIF.
- CI gate with deterministic quality budgets and governance enforcement.
- Maintainer hotspot analysis to prioritize catalog debt.
- ATT&CK Navigator layer export compatible with MITRE Navigator and DeTT&CT.
- Interactive console mode with `/help`, `/intro`, `/tips`.
- Watch mode for iterative rule development.
- Benchmark command for performance profiling.
- Internationalization: English and French (`--lang en|fr` / `RULESCOPE_LANG`).

**Plugin system**
- `RuleAnalyzer` protocol for custom analyzers (PEP 561 `py.typed` included).
- `register_analyzer()` API and setuptools entry_point discovery.

**Analyzers (54 finding codes)**
- META-001 to META-007: metadata hygiene (missing fields, invalid UUID, short description, few tags).
- NOISE-001 to NOISE-010: noise risk (wildcards, regex, leading wildcards, generic fields, thin logic, short substrings, IOC dumps, OR-storms).
- STRUCT-001 to STRUCT-008: structural issues (logsource, detection, condition coherence, undefined/unreferenced selections).
- MAINT-001 to MAINT-006: maintainability (selection sprawl, condition complexity, nesting, long conditions, large value sets).
- WEAK-001 to WEAK-009: analytical weakness (single selector, wildcard-heavy, contains-only, low diversity, severity inflation, pure negation, filter-only, vague values, low semantic precision).
- DOC-001 to DOC-006: documentation quality (title clarity, generic titles, terse descriptions, placeholder FPs, non-URL references).
- ATK-001 to ATK-006: ATT&CK mapping quality (missing tags, tactic-only, technique-only, unknown tactics, malformed IDs, no sub-techniques).
- CORR-001 to CORR-004: correlation rule quality (missing type, group-by, timespan, base rules).
- DUP-001: duplicate detection.
- OVL-001: behavioral overlap detection.
- PARSE-001: YAML parsing failures.

**Semantic diff (15 change codes)**
- SEM-LOGSOURCE, SEM-BROADER-001/002, SEM-TIGHTER-001/002, SEM-WEAKER-001/002, SEM-STRONGER-001/002, SEM-COVERAGE-001/002, SEM-SEVERITY-001/002, SEM-MAINT-001/002.

**Test suite**
- 310 tests, coverage threshold 90%, branch coverage enabled.
- Full CLI contract tests via `typer.testing.CliRunner`.
- Console dispatch integration tests.
- Reporter snapshot tests (HTML, JSON, SARIF, Markdown).
- Plugin system integration tests.
- Parser edge case tests.
- Finding registry validation test (ensures all emitted codes have remediation suggestions).
- French localization path tests.

**CI/CD**
- GitHub Actions workflow (lint, test, build, smoke) on Python 3.10–3.13.
- GitHub Action for PR quality gates (`action.yml`).
- Strict linting: ruff with no suppressed import or dead-variable warnings.
- Makefile for common development tasks.
