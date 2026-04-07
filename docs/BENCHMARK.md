# Benchmark: RuleScope on SigmaHQ

Benchmark run against the full [SigmaHQ](https://github.com/SigmaHQ/sigma) `rules/` directory (core rules only).

## Summary

| Metric | Value |
|--------|-------|
| Total rules | 3111 |
| Parse rate | **100.0%** (0 failures) |
| Average rule score | 96/100 |
| Median rule score | 97/100 |
| Catalog score (with debt penalties) | 52/100 |
| Total findings | 13,922 |
| Throughput | **48.8 rules/second** (~20ms per rule) |
| Total scan time | 64 seconds |

## Parse Rate

RuleScope parsed all 3,111 SigmaHQ rules without a single failure, including:
- Rules with 400+ values in a single selector (e.g. DLL sideloading lists)
- Rules with 10+ selection blocks and complex boolean conditions
- Rules targeting 30+ logsource types (Windows, Linux, macOS, AWS, Azure, GCP, etc.)
- Multi-document YAML files with global metadata sections

## Score Distribution

| Range | Rules | Percentage |
|-------|-------|------------|
| 90–100 | 3,098 | 99.6% |
| 75–89 | 13 | 0.4% |
| 50–74 | 0 | 0% |
| < 50 | 0 | 0% |

99.6% of SigmaHQ rules score 90+ at the individual rule level, confirming that the SigmaHQ maintainers enforce strong per-rule quality.

## Catalog Score Explanation

The catalog-level score of 52/100 reflects **catalog-wide debt**, not individual rule weakness:

- **304 duplicate clusters**: near-identical rules across the catalog
- **37K overlap pairs**: rules on the same logsource sharing significant detection patterns (primarily `windows/process_creation`, which has 1,167 rules)
- **556 analytically weak rules** (weakness < 70): primarily antivirus detection rules with single-selector, contains-only, single-field patterns

This is expected behavior — RuleScope intentionally penalizes catalog-level debt that individual rule linters cannot see.

## Finding Distribution

| Category | Findings | Notes |
|----------|----------|-------|
| weakness | 4,687 | Single selectors, contains-only matching, low field diversity |
| attack | 3,741 | Missing sub-techniques, tactic-only mappings |
| documentation | 1,946 | Terse descriptions, placeholder false positive entries |
| overlap | 1,822 | Significant detection overlap within logsource groups |
| noise | 609 | Wildcard-heavy rules, leading wildcards |
| maintainability | 494 | Complex conditions, large value sets |
| metadata | 320 | Few tags, missing dates |
| duplicate | 300 | Near-identical rule pairs |
| structural | 3 | Empty selections |

## Top Logsources

| Logsource | Rules |
|-----------|-------|
| windows/process_creation | 1,167 |
| windows/registry_set | 204 |
| windows/file_event | 165 |
| windows/ps_script | 160 |
| windows/security | 144 |
| linux/process_creation | 119 |
| windows/image_load | 98 |
| macos/process_creation | 67 |
| windows/system | 63 |
| aws/cloudtrail | 55 |

## Performance Notes

- Overlap detection uses sampling for logsource groups with 150+ rules to avoid O(n²) explosion
- Cross-logsource duplicate detection uses length-based early-exit to skip obviously dissimilar pairs
- The full SigmaHQ scan completes in ~64 seconds on a single core with no parallelization

## Weakest Rules (sample)

| Score | Title | Primary Issues |
|-------|-------|----------------|
| 85 | Malware User Agent | Leading wildcards, 106 values, high wildcard count |
| 87 | CrackMapExec Execution Patterns | All-wildcard detection |
| 87 | Suspicious Spool Service Child Process | 10+ selection blocks, complex condition |
| 88 | Potential System DLL Sideloading | 422 values in one selector |
| 88 | PowerShell Command Line Obfuscation | Complex condition, generic fields at high severity |

These are legitimate quality signals — not false positives.
