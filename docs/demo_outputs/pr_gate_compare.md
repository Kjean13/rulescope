# RuleScope Compare Report

- **Generated:** `2026-03-21T03:10:10.915134+00:00`
- **Verdict:** **Regression**

## Summary

| Metric | Baseline | Candidate | Delta |
|--------|----------|-----------|-------|
| Catalog score | 69 | 64 | -5 |
| Duplicate pairs | - | - | -1 |
| Overlap pairs | - | - | +2 |
| Weak rules | - | - | +3 |

## Takeaways

- Catalog score delta: -5 points.
- Duplicate pairs delta: -1.
- Overlap pairs delta: +2.
- Analytically weak rules delta: +3.
- Rules added/removed: +1 / -0.
- Rules with material regressions: 2.
- New high/critical findings introduced: 3.

## Strongest Regressions

- `suspicious_powershell.yml` — 98 → 88 (-10)
- `weak_metadata_rule.yml` — 83 → 76 (-7)
