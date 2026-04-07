# Semantic diff model

RuleScope semantic diff focuses on **meaningful rule drift**, not only text drift.

## Signals currently tracked

- wildcard growth or reduction
- broader `contains` usage
- stronger bounded or exact modifiers
- selector count changes
- field diversity changes
- ATT&CK technique coverage drift
- severity inflation without stronger quality
- condition complexity drift
- logsource changes

## Intent

The compare engine is meant to answer:

- did this rule become broader?
- did it lose context or selectivity?
- did it become harder to maintain?
- did severity increase without stronger logic?

## Limits

This is still a heuristic semantic layer.
It improves PR review quality, but it does not replace full behavioral validation against real telemetry.

## Current limits

- Semantic diff relies on curated heuristics and normalized rule structure, not full semantic equivalence proving.
- It is optimized to catch review-relevant drift such as broader matching, weaker selectors, and coverage loss.
- Results should be reviewed by a maintainer before release or enforcement policy changes.


## Relationship with duplicate detection

Semantic diff and duplicate detection now share the same philosophy: compare the **event surface** of a rule, not its prose. In practice this means the engine compares fields, modifiers, normalized values, and condition logic before calling two rules near-identical.
