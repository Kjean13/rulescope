# RuleScope use cases

## Detection content release gate
Use `compare` and `ci` to block releases when a candidate catalog regresses against the baseline.

## Catalog debt review
Use `scan`, `maintainers`, and the HTML report to prioritize duplicates, overlap, weak metadata, and weak rules.

## Analyst coaching and rule hardening
Use `explain --all --max-rules N` to turn the weakest N rules into a concrete remediation queue for junior analysts or students.
