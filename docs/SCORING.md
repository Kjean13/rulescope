# RuleScope scoring model

RuleScope scores each rule across seven weighted pillars.
The defaults below are calibrated against the SigmaHQ catalog (3 100+ rules) and can be overridden in `.rulescope.yml`.

## Pillars

| Pillar | Default weight | What it checks |
|---|---|---|
| `noise` | 22% | Wildcard abuse, leading wildcards, OR-storms, IOC dumps, severity vs confidence alignment |
| `weakness` | 22% | Field precision, modifier strength, value specificity, negation patterns, filter-only detection |
| `attack_quality` | 18% | ATT&CK tactic/technique coverage, sub-technique usage, malformed tag IDs |
| `metadata` | 10% | Required fields, UUID validity, lifecycle status, references, tags |
| `maintainability` | 10% | Condition complexity, selection sprawl, nesting depth, large value sets |
| `documentation` | 10% | Title clarity, description quality, false-positive guidance |
| `structural` | 8% | Logsource completeness, detection block validity, condition/selection coherence |

## Design principles

1. Broken detection logic must dominate the score — structural failure cannot be masked by good metadata.
2. A rule can look clean in YAML and still be operationally weak. Noise and weakness carry the highest weight for that reason.
3. Every finding maps to a concrete remediation suggestion (`explain` command).
4. Scan, explain, compare, and maintainer views all derive from the same per-rule findings — no hidden logic.
5. Leading wildcards and broad `contains` patterns have measurable SIEM infrastructure cost; the score reflects that.

## Score bands

- **90–100** — production-ready, minor polish remaining
- **75–89** — solid, worth a review pass before promotion
- **50–74** — needs work before merge
- **0–49** — broken logic, excessive noise, or missing structure

## Limits

The score is a governance signal, not a replacement for telemetry validation or analyst judgment.
A high score does not guarantee detection efficacy in a given SIEM or data environment.
A low score on an intentionally broad hunting rule does not mean the rule is wrong.

## v1.0 weakness refinements

Weakness scoring in v1.0 moves beyond wildcard counting to three grounded signals:

- **Field precision** — anchored fields (`OriginalFileName`, `Image`, `Hashes`, `EventID`) carry more weight than generic free-text fields like `CommandLine`.
- **Modifier strength** — `endswith`, `startswith`, and exact matches score higher than `contains`.
- **Value specificity** — full binary names, hashes, and long discriminating strings score higher than short fragments like `pass` or `tmp`.

Lifecycle status is used as a calibration hint: `deprecated` and `unsupported` cap the weakness score; `experimental` rules cannot score artificially high.
