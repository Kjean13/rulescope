# RuleScope PR Gate

The repository includes `.github/workflows/pr-gate.yml`.

## What it does

- checks out the pull request head
- checks out the base branch in a temporary worktree
- compares the baseline rule catalog vs the candidate catalog
- uploads Markdown, HTML, and JSON artifacts
- writes a GitHub Actions job summary
- updates a sticky pull request comment
- fails the workflow if the candidate catalog regresses

## How to configure it

You can provide the rules path in three ways:

1. directly in the workflow
2. with a repository variable named `DETECTION_RULES_PATH`
3. through `workflow_dispatch`

Example paths:

```yaml
examples/rules
sigma/rules
detections/sigma
content/detections
```

## Main enforcement point

```bash
rulescope compare .pr_gate/base/$DETECTION_RULES_PATH $DETECTION_RULES_PATH --fail-on-regression
```

That means a pull request can still generate artifacts even if it eventually fails on regression.

## Local validation script

The repository also includes:

```bash
.github/scripts/validate_pr_gate_local.sh <repo-path> <base-ref> <candidate-ref> [rules-path]
```

It replays the same baseline-vs-candidate logic with Git worktrees on a local repository.

Included proof files:

- `docs/demo_outputs/pr_gate_local_test.txt`
- `docs/demo_outputs/pr_gate_compare.md`

Those files were generated from a local replay where the gate correctly failed with exit code `1` on a regression.
