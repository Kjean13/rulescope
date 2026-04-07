#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 3 ]; then
  echo "Usage: $0 <repo-path> <base-ref> <candidate-ref> [rules-path]" >&2
  exit 2
fi

REPO_PATH="$1"
BASE_REF="$2"
CANDIDATE_REF="$3"
RULES_PATH="${4:-examples/rules}"
ARTIFACT_DIR="$REPO_PATH/.pr_gate_local_artifacts"

rm -rf "$ARTIFACT_DIR" "$REPO_PATH/.pr_gate_local"
mkdir -p "$ARTIFACT_DIR" "$REPO_PATH/.pr_gate_local"

pushd "$REPO_PATH" >/dev/null

git checkout "$CANDIDATE_REF" >/dev/null 2>&1

git worktree add .pr_gate_local/base "$BASE_REF" >/dev/null 2>&1

rulescope compare \
  ".pr_gate_local/base/$RULES_PATH" \
  "$RULES_PATH" \
  --format markdown \
  --output "$ARTIFACT_DIR/compare.md"

rulescope report "$RULES_PATH" --output "$ARTIFACT_DIR/rulescope_report.html" >/dev/null
rulescope scan "$RULES_PATH" --format json --output "$ARTIFACT_DIR/catalog.json" >/dev/null

set +e
rulescope compare \
  ".pr_gate_local/base/$RULES_PATH" \
  "$RULES_PATH" \
  --fail-on-regression > "$ARTIFACT_DIR/enforce.txt" 2>&1
EXIT_CODE=$?
set -e

git worktree remove .pr_gate_local/base --force >/dev/null 2>&1 || true

popd >/dev/null

echo "Local PR gate exit code: $EXIT_CODE"
echo "Artifacts: $ARTIFACT_DIR"
exit 0
