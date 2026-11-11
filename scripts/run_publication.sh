#!/usr/bin/env bash
# Freeze a clean Git revision and automatically generate all reviewer evidence.
set -euo pipefail
suite="${1:-cove-confirmation}"
case "$suite" in
  reviewer-controls|cove-confirmation) ;;
  *) echo "Allowed suites: reviewer-controls, cove-confirmation" >&2; exit 2 ;;
esac
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing publication experiment from a dirty/untracked checkout." >&2
  exit 1
fi
export SWARM_COMMIT
SWARM_COMMIT="$(git rev-parse --verify HEAD)"
if [[ ! "$SWARM_COMMIT" =~ ^[a-f0-9]{40}$ ]]; then
  echo "Cannot identify the exact clean Git source revision." >&2
  exit 1
fi
echo "Building and running frozen revision: $SWARM_COMMIT"
docker compose build --no-cache
docker compose run --rm experiment run --suite "/app/scenarios/${suite}.yaml"
archive="$(find results -maxdepth 1 -type f -name "${suite}-*-evidence.zip" | sort | tail -1)"
if [[ -z "$archive" || ! -s "$archive" ]]; then
  echo "No complete evidence ZIP was produced." >&2
  exit 1
fi
printf 'Reviewer evidence: %s\nSource commit: %s\n' "$archive" "$SWARM_COMMIT"
