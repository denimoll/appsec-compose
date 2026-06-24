#!/usr/bin/env bash
# appsec-compose — one-command OSS AppSec scan.
#
#   ./run.sh <path-to-repo> [--fail-on critical|high|medium|low|none]
#
# Reads scan-config.yml, runs the enabled scanners over the target repo and
# writes reports to ./reports/. Exit code mirrors the collector's policy
# verdict (0 = pass, 1 = fail).
set -euo pipefail

usage() {
  echo "Usage: $0 <path-to-repo> [--fail-on critical|high|medium|low|none] [--update-baseline]" >&2
  exit 2
}

[[ $# -lt 1 ]] && usage
TARGET="$1"; shift
FAIL_ON_OVERRIDE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fail-on) FAIL_ON_OVERRIDE="${2:-}"; shift 2 ;;
    --update-baseline) export ASS_UPDATE_BASELINE=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ -d "$TARGET" ]] || { echo "Error: target '$TARGET' is not a directory" >&2; exit 2; }

SCAN_TARGET="$(cd "$TARGET" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCAN_TARGET
cd "$SCRIPT_DIR"

# Render scan-config.yml -> .env (versions + flags) and read the enabled list.
eval "$(python3 scripts/render-env.py)"
[[ -n "$FAIL_ON_OVERRIDE" ]] && export FAIL_ON="$FAIL_ON_OVERRIDE"

mkdir -p reports/native cache/semgrep cache/trivy cache/grype
# Ensure the baseline file exists so Docker can bind-mount it (empty = no baseline).
[[ -f appsec-baseline.json ]] || echo '{"fingerprints": []}' > appsec-baseline.json

if [[ -z "${ASS_ENABLED// }" ]]; then
  echo "Error: no scanners enabled in scan-config.yml" >&2; exit 2
fi

if [[ "$ASS_OFFLINE" == "1" && ! -s cache/semgrep/default.yaml ]]; then
  echo "Error: offline=true but no cache found. Run ./preload.sh first (with network)." >&2
  exit 2
fi

echo "Scanning : $SCAN_TARGET"
echo "Scanners : $ASS_ENABLED"
echo "Mode     : $([[ "$ASS_OFFLINE" == "1" ]] && echo offline || echo online)"
[[ -n "${FAIL_ON_OVERRIDE}" ]] && echo "fail_on  : $FAIL_ON_OVERRIDE (override)"
[[ "${ASS_UPDATE_BASELINE:-}" == "1" ]] && echo "baseline : updating snapshot"

docker compose down --remove-orphans >/dev/null 2>&1 || true

# Run the enabled scanners in parallel (one-shot). Plain `up` (no
# --abort-on-container-exit) waits for every listed service to finish.
# shellcheck disable=SC2086
docker compose up --no-deps $ASS_ENABLED

# Collector reads the reports and returns the policy exit code. --no-deps so it
# doesn't re-trigger the scanners via depends_on.
set +e
docker compose run --rm --no-deps --build collector
code=$?
set -e

docker compose down --remove-orphans >/dev/null 2>&1 || true

echo
echo "Done. See ./reports/summary.md (exit code: $code)"
exit "$code"
