#!/usr/bin/env bash
# appsec-compose — one-command OSS AppSec scan.
#
#   ./run.sh <path-to-repo>  [--fail-on L] [--update-baseline]
#   ./run.sh --image <ref>   [--fail-on L]        # scan a container image
#
# Reads scan-config.yml, runs the enabled scanners over the target (repo or
# image) and writes reports to ./reports/. Exit code mirrors the collector's
# policy verdict (0 = pass, 1 = fail).
set -euo pipefail

usage() {
  echo "Usage: $0 <path-to-repo> [--fail-on L] [--update-baseline]" >&2
  echo "       $0 --image <ref> [--registry-user U --registry-pass P] [--fail-on L]" >&2
  echo "       $0 --build <context> [--dockerfile <path>] [--fail-on L]" >&2
  exit 2
}

# Scanners that can scan a container image (the rest are source-only).
IMAGE_TOOLS=" trivy grype syft "

TARGET=""; IMAGE_REF=""; BUILD_CTX=""; DOCKERFILE=""; FAIL_ON_OVERRIDE=""
REG_USER="${REGISTRY_USER:-}"; REG_PASS="${REGISTRY_PASS:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE_REF="${2:-}"; shift 2 ;;
    --build) BUILD_CTX="${2:-}"; shift 2 ;;
    --dockerfile) DOCKERFILE="${2:-}"; shift 2 ;;
    --registry-user) REG_USER="${2:-}"; shift 2 ;;
    --registry-pass) REG_PASS="${2:-}"; shift 2 ;;
    --fail-on) FAIL_ON_OVERRIDE="${2:-}"; shift 2 ;;
    --update-baseline) export ASS_UPDATE_BASELINE=1; shift ;;
    -h|--help) usage ;;
    -*) echo "Unknown argument: $1" >&2; usage ;;
    *) TARGET="$1"; shift ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
# Empty dir for the (unused) /code mount in image mode; in-project so Docker can
# always bind-mount it. .img-archive holds a saved image tar in build mode.
mkdir -p .img-empty .img-archive

# Derive the registry host from an image ref (for the docker auth config key).
registry_of() {
  local ref="$1" first="${1%%/*}"
  if [[ "$ref" == */* && ( "$first" == *.* || "$first" == *:* || "$first" == "localhost" ) ]]; then
    echo "$first"
  else
    echo "https://index.docker.io/v1/"
  fi
}

IMAGE_MODE=0; TARGET_LABEL=""
if [[ -n "$BUILD_CTX" ]]; then
  IMAGE_MODE=1
  [[ -e "$BUILD_CTX" ]] || { echo "Error: build context '$BUILD_CTX' not found" >&2; exit 2; }
  tag="appsec-compose-build:scan"
  echo "Building image from $BUILD_CTX ..."
  if [[ -n "$DOCKERFILE" ]]; then
    docker build -f "$DOCKERFILE" -t "$tag" "$BUILD_CTX"
  else
    docker build -t "$tag" "$BUILD_CTX"
  fi
  docker save "$tag" -o .img-archive/image.tar
  export ASS_IMAGE_TAR="/archive/image.tar"
  SCAN_TARGET="$SCRIPT_DIR/.img-empty"
  TARGET_LABEL="built image from $BUILD_CTX"
elif [[ -n "$IMAGE_REF" ]]; then
  IMAGE_MODE=1
  export ASS_IMAGE="$IMAGE_REF"
  SCAN_TARGET="$SCRIPT_DIR/.img-empty"
  TARGET_LABEL="image $IMAGE_REF"
  if [[ -n "$REG_USER" && -n "$REG_PASS" ]]; then
    reg="$(registry_of "$IMAGE_REF")"
    b64="$(printf '%s:%s' "$REG_USER" "$REG_PASS" | base64 | tr -d '\n')"
    mkdir -p .docker-auth
    printf '{"auths":{"%s":{"auth":"%s"}}}' "$reg" "$b64" > .docker-auth/config.json
    chmod 600 .docker-auth/config.json
    export ASS_DOCKER_CONFIG="$SCRIPT_DIR/.docker-auth"
    echo "Registry auth : configured for $reg"
  fi
elif [[ -n "$TARGET" ]]; then
  [[ -d "$TARGET" ]] || { echo "Error: target '$TARGET' is not a directory" >&2; exit 2; }
  SCAN_TARGET="$(cd "$TARGET" && pwd)"
  TARGET_LABEL="$SCAN_TARGET"
else
  usage
fi
export SCAN_TARGET

# Render scan-config.yml -> .env (versions + flags) and read the enabled list.
# render-env reads ASS_IMAGE to pick filesystem vs image targets.
eval "$(python3 scripts/render-env.py)"
[[ -n "$FAIL_ON_OVERRIDE" ]] && export FAIL_ON="$FAIL_ON_OVERRIDE"

mkdir -p reports/native cache/semgrep cache/trivy cache/grype semgrep-rules
# Ensure the baseline file exists so Docker can bind-mount it (empty = no baseline).
[[ -f appsec-baseline.json ]] || echo '{"fingerprints": []}' > appsec-baseline.json

# In image mode keep only image-capable scanners.
if [[ "$IMAGE_MODE" == "1" ]]; then
  keep=""
  for s in $ASS_ENABLED; do [[ "$IMAGE_TOOLS" == *" $s "* ]] && keep="$keep $s"; done
  ASS_ENABLED="$(echo "$keep" | xargs || true)"
  [[ -z "$ASS_ENABLED" ]] && { echo "Error: image mode needs trivy/grype/syft enabled" >&2; exit 2; }
fi

if [[ -z "${ASS_ENABLED// }" ]]; then
  echo "Error: no scanners enabled in scan-config.yml" >&2; exit 2
fi
export ASS_ENABLED   # tell the collector which scanners actually ran

if [[ "$ASS_OFFLINE" == "1" && "$IMAGE_MODE" != "1" && ! -s cache/semgrep/default.yaml ]]; then
  echo "Error: offline=true but no cache found. Run ./preload.sh first (with network)." >&2
  exit 2
fi

echo "Target   : $TARGET_LABEL"
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
