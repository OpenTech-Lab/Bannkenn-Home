#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# push-image.sh — Build and push device-monitor to Docker Hub
# Usage:
#   ./scripts/push-image.sh              # build for host arch only
#   ./scripts/push-image.sh --multiarch  # build for amd64 + arm64 (Synology ARM)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$ROOT_DIR/.env"

# --- Load .env ----------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: .env file not found at $ENV_FILE"
  echo "       Copy .env.example to .env and fill in your values."
  exit 1
fi

set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

# --- Validate required vars ---------------------------------------------
MISSING=()
[[ -z "${DOCKERHUB_USERNAME:-}" ]] && MISSING+=("DOCKERHUB_USERNAME")
[[ -z "${DOCKERHUB_TOKEN:-}" ]]    && MISSING+=("DOCKERHUB_TOKEN")
[[ -z "${IMAGE_NAME:-}" ]]         && MISSING+=("IMAGE_NAME")

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "ERROR: Missing required variables in .env:"
  printf '  - %s\n' "${MISSING[@]}"
  exit 1
fi

# --- Resolve tag --------------------------------------------------------
TAG="${IMAGE_TAG:-latest}"
FULL_IMAGE="$DOCKERHUB_USERNAME/$IMAGE_NAME:$TAG"

# --- Docker Hub login ---------------------------------------------------
echo "Logging in to Docker Hub as $DOCKERHUB_USERNAME ..."
echo "$DOCKERHUB_TOKEN" | docker login --username "$DOCKERHUB_USERNAME" --password-stdin

# --- Build --------------------------------------------------------------
MULTIARCH=false
if [[ "${1:-}" == "--multiarch" ]]; then
  MULTIARCH=true
fi

if [[ "$MULTIARCH" == "true" ]]; then
  echo "Building multi-arch image (amd64 + arm64): $FULL_IMAGE"

  # Ensure buildx builder with multi-platform support exists
  if ! docker buildx inspect multiarch-builder &>/dev/null; then
    docker buildx create --name multiarch-builder --use
  else
    docker buildx use multiarch-builder
  fi

  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag "$FULL_IMAGE" \
    --push \
    "$ROOT_DIR/device-monitor"
else
  echo "Building image for host architecture: $FULL_IMAGE"
  docker build \
    --tag "$FULL_IMAGE" \
    "$ROOT_DIR/device-monitor"

  echo "Pushing $FULL_IMAGE ..."
  docker push "$FULL_IMAGE"
fi

echo ""
echo "Done! Image available at: https://hub.docker.com/r/$DOCKERHUB_USERNAME/$IMAGE_NAME"
echo ""
echo "On your NAS, update docker-compose.yml:"
echo "  image: $FULL_IMAGE"
