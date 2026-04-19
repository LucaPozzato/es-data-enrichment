#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: ./docker.sh <command>

Commands:
  start   Build the image and prepare for first run
  stop    Stop and remove the enrichment container
  reset   Rebuild the Docker image from scratch (no cache)
EOF
}

case "${1:-}" in

  start)
    touch domain_mappings.db
    echo "Building enrichment image..."
    docker compose build enrichment
    echo "Starting enrichment container..."
    docker compose up -d enrichment
    echo "Done. Container running as es-enrichment."
    ;;

  stop)
    echo "Stopping enrichment container..."
    docker compose down enrichment 2>/dev/null || true
    echo "Done."
    ;;

  reset)
    echo "Rebuilding enrichment image from scratch..."
    docker compose down 2>/dev/null || true
    docker compose build --no-cache enrichment
    touch domain_mappings.db
    docker compose up -d enrichment
    echo "Done. Container running as es-enrichment."
    ;;

  -h|--help|*)
    usage
    ;;

esac
