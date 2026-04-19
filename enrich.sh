#!/usr/bin/env bash
set -euo pipefail

COMPOSE="docker compose"
ES_HOST=$(grep ES_HOST .env 2>/dev/null | cut -d= -f2 | tr -d ' ' || echo "http://host.docker.internal:9200")

usage() {
  cat <<EOF
Usage: ./enrich.sh <command>

Commands:
  run           Run all enrichments
  threat-intel  Run threat-intel enrichment only
  redirect      Run redirect enrichment only

  reset-db      Delete domain_mappings.db
  reset-es      Clear all enrichment fields from Elasticsearch
  reset         Interactive: choose what to reset
EOF
}

case "${1:-}" in

  run)
    touch domain_mappings.db
    $COMPOSE exec enrichment python run.py
    ;;

  threat-intel)
    touch domain_mappings.db
    $COMPOSE exec enrichment python run.py --enrichment threat-intel
    ;;

  redirect)
    touch domain_mappings.db
    $COMPOSE exec enrichment python run.py --enrichment redirect
    ;;

  reset-db)
    rm -f domain_mappings.db
    echo "domain_mappings.db deleted."
    ;;

  reset-es)
    echo "Clearing enrichment fields from ${ES_HOST}..."
    curl -s -X POST "${ES_HOST}/suricata-*/_update_by_query" \
      -H 'Content-Type: application/json' \
      -d '{"script":{"source":"ctx._source.remove(\"enrichment\")"},"query":{"match_all":{}}}' \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Cleared {d[\"updated\"]} docs')"
    ;;

  reset)
    echo "What to reset?"
    echo "  1) Mapping DB only (domain_mappings.db)"
    echo "  2) ES enrichment data only"
    echo "  3) Both"
    read -rp "Choice [1/2/3]: " choice
    case "$choice" in
      1) bash "$0" reset-db ;;
      2) bash "$0" reset-es ;;
      3) bash "$0" reset-db && bash "$0" reset-es ;;
      *) echo "Invalid choice." && exit 1 ;;
    esac
    ;;

  *)
    usage
    ;;
esac
