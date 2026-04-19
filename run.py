"""
Main entry point. Runs one or more enrichments against Elasticsearch.

Usage:
  python run.py                          # run all enrichments
  python run.py --enrichment threat-intel
  python run.py --enrichment redirect
"""

import argparse
import logging
import os
import sys

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")


def get_es_client() -> Elasticsearch:
    kwargs: dict = {"hosts": [ES_HOST]}
    if ES_USER and ES_PASS:
        kwargs["basic_auth"] = (ES_USER, ES_PASS)
    client = Elasticsearch(**kwargs)
    try:
        info = client.info()
        log.info("Connected to Elasticsearch %s at %s", info["version"]["number"], ES_HOST)
    except Exception as exc:
        raise ConnectionError(f"Cannot reach Elasticsearch at {ES_HOST}: {exc}")
    return client


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC data enrichment runner")
    parser.add_argument(
        "--enrichment",
        choices=["threat-intel", "redirect", "all"],
        default="all",
        help="Which enrichment to run (default: all)",
    )
    args = parser.parse_args()

    es = get_es_client()

    if args.enrichment in ("threat-intel", "all"):
        log.info("=== Running: threat-intel enrichment ===")
        from enrichments.threat_intel import process_alerts
        process_alerts(es)

    if args.enrichment in ("redirect", "all"):
        log.info("=== Running: redirect analysis enrichment ===")
        from enrichments.redirect import process_redirect_alerts
        process_redirect_alerts(es)


if __name__ == "__main__":
    main()
