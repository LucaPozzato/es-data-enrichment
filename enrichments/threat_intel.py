import ipaddress
import os
import random
import time
import logging
from datetime import datetime, timezone

import requests
from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_RATE_LIMIT_DELAY = 15
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
ES_INDEX = os.getenv("ES_INDEX", "suricata-*")

MOCK_COUNTRIES = ["US", "CN", "RU", "DE", "NL", "BR", "FR", "KR", "IN", "UA"]
MOCK_ISPS = [
    "AS13335 Cloudflare", "AS15169 Google", "AS16509 Amazon",
    "AS3320 Deutsche Telekom", "AS9009 M247",
]


def vt_lookup(ioc: str, ioc_type: str) -> dict:
    """
    ioc_type: "ip" or "domain"
    TODO: uncomment real implementation when API key is available.
    """
    # if not VT_API_KEY:
    #     return {"error": "no_api_key"}
    # endpoint = "ip_addresses" if ioc_type == "ip" else "domains"
    # url = f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}"
    # headers = {"x-apikey": VT_API_KEY}
    # try:
    #     resp = requests.get(url, headers=headers, timeout=10)
    #     if resp.status_code == 404:
    #         return {"found": False}
    #     resp.raise_for_status()
    #     data = resp.json().get("data", {}).get("attributes", {})
    #     stats = data.get("last_analysis_stats", {})
    #     return {
    #         "found": True,
    #         "malicious": stats.get("malicious", 0),
    #         "suspicious": stats.get("suspicious", 0),
    #         "harmless": stats.get("harmless", 0),
    #         "undetected": stats.get("undetected", 0),
    #         "reputation": data.get("reputation", 0),
    #         "country": data.get("country", ""),
    #         "as_owner": data.get("as_owner", ""),
    #     }
    # except requests.RequestException as e:
    #     log.warning("VT lookup failed for %s: %s", ioc, e)
    #     return {"error": str(e)}
    malicious = random.randint(0, 15)
    suspicious = random.randint(0, 5)
    harmless = random.randint(40, 72)
    undetected = 72 - malicious - suspicious - harmless
    return {
        "found": True, "mock": True,
        "malicious": malicious, "suspicious": suspicious,
        "harmless": max(harmless, 0), "undetected": max(undetected, 0),
        "reputation": random.randint(-100, 10),
        "country": random.choice(MOCK_COUNTRIES),
        "as_owner": random.choice(MOCK_ISPS),
    }


def abuseipdb_lookup(ip: str) -> dict:
    # TODO: uncomment real implementation when API key is available.
    # if not ABUSEIPDB_API_KEY:
    #     return {"error": "no_api_key"}
    # url = "https://api.abuseipdb.com/api/v2/check"
    # headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    # params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": False}
    # try:
    #     resp = requests.get(url, headers=headers, params=params, timeout=10)
    #     resp.raise_for_status()
    #     data = resp.json().get("data", {})
    #     return {
    #         "found": True,
    #         "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
    #         "total_reports": data.get("totalReports", 0),
    #         "country_code": data.get("countryCode", ""),
    #         "domain": data.get("domain", ""),
    #         "isp": data.get("isp", ""),
    #         "is_tor": data.get("isTor", False),
    #         "last_reported_at": data.get("lastReportedAt", ""),
    #     }
    # except requests.RequestException as e:
    #     log.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
    #     return {"error": str(e)}
    return {
        "found": True, "mock": True,
        "abuse_confidence_score": random.randint(0, 100),
        "total_reports": random.randint(0, 500),
        "country_code": random.choice(MOCK_COUNTRIES),
        "isp": random.choice(MOCK_ISPS),
        "is_tor": random.choice([True, False, False, False]),
        "last_reported_at": datetime.now(timezone.utc).isoformat(),
    }


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def extract_ioc(doc: dict) -> tuple[str, str] | tuple[None, None]:
    queries = doc.get("dns", {}).get("queries", [])
    if queries and isinstance(queries, list):
        name = queries[0].get("rrname")
        if name:
            return name, "domain"

    sni = doc.get("tls", {}).get("sni")
    if sni:
        return sni, "domain"

    dest_ip = doc.get("dest_ip")
    if dest_ip and not is_private_ip(dest_ip):
        return dest_ip, "ip"

    src_ip = doc.get("src_ip")
    if src_ip and not is_private_ip(src_ip):
        return src_ip, "ip"

    return None, None


_ioc_cache: dict[str, dict] = {}


def enrich_ioc(ioc: str, ioc_type: str) -> dict:
    if ioc in _ioc_cache:
        return _ioc_cache[ioc]
    log.info("Threat-intel enriching %s: %s", ioc_type, ioc)
    result: dict = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "virustotal": vt_lookup(ioc, ioc_type),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }
    if ioc_type == "ip":
        result["abuseipdb"] = abuseipdb_lookup(ioc)
    # time.sleep(VT_RATE_LIMIT_DELAY)  # uncomment when real API keys are active
    _ioc_cache[ioc] = result
    return result


def build_enrichment(doc: dict) -> dict:
    ioc, ioc_type = extract_ioc(doc)
    if ioc is None:
        return {"processed": True, "skipped": True, "skip_reason": "no_public_ioc"}
    enrichment = enrich_ioc(ioc, ioc_type)
    enrichment["processed"] = True
    return enrichment


def process_alerts(es: Elasticsearch) -> None:
    base_filter = {"must_not": [{"exists": {"field": "enrichment.threat_intel.processed"}}]}
    queries = [
        {"bool": {"must": [{"term": {"event_type": "alert"}}], **base_filter}},
        {"bool": {"must": [{"term": {"event.type": "alert"}}], **base_filter}},
    ]

    pit = es.open_point_in_time(index=ES_INDEX, keep_alive="5m")
    pit_id = pit["id"]
    processed = 0

    try:
        for query in queries:
            search_after = None
            while True:
                body = {
                    "query": query,
                    "size": BATCH_SIZE,
                    "sort": [{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
                    "pit": {"id": pit_id, "keep_alive": "5m"},
                }
                if search_after:
                    body["search_after"] = search_after

                resp = es.search(body=body)
                hits = resp["hits"]["hits"]
                pit_id = resp.get("pit_id", pit_id)
                if not hits:
                    break

                for hit in hits:
                    enrichment = build_enrichment(hit["_source"])
                    es.update(index=hit["_index"], id=hit["_id"],
                              body={"doc": {"enrichment": {"threat_intel": enrichment}}})
                    if not enrichment.get("skipped"):
                        processed += 1
                        log.info("[%d] Threat-intel enriched %s (%s: %s)",
                                 processed, hit["_id"], enrichment["ioc_type"], enrichment["ioc"])
                    else:
                        log.debug("Skipped %s: %s", hit["_id"], enrichment.get("skip_reason"))

                search_after = hits[-1]["sort"]

            if processed > 0:
                break
    finally:
        es.close_point_in_time(body={"id": pit_id})

    log.info("Threat-intel done. Total enriched: %d", processed)
