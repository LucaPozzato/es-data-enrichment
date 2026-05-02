"""
Redirect & reachability analysis enrichment.

For each DNS/TLS alert:
  1. Check mapping DB — if alert domain has a known parent, return immediately
     (no ES query, no HTTP probe, no selenium).
  2. If no known mapping: fetch DNS/TLS events from same src_ip in the
     1 s before the alert, ordered oldest→newest.
  3. HTTP probe the alert domain (for log fields only).
  4. Walk pre-alert domains oldest→newest:
       a. HTTP probe each — skip if unreachable or asset
       b. Visit with headless Chrome + tcpdump
       c. If alert domain appears in _all_domains (CDP + tcpdump) → confirmed:
            original_site = this domain
            relationship  = redirect_target | embedded_resource
            record mappings → stop
       d. Otherwise continue to next pre-alert domain
  5. Score 0-100 / verdict / to_analyze (True if no relationship confirmed).
  6. Write enrichment.redirect to ES.
"""

import json
import logging
import os
import platform
import re
import subprocess
import tempfile
import time
import warnings
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning
from elasticsearch import Elasticsearch

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

log = logging.getLogger(__name__)

ES_INDEX = os.getenv("ES_INDEX", "suricata-*")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))

# Edge 122 on Windows — servers that fingerprint UA see a real Edge client
_EDGE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
)

BROWSER_HEADERS = {
    "User-Agent": _EDGE_UA,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-CH-UA": '"Chromium";v="122", "Microsoft Edge";v="122", "Not-A.Brand";v="99"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

HTTP_TIMEOUT = 1
MAX_READ_BYTES = 51200   # 50 KB — enough to detect redirect patterns
VISITABLE_MIN_BYTES = 5_000
SELENIUM_WAIT_SEC = 2


# ── HTTP probe ─────────────────────────────────────────────────────────────────

_probe_cache: dict[str, dict] = {}


def probe_domain(domain: str) -> dict:
    if domain in _probe_cache:
        return _probe_cache[domain]

    result = {
        "reachable": False, "scheme": None, "status_code": None,
        "final_url": None, "redirect_chain": [], "content_type": "",
        "page_size_bytes": 0, "is_redirect": False,
        "has_meta_refresh": False, "has_js_redirect": False,
    }

    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}", headers=BROWSER_HEADERS,
                timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False, stream=True,
            )
            content = b""
            for chunk in resp.iter_content(4096):
                content += chunk
                if len(content) >= MAX_READ_BYTES:
                    break

            result.update({
                "reachable": True, "scheme": scheme,
                "status_code": resp.status_code, "final_url": resp.url,
                "redirect_chain": [r.url for r in resp.history],
                "content_type": resp.headers.get("Content-Type", ""),
                "page_size_bytes": int(resp.headers.get("Content-Length") or len(content)),
                "is_redirect": bool(resp.history),
            })

            if "text/html" in result["content_type"]:
                text = content.decode("utf-8", errors="ignore").lower()
                result["has_meta_refresh"] = bool(
                    re.search(r'<meta[^>]+http-equiv=["\']refresh["\']', text)
                )
                result["has_js_redirect"] = bool(
                    re.search(
                        r"window\.location\s*=|window\.location\.replace\s*\("
                        r"|window\.location\.href\s*=",
                        text,
                    )
                )
            break
        except requests.RequestException:
            continue

    _probe_cache[domain] = result
    return result


def classify_probe(probe: dict) -> str:
    """
    real_page     — large HTML, no redirect → worth a selenium visit
    redirect      — hard 3xx redirect chain
    soft_redirect — tiny HTML with JS/meta redirect, or featureless stub
    asset         — non-HTML (JSON, image, binary…)
    unreachable   — no response within timeout
    """
    if not probe["reachable"]:
        return "unreachable"
    if "text/html" not in probe.get("content_type", ""):
        return "asset"
    if probe["is_redirect"]:
        return "redirect"
    if probe["has_meta_refresh"] or probe["has_js_redirect"]:
        return "soft_redirect"
    if probe["page_size_bytes"] >= VISITABLE_MIN_BYTES:
        return "real_page"
    return "soft_redirect"


# ── ES lookback ────────────────────────────────────────────────────────────────

def get_pre_alert_domains(
    es: Elasticsearch,
    index: str,
    src_ip: str,
    alert_time: datetime,
    exclude_domain: str,
    window_sec: int = 3,
) -> list[str]:
    """
    Unique domains queried by src_ip in [alert_time - window_sec, alert_time).
    Returned in timestamp order — oldest first — so index 0 is the original site.
    """
    try:
        resp = es.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"event_type": ["dns", "tls"]}},
                            {"term": {"src_ip": src_ip}},
                            {"range": {"@timestamp": {
                                "gte": (alert_time - timedelta(seconds=window_sec)).isoformat(),
                                "lt": alert_time.isoformat(),
                            }}},
                        ]
                    }
                },
                "sort": [{"@timestamp": "asc"}],
                "size": 50,
                "_source": ["dns.queries", "tls.sni"],
            },
        )
    except Exception as exc:
        log.warning("Pre-alert domain query failed: %s", exc)
        return []

    # Preserve timestamp order; deduplicate while keeping first occurrence
    ordered: list[str] = []
    seen_set: set[str] = set()
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        for q in src.get("dns", {}).get("queries", []):
            name = q.get("rrname", "").rstrip(".")
            if name and name != exclude_domain and name not in seen_set:
                ordered.append(name)
                seen_set.add(name)
        sni = src.get("tls", {}).get("sni", "").rstrip(".")
        if sni and sni != exclude_domain and sni not in seen_set:
            ordered.append(sni)
            seen_set.add(sni)

    return ordered  # oldest first


# ── Selenium visit ─────────────────────────────────────────────────────────────

def _tcpdump_iface() -> str:
    return "en0" if platform.system() == "Darwin" else "any"


def _parse_pcap_dns(pcap_path: str) -> set[str]:
    try:
        from scapy.all import rdpcap, DNS, DNSQR  # type: ignore
        domains: set[str] = set()
        for pkt in rdpcap(pcap_path):
            if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                name = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                if name:
                    domains.add(name)
        return domains
    except Exception as exc:
        log.debug("pcap parse skipped: %s", exc)
        return set()


def selenium_visit(domain: str, alert_domain: str) -> dict:
    """
    Headless Chrome visit. Returns exactly 5 enrichment fields plus
    an internal _all_domains set used for mapping DB recording (not stored in ES).

    CDP separates request types:
      type == "Document"  →  browser navigated/redirected to this URL
      everything else     →  sub-resource (script, image, XHR, fetch…)

    redirected_to_alert = True when the browser actually navigated to the alert domain
                          (hard redirect or JS navigation, not just a resource load)
    alert_in_resources  = True when the alert domain was loaded as a sub-resource
                          but the browser never navigated there
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        return {
            "visited_domain": domain, "redirected_to_alert": False,
            "alert_in_resources": False, "unique_domains": 0,
            "capture_method": "none", "_all_domains": set(),
        }

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dns-cache")
    options.add_argument("--dns-prefetch-disable")
    # Spoof Edge — bypass Chrome-specific server-side blocks and Safe Browsing redirects
    options.add_argument(f"--user-agent={_EDGE_UA}")
    options.add_argument(
        '--add-headers=Sec-CH-UA:"Chromium";v="122", "Microsoft Edge";v="122", "Not-A.Brand";v="99"'
    )
    # Block all file downloads — drive-by downloads silently discarded
    options.add_experimental_option("prefs", {
        "download_restrictions": 3,
        "download.default_directory": "/dev/null",
        "safebrowsing.enabled": False,       # no Safe Browsing redirects to warning pages
        "profile.default_content_setting_values.automatic_downloads": 2,
    })
    # Allow mixed HTTP/HTTPS content — see redirects Edge would follow
    options.add_argument("--allow-running-insecure-content")
    options.add_argument("--disable-client-side-phishing-detection")
    options.add_argument("--disable-features=SafeBrowsing")
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    # tcpdump for DNS (port 53) — runs in background, skipped on permission error
    pcap_fd, pcap_path = tempfile.mkstemp(suffix=".pcap")
    os.close(pcap_fd)
    tcpdump_proc = None
    try:
        tcpdump_proc = subprocess.Popen(
            ["tcpdump", "-i", _tcpdump_iface(), "-w", pcap_path, "-q", "port 53"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.2)
        log.debug("tcpdump started on %s", _tcpdump_iface())
    except (FileNotFoundError, PermissionError, OSError) as exc:
        log.debug("tcpdump skipped: %s", exc)
        tcpdump_proc = None

    driver = None
    nav_domains: set[str] = set()       # browser navigated/redirected to these
    resource_domains: set[str] = set()  # loaded as sub-resources

    try:
        # In Docker (Debian) Chrome is installed as /usr/bin/chromium
        import shutil
        if shutil.which("chromium") and not shutil.which("google-chrome"):
            from selenium.webdriver.chrome.service import Service
            driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)
        else:
            driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(10)

        for scheme in ("https", "http"):
            try:
                driver.get(f"{scheme}://{domain}")
                break
            except Exception:
                continue

        time.sleep(SELENIUM_WAIT_SEC)

        for entry in driver.get_log("performance"):
            try:
                msg = json.loads(entry["message"])["message"]
                if msg.get("method") != "Network.requestWillBeSent":
                    continue
                params = msg["params"]
                resource_type = params.get("type", "")
                host = urlparse(params["request"]["url"]).hostname
                if not host:
                    continue
                if resource_type == "Document":
                    nav_domains.add(host)
                else:
                    resource_domains.add(host)
            except (KeyError, json.JSONDecodeError, TypeError):
                pass

        log.debug("CDP nav_domains=%d resource_domains=%d", len(nav_domains), len(resource_domains))

    except Exception as exc:
        log.warning("Selenium visit failed for %s: %s", domain, exc)

    finally:
        if driver:
            driver.quit()
        if tcpdump_proc:
            tcpdump_proc.terminate()
            try:
                tcpdump_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                tcpdump_proc.kill()

    pcap_domains = _parse_pcap_dns(pcap_path)
    try:
        os.unlink(pcap_path)
    except OSError:
        pass

    all_domains = nav_domains | resource_domains | pcap_domains
    capture_method = "cdp+tcpdump" if pcap_domains else "cdp"

    return {
        # ── 5 enrichment fields stored in ES ─────────────────────────────────
        "visited_domain": domain,
        "redirected_to_alert": alert_domain in nav_domains,
        "alert_in_resources": alert_domain in resource_domains and alert_domain not in nav_domains,
        "unique_domains": len(all_domains),
        "capture_method": capture_method,
        # ── internal — used for mapping DB only, stripped before ES write ────
        "_all_domains": all_domains,
    }


# ── Scoring ────────────────────────────────────────────────────────────────────

def _score(
    alert_class: str,
    pre_domains: list[str],
    has_known_mapping: bool,
    relationship: str,
    selenium: dict | None,
) -> tuple[int, str]:
    score = 0

    if has_known_mapping:
        score += 5
    else:
        score += 10  # no prior context = slightly more uncertain

    match alert_class:
        case "unreachable":   score += 15
        case "soft_redirect": score += 20
        case "redirect":      score += 25
        case "real_page":     score += 5
        case "asset":         score += 10

    if pre_domains:
        score += 10

    match relationship:
        case "embedded_resource": score += 20
        case "redirect_target":   score += 25
        case "redirect_source":   score += 15
        case "direct_contact":    score += 15

    if selenium:
        if selenium.get("redirected_to_alert"):
            score += 15  # browser was literally redirected to alert domain
        elif selenium.get("alert_in_resources"):
            score += 10  # alert domain loaded as background resource

    score = min(score, 100)
    verdict = "high" if score >= 65 else ("medium" if score >= 35 else "low")
    return score, verdict


# ── Main per-alert pipeline ────────────────────────────────────────────────────

def analyze_alert(doc: dict, es: Elasticsearch, index: str, db) -> dict:
    # Extract domain
    domain: str | None = None
    for q in doc.get("dns", {}).get("queries", []):
        domain = q.get("rrname", "").rstrip(".") or None
        if domain:
            break
    if not domain:
        domain = doc.get("tls", {}).get("sni", "").rstrip(".") or None
    if not domain:
        return {"processed": True, "skipped": True, "skip_reason": "no_domain"}

    ts_raw = doc.get("@timestamp", "")
    try:
        alert_time = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except ValueError:
        return {"processed": True, "skipped": True, "skip_reason": "invalid_timestamp"}

    src_ip = doc.get("src_ip", "")
    log.info("Redirect analysis: domain=%s src_ip=%s", domain, src_ip)

    # ── 1. Check mapping DB first (fast path — no ES query needed) ───────────
    all_known = db.lookup_parents(domain)
    if all_known:
        best = all_known[0]  # ordered by count desc
        log.info("  Known mapping (fast path): %s -> %s (count=%d)",
                 best["parent_domain"], domain, best["count"])
        score, verdict = _score("known_mapping", [], True, "known_mapping", None)
        return {
            "processed": True,
            "domain": domain,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "relationship": "known_mapping",
            "original_site": best["parent_domain"],
            "known_mapping": {
                "first_seen": best["first_seen"],
                "last_seen": best["last_seen"],
                "occurrence_count": best["count"],
            },
            "pre_alert_domains": [],
            "score": score,
            "verdict": verdict,
            "to_analyze": False,
        }

    # ── 2. No known mapping: get pre-alert domains + full analysis ────────────
    pre_domains: list[str] = []
    if src_ip:
        pre_domains = get_pre_alert_domains(es, index, src_ip, alert_time, domain)
        log.info("  Pre-alert domains (oldest→newest): %s", pre_domains)

    # ── 3. HTTP probe alert domain (log fields only) ──────────────────────────
    alert_probe = probe_domain(domain)
    alert_class = classify_probe(alert_probe)
    log.info("  Probe %s: class=%s status=%s size=%d",
             domain, alert_class, alert_probe["status_code"], alert_probe["page_size_bytes"])

    # ── 4. Walk pre-alert domains oldest→newest: curl probe → selenium+tcpdump ─
    # Visit each visitable domain; stop at the first one where the alert domain
    # appears in the combined CDP + tcpdump capture (_all_domains).
    original_site: str | None = None
    relationship: str | None = None
    selenium_fields: dict | None = None

    for parent in pre_domains:
        parent_probe = probe_domain(parent)
        parent_class = classify_probe(parent_probe)
        if parent_class in ("unreachable", "asset"):
            log.info("  Skip %s (%s)", parent, parent_class)
            continue

        log.info("  Selenium visit: %s (class=%s)", parent, parent_class)
        raw = selenium_visit(parent, domain)
        selenium_fields = {k: v for k, v in raw.items() if not k.startswith("_")}
        log.info("  Result: redirected_to_alert=%s alert_in_resources=%s domains=%d capture=%s",
                 raw["redirected_to_alert"], raw["alert_in_resources"],
                 raw["unique_domains"], raw["capture_method"])

        if domain in raw["_all_domains"]:
            original_site = parent
            relationship = "redirect_target" if raw["redirected_to_alert"] else "embedded_resource"
            log.info("  Found: %s -> %s (%s)", parent, domain, relationship)
            db.record(parent, domain)
            break

    # ── 5. Score ───────────────────────────────────────────────────────────────
    score, verdict = _score(alert_class, pre_domains, False, relationship or "direct_contact", selenium_fields)

    return {
        "processed": True,
        "domain": domain,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        # confirmed fields — only populated when analysis found a real relationship
        "relationship": relationship,
        "original_site": original_site,
        # log fields — always present
        "http_check": _probe_summary(alert_probe, alert_class),
        "pre_alert_domains": pre_domains,
        "selenium": selenium_fields,
        "score": score,
        "verdict": verdict,
        "to_analyze": original_site is None or score >= 50,
    }


def _probe_summary(probe: dict, probe_class: str) -> dict:
    return {
        "classification": probe_class,
        "reachable": probe["reachable"],
        "status_code": probe["status_code"],
        "page_size_bytes": probe["page_size_bytes"],
        "content_type": probe["content_type"],
        "is_redirect": probe["is_redirect"],
        "redirect_chain": probe["redirect_chain"],
        "final_url": probe["final_url"],
        "has_meta_refresh": probe["has_meta_refresh"],
        "has_js_redirect": probe["has_js_redirect"],
    }


# ── Main loop ──────────────────────────────────────────────────────────────────

def process_redirect_alerts(es: Elasticsearch) -> None:
    from mapping_db import MappingDB

    db = MappingDB()

    query = {
        "bool": {
            "must": [{"term": {"event_type": "alert"}}],
            "should": [
                {"exists": {"field": "dns.queries"}},
                {"exists": {"field": "tls.sni"}},
            ],
            "minimum_should_match": 1,
            "must_not": [{"exists": {"field": "enrichment.redirect.processed"}}],
        }
    }

    pit = es.open_point_in_time(index=ES_INDEX, keep_alive="5m")
    pit_id = pit["id"]
    processed = skipped = 0

    try:
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
                enrichment = analyze_alert(hit["_source"], es, hit["_index"], db)
                es.update(
                    index=hit["_index"], id=hit["_id"],
                    body={"doc": {"enrichment": {"redirect": enrichment}}},
                )
                if enrichment.get("skipped"):
                    skipped += 1
                else:
                    processed += 1
                    log.info(
                        "[%d] %s | rel=%s original_site=%s score=%d verdict=%s to_analyze=%s",
                        processed, hit["_id"],
                        enrichment.get("relationship"),
                        enrichment.get("original_site"),
                        enrichment.get("score", 0),
                        enrichment.get("verdict"),
                        enrichment.get("to_analyze"),
                    )

            search_after = hits[-1]["sort"]

    finally:
        es.close_point_in_time(body={"id": pit_id})

    log.info("Redirect enrichment done. Enriched: %d  Skipped: %d", processed, skipped)
