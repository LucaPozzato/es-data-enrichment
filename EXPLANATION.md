# Code Explanation

Detailed walkthrough of every file and function in the pipeline.

---

## Project structure

```
run.py                      entry point — connects to ES, dispatches enrichments
enrichments/
  __init__.py               empty — makes enrichments/ a Python package
  threat_intel.py           VirusTotal + AbuseIPDB IOC enrichment
  redirect.py               redirect / reachability / browsing-context analysis
mapping_db.py               SQLite wrapper for domain relationship store
domain_mappings.db          runtime SQLite database (auto-created, volume-mounted)
Dockerfile                  enrichment container image
docker-compose.yml          container config — DNS set to 8.8.8.8/1.1.1.1, NET_ADMIN for tcpdump
docker.sh                   build / stop / reset the Docker container
enrich.sh                   run enrichments, reset mapping DB or ES data
```

---

## Docker setup

### Dockerfile

Installs on top of `python:3.12-slim`:
- `chromium` + `chromium-driver` — headless Chrome for selenium
- `tcpdump` + `libpcap-dev` — packet capture and scapy parsing

Copies only the Python source (`run.py`, `enrichments/`, `mapping_db.py`, `requirements.txt`). Scripts, docs, `.env`, and the DB file are excluded via `.dockerignore`.

### docker-compose.yml

Key settings on the `enrichment` service:
- `command: sleep infinity` — keeps the container alive so `docker compose exec` can run enrichments on demand
- `dns: [8.8.8.8, 1.1.1.1]` — bypasses Docker's internal forwarding resolver (which caches) and hits external resolvers directly, giving fresh DNS on every run
- `cap_add: NET_ADMIN` — required for tcpdump to capture inside the container
- `extra_hosts: host.docker.internal:host-gateway` — lets the container reach ES/Kibana running on the host
- `volumes: ./domain_mappings.db:/app/domain_mappings.db` — persists the mapping DB across container runs
- `environment: ES_HOST: http://host.docker.internal:9200` — overrides the `.env` value inside the container; `.env` uses `localhost` for local commands like `reset-es`, but the container needs `host.docker.internal` to reach the host
- `read_only: true` — container filesystem is read-only; malware visited during selenium analysis cannot write or persist anywhere in the container
- `tmpfs: /tmp` — RAM-backed `/tmp` so Chrome and tcpdump have a writable scratch space; wiped on container stop
- `security_opt: no-new-privileges:true` — prevents any process inside the container from gaining elevated privileges

### docker.sh

```
./docker.sh start   # build image + touch domain_mappings.db + start container (run once after clone)
./docker.sh stop    # stop and remove the container
./docker.sh reset   # rebuild from scratch with --no-cache and restart
```

`domain_mappings.db` must exist as a file before the container starts — Docker would create a directory if it's missing, breaking the volume mount. `start` always `touch`es it first.

### enrich.sh

```
./enrich.sh run           # all enrichments
./enrich.sh redirect      # redirect only
./enrich.sh threat-intel  # threat-intel only
./enrich.sh reset-db      # delete domain_mappings.db
./enrich.sh reset-es      # clear enrichment fields from ES
./enrich.sh reset         # interactive: choose what to reset
```

Each run command `touch`es `domain_mappings.db` before `docker compose exec` to guard against accidental deletion. `reset-es` runs `curl` locally against `ES_HOST` from `.env` (which is `localhost`).

---

## run.py

### `get_es_client()`

- `basic_auth` only added when both `ES_USER` and `ES_PASS` are non-empty — unauthenticated lab clusters work with no config change.
- Uses `client.info()` (`GET /`) rather than `ping()` (`HEAD /`). ES 8.x returns 400 for HEAD requests, which causes `ping()` to report the cluster as down even when it's healthy.
- Logs the cluster version so client/server mismatches are immediately visible.

### `main()`

Parses `--enrichment threat-intel | redirect | all` (default: `all`). Imports enrichment modules lazily so a missing optional dependency (e.g. selenium not installed) doesn't break the other enrichment.

---

## enrichments/threat_intel.py

### Constants

```python
VT_RATE_LIMIT_DELAY = 15   # seconds between VT calls (free tier: 4/min)
BATCH_SIZE = 100
```

### `vt_lookup(ioc, ioc_type)`

**Mock mode (active):** returns random but realistic data with `"mock": true`. The four engine-vote counts sum to 72 (approximate number of AV engines on VT). `max(..., 0)` prevents negative values.

**Real mode (TODO):** endpoint is `/ip_addresses/{ioc}` or `/domains/{ioc}`, API key in `x-apikey` header, maps `last_analysis_stats` + `reputation`.

### `abuseipdb_lookup(ip)`

IP-only — never called for domain IOCs. Mock `is_tor` is False 3/4 of the time to approximate a realistic hit rate.

### `is_private_ip(ip)`

`ipaddress.ip_address().is_private` covers RFC 1918, loopback, and IPv6 private ranges. `except ValueError` handles non-IP strings. Private IPs are skipped because public threat intel APIs return nothing useful for them.

### `extract_ioc(doc)`

Priority order — returns first hit:
1. `dns.queries[0].rrname` — DNS queried name (best signal)
2. `tls.sni` — TLS server name from ClientHello
3. `dest_ip` if not private — external destination
4. `src_ip` if not private — fallback for inbound attacks

All fields are flat raw Suricata `eve.json` — no ECS normalisation.

### `enrich_ioc(ioc, ioc_type)`

`_ioc_cache` is a module-level dict. Many alerts share the same domain or IP; caching means API quota is spent per unique IOC, not per alert.

### `process_alerts(es)`

Tries two queries: raw Suricata field layout (`event_type: "alert"`) then ECS layout (`event.type: "alert"`). First that returns results wins.

**PIT + search_after pagination:**
- `open_point_in_time` freezes a consistent snapshot so mid-loop `es.update` writes don't corrupt pagination.
- Sort tiebreaker is `_shard_doc` — the correct PIT-only unique field. Sorting by `_id` raises 400 in ES 8.x (fielddata disabled).
- `pit_id` is refreshed from every response — ES can rotate it between pages.
- `finally: close_point_in_time` — always releases the snapshot even on exception.

Idempotency: `must_not exists enrichment.threat_intel.processed` filters out already-enriched docs.

---

## enrichments/redirect.py

### Constants

```python
HTTP_TIMEOUT = 1            # probe must be fast
MAX_READ_BYTES = 51200      # 50 KB — enough to detect redirect patterns
VISITABLE_MIN_BYTES = 5000  # minimum size to classify as real_page
SELENIUM_WAIT_SEC = 2       # wait for JS to settle after page load
```

### `_EDGE_UA` and `BROWSER_HEADERS`

User-agent and headers are spoofed as **Microsoft Edge 122 on Windows**. This includes:
- UA string ending in `Edg/122.0.0.0`
- `Sec-CH-UA` client hints advertising Edge — servers that check hints (not just the UA string) also see Edge
- Full `Sec-Fetch-*` header set

Spoofing Edge rather than Chrome bypasses server-side blocks that target Chrome's UA, and avoids Chrome-specific Safe Browsing redirect pages that would interrupt the redirect chain capture.

### `probe_domain(domain)`

`_probe_cache` is module-level — one probe result per domain per run.

Tries HTTPS first, falls back to HTTP. Reads at most `MAX_READ_BYTES` with `stream=True` — enough to detect redirect patterns without downloading full pages. `verify=False` skips TLS cert validation; urllib3 warnings are suppressed globally at the top of the file.

### `classify_probe(probe)`

| Class | Meaning |
|---|---|
| `real_page` | Large HTML, no redirect — a page worth visiting |
| `redirect` | HTTP 3xx chain |
| `soft_redirect` | Small HTML with JS `window.location` or `<meta http-equiv=refresh>` |
| `asset` | Non-HTML (JSON, image, API endpoint) |
| `unreachable` | No response within timeout |

### `get_pre_alert_domains(es, index, src_ip, alert_time, exclude_domain)`

Queries `event_type: dns|tls` from the same `src_ip` in `[alert_time − 1s, alert_time)`, sorted `@timestamp: asc`. Returns deduplicated domains in **oldest-first** order — index 0 is the domain the user most likely navigated to first.

### `_tcpdump_iface()`

Returns `en0` on macOS, `any` on Linux. `any` is Linux-specific; on macOS it doesn't exist or has permission issues.

### `_parse_pcap_dns(pcap_path)`

Scapy parses the pcap for DNS query packets (`DNSQR`, `qr == 0`). Returns a set of queried domain names. Wrapped in `try/except` — returns empty set if scapy is unavailable or the pcap is malformed.

### `selenium_visit(domain, alert_domain)`

Headless Chrome with the following key flags:
- `--disable-dns-cache` + `--dns-prefetch-disable` — no DNS caching within or between visits
- `--user-agent` set to Edge UA — consistent with `BROWSER_HEADERS`
- `--allow-running-insecure-content` — follows HTTPS→HTTP mixed-content redirects that Chrome would otherwise block
- `--disable-features=SafeBrowsing` + `--disable-client-side-phishing-detection` — prevents Safe Browsing warning pages from interrupting redirect chains
- `download_restrictions: 3` in Chrome prefs — blocks all file downloads including drive-by JS-triggered ones; nothing can be saved to disk via the browser
- `safebrowsing.enabled: False` in prefs — consistent with the flag above

On Debian (Docker), Chrome is installed as `/usr/bin/chromium`. The code detects this and passes the explicit `Service("/usr/bin/chromedriver")` path; on macOS it lets Selenium find Chrome automatically.

**tcpdump** runs in a background subprocess capturing port 53 to a temp pcap in `/tmp`. `sleep(0.2)` gives it time to start. Skipped if tcpdump is unavailable or permission is denied.

**CDP event parsing** — `Network.requestWillBeSent`:
- `type == "Document"` → browser navigated/redirected → `nav_domains`
- everything else → sub-resource load → `resource_domains`

`_all_domains = nav_domains | resource_domains | pcap_domains` — union of all capture sources.

Returns 5 ES fields + one internal key:

| Field | Meaning |
|---|---|
| `visited_domain` | Domain the browser visited |
| `redirected_to_alert` | Alert domain in `nav_domains` (hard redirect) |
| `alert_in_resources` | Alert domain in `resource_domains` only |
| `unique_domains` | Total unique domains across all sources |
| `capture_method` | `cdp` or `cdp+tcpdump` |
| `_all_domains` | Internal — used for mapping DB, stripped before ES write |

### `_score(alert_class, pre_domains, has_known_mapping, relationship, selenium)`

Additive model capped at 100:

| Condition | Points |
|---|---|
| Known mapping | +5 |
| No known mapping | +10 |
| `unreachable` | +15 |
| `soft_redirect` | +20 |
| `redirect` | +25 |
| `real_page` | +5 |
| `asset` | +10 |
| Pre-alert domains exist | +10 |
| `embedded_resource` | +20 |
| `redirect_target` | +25 |
| `redirect_source` | +15 |
| `direct_contact` | +15 |
| Selenium: `redirected_to_alert` | +15 |
| Selenium: `alert_in_resources` | +10 |

Verdict: `high` ≥ 65, `medium` ≥ 35, `low` otherwise.

`to_analyze` is `True` when `original_site is None` or `score >= 50`. A confirmed relationship does not automatically suppress `to_analyze` — an `embedded_resource` at score ≥ 50 is still flagged for human review even though context was found.

### `analyze_alert(doc, es, index, db)` — main per-alert pipeline

**Step 1 — Mapping DB fast path**

```python
all_known = db.lookup_parents(domain)
if all_known:
    best = all_known[0]  # highest count first
    return { relationship: "known_mapping", original_site: best["parent_domain"], ... }
```

If the domain has been seen before, return immediately — no ES query, no HTTP probe, no selenium.

**Step 2 — Pre-alert domain lookback**

Fetch DNS/TLS events from the same src_ip in the 1 s before the alert. Oldest-first.

**Step 3 — HTTP probe alert domain**

For log fields (`http_check`) only.

**Step 4 — Walk pre-alert domains oldest → newest**

For each pre-alert domain:
1. HTTP probe it — skip if `unreachable` or `asset` (not worth visiting)
2. Visit with selenium + tcpdump
3. Check if alert domain is in `_all_domains` (CDP navigations + CDP resources + tcpdump DNS)
4. **Found** → `original_site = parent`, `relationship = redirect_target` (if browser navigated) or `embedded_resource` (if seen but not navigated). Record mapping. Stop.
5. **Not found** → continue to next pre-alert domain

If no pre-alert domain reveals the alert domain: `relationship` and `original_site` stay `None`, `to_analyze = True`.

**Mapping DB write (confirmed only)**

Only `original_site → alert_domain` is recorded. No intermediate domains, no guesses — prevents polluting the DB with unverified pairs.

### `process_redirect_alerts(es)` — main loop

Filters for `event_type: alert` documents that have either `dns.queries` or `tls.sni` (DNS/TLS alerts only) and have not yet been enriched (`must_not exists enrichment.redirect.processed`).

Uses the same **PIT + search_after** pagination as `process_alerts` in threat_intel:
- `open_point_in_time` freezes a consistent snapshot so mid-loop `es.update` writes don't corrupt pagination
- Sort tiebreaker is `_shard_doc` — the correct PIT-only unique field
- `pit_id` is refreshed from every response
- `finally: close_point_in_time` — always releases the snapshot even on exception

For each hit: calls `analyze_alert` → writes result to `enrichment.redirect` via `es.update`. Skipped docs (no domain, invalid timestamp) are counted separately and don't increment the enriched counter.

---

## mapping_db.py

### Schema

```sql
CREATE TABLE domain_mappings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_domain TEXT    NOT NULL,
    child_domain  TEXT    NOT NULL,
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    count         INTEGER DEFAULT 1,
    UNIQUE(parent_domain, child_domain)
)
```

`idx_child` on `child_domain` — used by `lookup_parents` (hot path).
`idx_parent` on `parent_domain` — used for reverse lookups.

### `_connect()`

Creates a SQLite connection and immediately sets `PRAGMA journal_mode=MEMORY`. By default SQLite writes a `.db-journal` file alongside the database during transactions. With `read_only: true` in the container, the `/app/` directory is read-only so SQLite cannot create that file. `MEMORY` mode keeps the journal in RAM instead — no journal file is ever written to disk. The database file itself is still written normally (it is exempt from `read_only` via the volume mount).

### `lookup_parents(child_domain)`

Returns all known parents ordered by `count DESC` — most frequently observed first. `all_known[0]` is the best guess for the fast path.

### `record(parent_domain, child_domain)`

Atomic upsert — inserts on first observation, increments `count` and updates `last_seen` on repeat. Self-loops silently dropped.

---

## Suricata field structure (this cluster)

Raw `eve.json` via Filebeat — no ECS normalisation:

| Data | Field |
|---|---|
| Event type | `event_type` (`"alert"`, `"dns"`, `"tls"`) |
| Source IP | `src_ip` |
| Destination IP | `dest_ip` |
| Timestamp | `@timestamp` |
| DNS queried name | `dns.queries[0].rrname` |
| DNS record type | `dns.queries[0].rrtype` |
| TLS SNI | `tls.sni` |
| Alert signature | `alert.signature` |
| Alert severity | `alert.severity` |

---

## Enriched document examples

### threat_intel

```json
{
  "enrichment": {
    "threat_intel": {
      "processed": true,
      "ioc": "app.storyblok.com",
      "ioc_type": "domain",
      "enriched_at": "2026-04-19T14:00:00+00:00",
      "virustotal": {
        "found": true,
        "mock": true,
        "malicious": 3,
        "suspicious": 1,
        "harmless": 65,
        "undetected": 3,
        "reputation": -12,
        "country": "NL",
        "as_owner": "AS13335 Cloudflare"
      }
    }
  }
}
```

### redirect — known mapping (fast path)

```json
{
  "enrichment": {
    "redirect": {
      "processed": true,
      "domain": "app.storyblok.com",
      "relationship": "known_mapping",
      "original_site": "treccani.it",
      "known_mapping": {
        "first_seen": "2026-04-19T13:40:00+00:00",
        "last_seen": "2026-04-19T14:00:00+00:00",
        "occurrence_count": 5
      },
      "pre_alert_domains": [],
      "score": 5,
      "verdict": "low",
      "to_analyze": false,
      "enriched_at": "2026-04-19T14:00:00+00:00"
    }
  }
}
```

### redirect — full analysis, relationship confirmed

```json
{
  "enrichment": {
    "redirect": {
      "processed": true,
      "domain": "app.storyblok.com",
      "relationship": "embedded_resource",
      "original_site": "treccani.it",
      "pre_alert_domains": ["treccani.it", "d1fm7fuuekry8j.cloudfront.net", "www.treccani.it"],
      "http_check": {
        "classification": "real_page",
        "reachable": true,
        "status_code": 200,
        "page_size_bytes": 5663,
        "content_type": "text/html; charset=utf-8",
        "is_redirect": false,
        "redirect_chain": [],
        "final_url": "https://app.storyblok.com/",
        "has_meta_refresh": false,
        "has_js_redirect": false
      },
      "selenium": {
        "visited_domain": "treccani.it",
        "redirected_to_alert": false,
        "alert_in_resources": true,
        "unique_domains": 8,
        "capture_method": "cdp+tcpdump"
      },
      "score": 55,
      "verdict": "medium",
      "to_analyze": true,
      "enriched_at": "2026-04-19T13:48:55+00:00"
    }
  }
}
```

### redirect — nothing found (log fields only)

```json
{
  "enrichment": {
    "redirect": {
      "processed": true,
      "domain": "get.geojs.io",
      "relationship": null,
      "original_site": null,
      "pre_alert_domains": ["www.reverso.net", "cdn.reverso.net"],
      "http_check": {
        "classification": "asset",
        "reachable": true,
        "status_code": 200,
        "page_size_bytes": 161,
        "content_type": "application/json",
        "is_redirect": false,
        "redirect_chain": [],
        "final_url": "https://get.geojs.io/v1/ip.json",
        "has_meta_refresh": false,
        "has_js_redirect": false
      },
      "selenium": {
        "visited_domain": "www.reverso.net",
        "redirected_to_alert": false,
        "alert_in_resources": false,
        "unique_domains": 7,
        "capture_method": "cdp+tcpdump"
      },
      "score": 45,
      "verdict": "medium",
      "to_analyze": true,
      "enriched_at": "2026-04-19T14:10:00+00:00"
    }
  }
}
```
