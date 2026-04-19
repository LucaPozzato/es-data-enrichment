# es-data-enrichment

SOC data enrichment pipeline for Suricata alerts stored in Elasticsearch.

**Stack:** Suricata → Filebeat → Elasticsearch / Kibana — Python 3.10+

Elasticsearch and Kibana run on the host. Only the enrichment runs in Docker.

---

## Setup

```bash
cp .env.example .env   # set API keys if needed
./docker.sh start      # build image and start container (run once after cloning)
```

**`.env` variables:**

| Variable | Default | Notes |
|---|---|---|
| `ES_HOST` | `http://localhost:9200` | Used by local commands (reset-es). Docker overrides this to `host.docker.internal` automatically. |
| `ES_USER` | _(empty)_ | Leave empty if auth is disabled |
| `ES_PASS` | _(empty)_ | Leave empty if auth is disabled |
| `ES_INDEX` | `suricata-*` | Index pattern |
| `VT_API_KEY` | _(empty)_ | VirusTotal key (free: 500/day, 4/min) |
| `ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB key (free: 1000/day) |

---

## Running enrichments

```bash
./enrich.sh run           # run all enrichments
./enrich.sh redirect      # run redirect analysis only
./enrich.sh threat-intel  # run threat-intel only
```

Both enrichments are **idempotent** — already-processed documents are skipped on re-runs.

---

## Container management

```bash
./docker.sh start   # build image and start container (first time setup)
./docker.sh stop    # stop and remove the container
./docker.sh reset   # rebuild image from scratch (no cache) and restart
```

---

## Data management

```bash
./enrich.sh reset      # interactive: choose what to reset
./enrich.sh reset-db   # delete domain_mappings.db
./enrich.sh reset-es   # clear all enrichment fields from ES
```

---

## Enrichments

### 1. `threat-intel`
Runs on every `event_type: alert` document.

Extracts the best IOC in priority order: DNS query domain → TLS SNI → public dest IP → public src IP. Looks it up on VirusTotal (domains + IPs) and AbuseIPDB (IPs only). Writes results under `enrichment.threat_intel`.

> **Mock mode active** — API calls are commented out, random data is returned with `"mock": true`. To activate real lookups: add keys to `.env`, uncomment the implementation blocks in `enrichments/threat_intel.py`, and uncomment `time.sleep(VT_RATE_LIMIT_DELAY)`.

---

### 2. `redirect`
Runs only on DNS/TLS alerts (alerts with `dns.queries` or `tls.sni`).

Answers: *why did the host contact this domain — what was the user doing?*

**Pipeline per alert:**

1. **Mapping DB fast path** — check if the alert domain has a known parent in `domain_mappings.db`. If yes: return immediately with `original_site` and `relationship: known_mapping`. No ES query, no HTTP probe, no selenium.

2. **Pre-alert DNS lookback** — query ES for DNS/TLS events from the same `src_ip` in the 1 second before the alert, ordered oldest → newest.

3. **HTTP probe — alert domain** — `GET` with Edge-spoofed headers (1 s timeout). Classifies the domain as:
   - `real_page` — large HTML, no redirect
   - `redirect` — HTTP 3xx chain
   - `soft_redirect` — JS or meta-refresh redirect
   - `asset` — non-HTML (JSON, image, binary)
   - `unreachable` — no response

4. **Walk pre-alert domains oldest → newest** — for each domain:
   - HTTP probe it — skip if `unreachable` or `asset`
   - Visit with headless Chrome (spoofed as Edge) + tcpdump
   - CDP captures navigations vs sub-resource loads; tcpdump captures DNS on port 53; all combined into `_all_domains`
   - If alert domain appears in `_all_domains` → `original_site` = this domain, record mapping, stop
   - Otherwise continue to next pre-alert domain

5. **Scoring** — 0–100 score, `low / medium / high` verdict. `to_analyze = True` if no relationship was confirmed or score ≥ 50.

6. **Mapping DB write** — on confirmed relationship: records `original_site → alert_domain` pair only.

**Confirmed fields** — only set when analysis found a real relationship:

| Field | Description |
|---|---|
| `relationship` | `known_mapping / redirect_target / embedded_resource` |
| `original_site` | Domain the user was browsing when this alert fired |
| `known_mapping.first_seen` | When this parent→child pair was first recorded |
| `known_mapping.last_seen` | Most recent observation |
| `known_mapping.occurrence_count` | How many times it has been seen |

**Log fields** — always present:

| Field | Description |
|---|---|
| `domain` | The alert domain that was analysed |
| `pre_alert_domains` | Domains contacted in the 1 s before the alert (oldest first) |
| `http_check.classification` | `real_page / redirect / soft_redirect / asset / unreachable` |
| `http_check.status_code` | HTTP status of the alert domain |
| `http_check.page_size_bytes` | Response body size |
| `http_check.is_redirect` | True if a 3xx chain was followed |
| `http_check.redirect_chain` | List of intermediate URLs |
| `http_check.final_url` | URL after following all redirects |
| `http_check.has_meta_refresh` | Meta-refresh tag detected in HTML |
| `http_check.has_js_redirect` | JS `window.location` redirect detected |
| `selenium.visited_domain` | Last domain the browser visited |
| `selenium.redirected_to_alert` | Browser was hard-redirected to the alert domain |
| `selenium.alert_in_resources` | Alert domain loaded as a sub-resource |
| `selenium.unique_domains` | Total unique domains seen during the visit |
| `selenium.capture_method` | `cdp` or `cdp+tcpdump` |
| `score` | 0–100 suspicion score |
| `verdict` | `low / medium / high` |
| `to_analyze` | True when no relationship confirmed or score ≥ 50 |
| `enriched_at` | ISO 8601 UTC timestamp |

---

## Repo structure

```
run.py                      main entry point
enrichments/
  threat_intel.py           VirusTotal + AbuseIPDB enrichment
  redirect.py               redirect / reachability analysis
mapping_db.py               SQLite store for domain relationships
domain_mappings.db          auto-created on first run
Dockerfile                  enrichment container image
docker-compose.yml          container configuration
docker.sh                   container management (start / stop / reset)
enrich.sh                   run enrichments and reset data
EXPLANATION.md              detailed code walkthrough
```

---

## Enabling real API keys (when ready)

1. Add `VT_API_KEY` and `ABUSEIPDB_API_KEY` to `.env`
2. In `enrichments/threat_intel.py`: uncomment the real implementation blocks inside `vt_lookup()` and `abuseipdb_lookup()`, and uncomment `time.sleep(VT_RATE_LIMIT_DELAY)` in `enrich_ioc()`
3. Search for `# TODO` — they mark every block that needs to be swapped
