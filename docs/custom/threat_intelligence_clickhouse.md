# Commercially Unrestricted Threat Intelligence ClickHouse Mirroring

This document describes the design, architecture, and operation of the local threat intelligence mirroring pipeline in the AiSOC platform. The pipeline synchronizes active open-source Indicators of Compromise (IOCs) into the ClickHouse warm-tier database, enabling high-performance, legally compliant threat enrichment without external non-commercial API limitations.

---

## 1. Architectural Motivation & Compliance

Commercial B2B SaaS and enterprise security appliances cannot rely on free public APIs (such as the free/public tiers of VirusTotal, GreyNoise, or AbuseIPDB) for real-time customer log enrichment. Doing so violates the Terms of Service (ToS) of those providers, introduces legal liabilities, and poses a risk of sudden API suspension. Furthermore, querying external APIs directly from customer-premise environments violates air-gap network constraints and leaks sensitive indicators.

To address these challenges, the AiSOC Threat Intelligence service (`services/threatintel`) utilizes **Local Mirroring**:
*   **Commercially Safe Feeds**: Only pulls feeds licensed under Creative Commons CC0 (Public Domain Dedication) or U.S. Government Work (public domain).
*   **Zero Outbound Leakage**: All raw events are matched locally against the ClickHouse mirroring database (`aisoc.ioc_enrichments`). No customer Indicators are ever sent to public servers.
*   **High Performance**: Replaces network-bound HTTP API roundtrips with sub-millisecond local ClickHouse indexing.

---

## 2. Ingestion & Storage Pipeline Architecture

The ingestion pipeline is designed as a secure, asynchronous multi-sink pipeline coordinating the following stages:

```
[External CC0 Feeds]
 (Abuse.ch, CISA KEV)
         │
         ▼
 [FeedScheduler] (app.feeds.scheduler)
  - Polling interval: 24h
         │
         ▼
[ThreatIntelPipeline] (app.feeds.pipeline)
  - 1. Deduplication (Redis Bloom Filter)
  - 2. Vector Indexing (Qdrant)
  - 3. Relationship Graphing (Neo4j)
  - 4. Event Database Ingestion (ClickHouse)
         │
         ▼
[ClickHouse Event Lake]
 (aisoc.ioc_enrichments)
```

### Key Components

1.  **Feed Poller & Scheduler (`scheduler.py` & `handlers.py`)**:
    An APScheduler-based runner triggers polling handlers on configurable intervals (default: every 24 hours).
2.  **Clients (`app.clients.abuse_ch`)**:
    *   `ThreatFoxClient`: Pulls active malware Command & Control (C2) IP addresses, domains, and ports over JSON.
    *   `UrlhausClient`: Pulls recently active malware payload distribution URLs.
3.  **Parsers (`app.parsers.abuse_ch`)**:
    Normalizes differing raw JSON structures into a unified, platform-standard IOC envelope containing `type` (ip, domain, url, hash), `value`, `source`, `severity`, and `description`.
4.  **Deduplication (`RedisBloomFilter`)**:
    Uses a Redis-backed Bloom filter to check if an indicator has been seen before. Only new, unique IOCs are passed to downstream databases, eliminating DB write amplification and bloat.
5.  **Direct ClickHouse Mirroring**:
    New indicators are grouped in batches and written directly to the ClickHouse warm-tier server over HTTP (port 8123) into the `aisoc.ioc_enrichments` table.

---

## 3. Database Schema

The mirrored indicators are stored in the ClickHouse warm-tier database `aisoc` under the following schema:

```sql
CREATE TABLE IF NOT EXISTS aisoc.ioc_enrichments (
    ioc_value String,
    ioc_type String,
    source String,
    severity String,
    description String,
    updated_at DateTime64(3) DEFAULT now()
) ENGINE = MergeTree()
PRIMARY KEY (ioc_type, ioc_value)
```

### Table Parameters
*   **Engine**: `MergeTree()` supports high-concurrency, high-throughput bulk inserts and parallelized SELECT scans.
*   **Primary Key**: `(ioc_type, ioc_value)` optimizes index memory usage, ensuring sub-millisecond queries when matching raw telemetry events by their IP, domain, URL, or file hash.

---

## 4. Operation and Verification Guide

### Step 1: Start the Services
Apply the newly configured ClickHouse environment variables to the container network and launch the stack:
```bash
./manage.sh restart
```

### Step 2: Verify Scheduler Registration
Stream the threat intelligence container logs to verify the poller is scheduled and initialized:
```bash
docker logs -f aisoc-dev1-threatintel
```
Verify that the following lines are printed indicating successful scheduler initialization:
```text
2026-07-22 00:00:00 [info] Registered feed feed=threatfox interval_seconds=86400
2026-07-22 00:00:00 [info] Registered feed feed=urlhaus interval_seconds=86400
2026-07-22 00:00:00 [info] Feed scheduler started
```

### Step 3: Query Mirrored Records in ClickHouse
Once a poll completes, query the ClickHouse table to verify that the CC0 indicator feeds have been successfully mirrored:
```bash
curl -u "aisoc:clickhouse_dev_secret" -s -X POST "http://localhost:18123/" -d "SELECT count(), source FROM aisoc.ioc_enrichments GROUP BY source"
```
Output:
```text
4328	threatfox
12540	urlhaus
1120	cisa-kev
```
This confirms that the local threat intelligence database is populated and active, providing legally uncompromised, zero-outbound-leakage log enrichment for the entire platform.
