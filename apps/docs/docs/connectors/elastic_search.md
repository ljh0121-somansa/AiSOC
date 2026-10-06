---
sidebar_position: 42
title: Elastic Search
description: Pull raw ECS firewall logs from an Elasticsearch cluster via ES|QL and let AiSOC's own detection rules gate them into alerts.
---

# Elastic Search

The Elastic Search connector pulls **raw ECS-format logs** from an
Elasticsearch cluster over its REST / ES|QL surface, and lets the
**AiSOC detection ruleset** decide which events become alerts. It is
designed for the common on-prem / hybrid case where a customer already
runs an Elasticsearch cluster (often behind their own native dashboards
and pipelines) and wants AiSOC to consume the raw `firewall-logs`
index without re-architecting their stack.

Unlike a native SIEM connector that ingests vendor-published findings,
this connector ingests **plain network logs** (typically
`event.dataset: firewall.<vendor>`), one event per ES document. The
connector flattens the ECS fields onto top-level alert fields
(`event_action`, `dst_port`, `src_geo`, `rule_name`, …) so AiSOC's
own rules can match on them.

## What you get

| Source | API | Notes |
|---|---|---|
| Elasticsearch index (ES|QL) | `POST /_query` with `FROM <index> | WHERE … | LIMIT …` | One server-side-filtered query per poll |

Events are normalized to OCSF **Network Activity** (class `4001`,
category `network`) and tagged `source: elastic_search`. The parsed
ECS fields are surfaced as top-level alert fields so detections can
match without unwrapping `raw_event`. The original ECS document is
preserved on `raw_event` for enrichment and debugging.

## Mixed model: native severity + AiSOC rules

This connector uses a **mixed model** — it does not force every event
to `low`, and it does not rely on a single rule to decide everything.

- **genuine high / critical** firewall events keep their **native
  severity** through the connector. Because a Network-Activity event
  with severity ≥ `high` trips the fusion promoter's `severity_id >= 4`
  gate, those events become alerts **immediately**, exactly as the
  vendor advertised them.

- **low / medium** events are **not** auto-promoted. They fall through
  to the AiSOC **detection ruleset**, which evaluates each one. Only the
  low/medium events that **match a rule** are promoted to alerts — for
  example an `allow` SSH from a foreign IP, a denied RDP probe, or a
  blocked DNS query to an uncommon resolver.

So the ruleset owns the gate for the interesting low/medium noise, while
genuine high-signal firewall events pass straight through.

## Configuration

| Field | Type | Default | Required | Notes |
|---|---|---|---|---|
| `base_url` | string | — | Yes | Cluster endpoint, e.g. `http://10.216.0.155:9200` (include scheme and port) |
| `api_key` | secret | — | No | `ApiKey` credential (preferred). Omit if using username/password. |
| `username` | string | — | No | Basic-auth fallback. Requires `password`. |
| `password` | secret | — | No | Basic-auth fallback. Requires `username`. |
| `index` | string | `firewall-logs` | No | Index pattern the poll is **scoped to** (ES|QL `FROM <index>`). Set to `.alerts-security.alerts-*` to consume Elastic Security alerts instead. |
| `ssl_verify` | boolean | `true` | No | Set `false` only for self-signed certs in private deployments. |

Provide **either** `api_key` **or** `username`+`password` — the
connector raises if neither is configured.

`api_key` and `password` are stored vault-encrypted at rest.

## How polling works

1. **Poll**: each cycle (default **30 s**) the connector runs an
   ES|QL query scoped to the configured index and time window:

   ```
   FROM <index> | WHERE @timestamp > NOW() - 30 seconds | LIMIT 30
   ```

   Only events within the last **30 seconds** are fetched, so this is
   near-real-time and the ruleset sees fresh events without re-polling
   history.

2. **Normalize**: each returned document is flattened to the top-level
   fields listed below (ECS paths → AiSOC fields).

3. **Ingest → Fusion**: the canonical Network-Activity envelope is sent
   to the ingestion pipeline, normalized, and routed to the fusion
   engine.

4. **Detection rule**: native AI-SOC rules evaluate the event against
   the fusion live-detection ruleset. Genuine high/critical events
   promote via the severity gate; low/medium events promote only if a
   rule matches (see [Detection behaviour](#detection-behaviour)).

5. **Alert**: matching events become alerts on `/alerts` and appear in
   the Investigation Rail with a correlation narrative.

> **Note:** the poll uses ES|QL `FROM`/`WHERE`/`LIMIT` syntax, so the
> configured index must support ES|QL (Elasticsearch 7.13+). The
> `index` name is inserted verbatim into the `FROM` clause — use a
> concrete index name or a simple glob pattern.

## Field mapping

The connector maps ECS fields onto these flat top-level alert fields
(detections match on them):

| AiSOC flat field | ECS source |
|---|---|
| `severity` | `log.level` / `level` / `severity` (native — not forced to `low`) |
| `src_ip` | `source.ip` / `client.ip` |
| `dst_ip` | `destination.ip` / `server.ip` |
| `dst_port` | `destination.port` |
| `src_geo` | `source.country_iso_code` |
| `rule_name` | `rule.name` |
| `rule_id` | `rule.id` |
| `event_action` | `event.action` (`allow` / `deny` / `drop` / `block` / …) |
| `event_dataset` | `event.dataset` (e.g. `firewall.fortinet`) |
| `network_transport` | `network.transport` |
| `network_protocol` | `network.protocol` |
| `hostname` | `host.name` / `host.hostname` |
| `src_ip_geo` (country) | `source.country_iso_code` |
| `risk_score` | `event.risk_score` |
| `mitre_techniques` | `threat.technique.id` |
| `created_at` | `@timestamp` / `event.ingested` |
| `raw_event` | the full original ECS document |

## Detection behaviour

The bundled firewall detection rules live in
`detections/network/` and are exported into the live ruleset on
startup. They focus on the **low/medium** events that the mixed model
delivers to the ruleset — suspicious `allow`/`deny`/`drop`/`block`
patterns, uncommon ports, foreign source IPs / geos, and
management-port probing. They do **not** re-adjudicate genuine
high/critical events (those promote via the severity gate before the
ruleset sees them).

Examples of what the ruleset catches:

- **`firewall-allow-foreign-ssh`** — an `allow` on `dst_port=22` from a
  source outside RFC1918 space (likely external admin / intrusion).
- **`firewall-deny-internal-admin-creds`** — a `deny` on `dst_port=3389`
  from a non-admin subnet (misconfig or lateral-movement probe).
- **`firewall-allow-external-to-internal-db`** — an `allow` on
  `dst_port ∈ {3306, 5432}` from an external source (database exposed to
  the internet).
- **`firewall-drop-foreign-mgmt`** — a `drop` on a management port
  (SSH/RDP/VNC/WinRM) from a source outside the approved geography.

A native **high/critical** firewall event, by contrast, becomes an
alert on its own the moment it is ingested — the ruleset does not need
a matching rule for it.

## Prerequisites

- An **Elasticsearch 7.13+** cluster whose `firewall-logs` index is
  reachable from the `connectors` service.
- A credential with **read / search** rights on the target index:
  - an **API key** scoped to the index (preferred), **or**
  - a **username + password** (basic auth).
- The cluster endpoint in `base_url` reachable from the connectors
  service host.

## Setup walkthrough

1. **Connectors → Add connector → Elastic Search**.
2. Enter the **Elasticsearch URL** (e.g. `http://10.216.0.155:9200`).
3. Enter an **API Key** (preferred) **or** a **Username + Password**.
4. Set the **Index** to `firewall-logs` (default) — or `.alerts-security.alerts-*`
   to consume Elastic Security alerts instead.
5. Leave **Verify SSL certificate** on, unless the cluster uses a
   self-signed certificate.
6. **Test connection** — AiSOC hits the cluster root endpoint to verify
   auth and reachability.
7. **Save**.

The scheduler polls every 300 seconds by default; each poll surfaces
recent events into `/alerts`.

## Troubleshooting

**`Test connection` fails / "Connection failed"** — the `base_url`
scheme (http vs https), host, and port are correct, the credential is
accepted, and the connectors service can reach the cluster. Confirm
`ssl_verify` matches the certificate situation.

**No alerts arrive** — two likely causes:

- The configured **`index` is empty or has no recent events**. The poll
  only fetches events from the last 5 minutes; if nothing has been
  written to that index since the connector was enabled, nothing fires.
  Check the index in Kibana / `_cat/count` first.
- The matching events are **low/medium and don't match a rule**. Only
  matched low/medium events become alerts — genuine high/critical events
  always do. If you expect an event to fire, confirm its `event_action`
  and `dst_port` line up with a bundled rule.

**ES|QL errors** — the poll uses ES|QL `FROM`/`WHERE`/`LIMIT` syntax.
The cluster must support ES|QL (Elasticsearch 7.13+), and the `index`
value is inserted verbatim into the `FROM` clause. Use a concrete index
name or a simple glob; arbitrary ES query syntax is **not** accepted
here (use the federated search surface for ad-hoc queries).

**`ssl_verify` warnings for internal clusters** — set **Verify SSL
certificate** to `false` only for self-signed certificates in private
deployments; prefer adding the CA to the trust store in production.

## Related

- [AWS VPC Flow Logs](/docs/connectors/aws-vpc-flow) — cloud-native
  equivalent flow-log ingestion for AWS customers.
- [Zeek / Suricata](/docs/connectors/zeek_suricata) — IDS/NEA flow
  records as an alternative network-signal source.
- [Detection rules overview](/docs/concepts/detection-rules) — how the
  AiSOC ruleset gates events into alerts.
