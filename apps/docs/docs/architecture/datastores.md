---
sidebar_position: 4
title: 데이터 저장소 아키텍처 (Datastores)
description: AiSOC을 구성하는 7대 데이터 저장소(PostgreSQL, ClickHouse, Neo4j, Qdrant, Redis, Kafka, OpenSearch)의 역할, 저장 방식 및 상세 사용처.
---

# 데이터 저장소 아키텍처 (Datastores)

AiSOC은 단일 데이터베이스에 모든 부하를 집중시키는 대신, 워크로드의 특성에 최적화된 **다중 모델 영속성(Polyglot Persistence) 아키텍처**를 채택하고 있습니다. 

초당 수만 건의 원시 로그 수집, 트랜잭션 보장(ACID) 인시던트 관리, 실시간 엔티티 관계망 추적, AI 기반 위협 인텔리전스 벡터 검색, 초저지연 인메모리 캐싱을 각각 전담하는 **7가지 특화 스토리지 엔진**을 유기적으로 결합하여 운영합니다.

```
                                  [ AiSOC Polyglot Data Tier ]

     [ Log / Telemetry / HEC ] ──▶ [ Ingest Service (Go) ]
                                           │
                                           ▼
                            ┌─────────────────────────────┐
                            │    Kafka (Event Spine)      │ ─── 7.5.0 분산 스트리밍 백본
                            └─────────────────────────────┘
                                   │               │
                   ┌───────────────┘               └───────────────┐
                   ▼                                               ▼
      ┌─────────────────────────┐                     ┌─────────────────────────┐
      │  ClickHouse Event Lake  │                     │  Fusion Engine / Graph  │
      │  (23.8 열 지향 OLAP)    │                     │ (실시간 상관분석 & 탐지)│
      └─────────────────────────┘                     └─────────────────────────┘
                   │                                               │
                   ▼                                               ▼
         [/hunt 위협 헌팅 검색]                        ┌─────────────────────────┐
                                                       │    Neo4j Entity Graph   │ ─── 5.15-community
                                                       │ (17개 노드 / 14개 엣지) │
                                                       └─────────────────────────┘
                                                                   │
                                                                   ▼
┌─────────────────────────┐    ┌─────────────────────────┐    ┌─────────────────────────┐
│   PostgreSQL 16 (OLTP)  │    │     Redis 7 (Cache)     │    │   Qdrant (Vector DB)    │
│ (핵심 상태 & 메타데이터)     │    │ (Pub/Sub & 인리치먼트)    │    │ (1.7.0 위협 인텔 RAG)     │
└─────────────────────────┘    └─────────────────────────┘    └─────────────────────────┘
```

---

## 1. PostgreSQL 16 (핵심 OLTP 및 시스템 메타데이터)

* **도커 이미지:** `postgres:16-alpine`
* **저장 방식:** 행 기반(Row-oriented) 관계형 테이블, 행 수준 보안(Row-Level Security, RLS), JSONB 지원.
* **역할:** 시스템의 메인 두뇌로서 운영 상태, 테넌트 격리 설정, 인시던트 수명 주기 및 감사 원장 관리.
* **주요 테이블 및 도메인:**
  * **경보 및 인시던트:** `alerts`, `cases`, `case_timeline`, `case_tasks` (SOC 전체 트리아지 수명 주기).
  * **에이전트 감사 원장:** `investigation_runs`, `investigation_events` (프롬프트 해시, LLM 응답 원본, 도구 호출 이력 및 암호화 서명이 담긴 불변 감사 로그).
  * **멀티테넌시 및 접근 제어:** `tenants`, `users`, `roles`, `api_keys`, `passkey_credentials` (PostgreSQL RLS 정책으로 테넌트 간 데이터 완벽 격리).
  * **보안 볼트(Credential Vault):** `connectors`, `tenant_inbox_tokens`, `tenant_llm_credentials` (AES-128 Fernet으로 애플리케이션 계층에서 암호화 저장).
  * **탐지 룰 및 플레이북:** `detection_rules`, `playbooks`, `aisoc_institutional_memory` (과거 인시던트 판정 이력 및 해결 템플릿).

---

## 2. ClickHouse 23.8 (OLAP 분석용 원시 이벤트 레이크)

* **도커 이미지:** `clickhouse/clickhouse-server:23.8`
* **저장 방식:** 열 지향(Columnar) 스토리지, `MergeTree` 엔진 계열 (시간 및 테넌트 기반 파티셔닝, 80% 이상의 압축률).
* **역할:** Splunk, Syslog, EDR 등에서 쏟아지는 대용량 보안 로그를 영구 보관하고 실시간 쿼리(초당 수천만 행)를 처리하는 분석 레이크.
* **주요 사용처:**
  * **`aisoc.raw_events`:** 모든 커넥터에서 수집되어 OCSF 표준으로 정규화된 원시 보안 이벤트를 전수 저장.
  * **`/hunt` 위협 헌팅 엔진:** SPL, ES|QL, KQL, SQL 번역을 통해 수개월 치의 방대한 원시 로그를 수초 내에 검색 및 피벗 분석 (`lake_sql.rewrite_for_tenant`).
  * **운영 통계 집계:** Operations Funnel의 관심 이벤트(Events of Interest, EOI) 실시간 집계.

---

## 3. Neo4j 5.15 (엔티티 및 공격 그래프 데이터베이스)

* **도커 이미지:** `neo4j:5.15-community`
* **저장 방식:** 속성 그래프 모델(Labeled Property Graph), Cypher 쿼리 언어.
* **역할:** 실시간 엔티티 관계망 구축, 횡적 이동(Lateral Movement) 경로 탐색, 피해 확산 반경(Blast Radius) 계산.
* **주요 사용처:**
  * **Graph-at-Ingest:** 로그가 유입되는 즉시 `User`, `Host`, `IP`, `Domain`, `Process`, `Alert`, `File` 등 17개 노드 레이블과 14개 관계 엣지(`AUTHENTICATED_TO`, `RESOLVES_TO`, `SPAWNED`, `COMMUNICATED_WITH` 등)를 자동 적재.
  * **피해 확산 반경 분석:** 침해된 자산을 중심으로 Depth-2 단계까지 연결된 모든 내부 호스트와 관리자 계정을 탐색.
  * **콘솔 시각화:** 대시보드의 `AttackGraphView` 및 조사 레일(Investigation Rail)의 피벗 그래프 렌더링.

---

## 4. Qdrant 1.7 (벡터 유사도 검색 데이터베이스)

* **도커 이미지:** `qdrant/qdrant:v1.7.0`
* **저장 방식:** HNSW(Hierarchical Navigable Small World) 인덱스 기반 고차원 벡터 스토어 (Cosine 유사도).
* **역할:** 위협 인텔리전스 및 보안 지식의 의미론적 유사성 판단, AI 에이전트 RAG(검색 증강 생성).
* **주요 사용처:**
  * **위협 인텔리전스(Threat Intel):** `services/threatintel`에서 IOC(해시, 도메인, IP) 및 위협 그룹(Threat Actor)의 행동 패턴(TTP)을 고차원 벡터로 인덱싱.
  * **의미론적 공격 기법 매칭:** 낯선 공격 텍스트를 보고 가장 유사한 MITRE ATT&CK 기법 및 과거 사례를 자동 추천.

---

## 5. Redis 7 (인메모리 캐시 및 실시간 Pub/Sub)

* **도커 이미지:** `redis:7-alpine`
* **저장 방식:** 인메모리 Key-Value, Hash, Set (`tenant:{tenant_id}:*` 키 네임스페이스 격리).
* **역할:** 마이크로초(Microsecond) 단위의 초저지연 데이터 캐싱, 분산 락, 실시간 브라우저 푸시.
* **주요 사용처:**
  * **보강 데이터 캐시 (`state.enrichment_cache`):** VirusTotal, Shodan, WHOIS, GeoIP 등의 외부 API 반복 호출을 방지하기 위한 캐싱.
  * **실시간 웹소켓 (`services/realtime`):** 알람 승격, 조사 단계 변경, 타임라인 이벤트를 브라우저 클라이언트에 즉시 밀어주는 메시지 버스.
  * **분산 동기화 제어:** 여러 컨테이너에서 커넥터 폴링 및 스케줄러 작업이 중복 실행되지 않도록 분산 락 제어.

---

## 6. Kafka / Redpanda 7.5 (이벤트 스트리밍 백본)

* **도커 이미지:** `confluentinc/cp-kafka:7.5.0` (개발 환경: Zookeeper 연동, 운영 환경: KRaft / Redpanda 호환)
* **저장 방식:** 파티션 기반 Append-only 분산 커밋 로그.
* **역할:** 트래픽 급증 시에도 데이터 유실을 방지하는 결합도 낮은(Decoupled) 무손실 메시지 큐.
* **주요 사용처:**
  * **`raw_events` 토픽:** Ingest 서비스가 OCSF로 변환한 모든 원시 이벤트를 수신하여 병렬 컨슈머(`fusion`, `clickhouse`, `graph_writer`)로 분배.
  * **데드 레터 큐(Dead-Letter Queue, DLQ):** 스키마가 깨지거나 파싱 불가능한 독성 이벤트를 격리하여 파이프라인 전체 중단 방지.

---

## 7. OpenSearch 2.11 (전문 검색 엔진)

* **도커 이미지:** `opensearchproject/opensearch:2.11.0`
* **저장 방식:** 분산 역색인(Inverted Index) JSON 문서 스토어.
* **역할:** 비정형 보안 문서 및 감사 로그의 자연어 전문 검색(Full-text Search).
* **주요 사용처:**
  * **지식 베이스(KB Documents):** SOC 플레이북, 포스트모텀 보고서, 규정 준수 증적 문서의 텍스트 검색.
  * **탐지 룰 제안 카탈로그:** Sigma 및 탐지 룰 정의의 텍스트 매칭 검색 지원.
