# 검증 완료된 7대 데이터 저장소 아키텍처 명세 (Verified Datastores)

[메타데이터]
- 검증 기준: `docker-compose.yml`, `services/api/app/models/`, `services/ingest/internal/graph/`, `services/threatintel/`, `services/connectors/`
- 검증 일자: 2026-08-21
- 검증 상태: 100% 코드베이스 및 인프라 대조 일치

---

## 1. PostgreSQL 16 (`postgres:16-alpine`)
* **역할:** 트랜잭션 보장 메인 RDBMS (OLTP)
* **저장 방식:** 행 기반 관계형 테이블, RLS(Row-Level Security) 테넌트 격리, JSONB
* **주요 테이블:** `alerts`, `cases`, `case_timeline`, `investigation_events`(감사원장), `tenants`, `users`, `connectors`, `detection_rules`, `playbooks`

## 2. ClickHouse 23.8 (`clickhouse/clickhouse-server:23.8`)
* **역할:** 대용량 원시 보안 로그 분석 레이크 (OLAP)
* **저장 방식:** 열 지향(Columnar) `MergeTree` 엔진, 시간/테넌트별 파티셔닝
* **주요 사용처:** `aisoc.raw_events` (OCSF 원시 이벤트 전수 저장), `/hunt` 위협 헌팅 초고속 쿼리, EOI 통계

## 3. Neo4j 5.15 (`neo4j:5.15-community`)
* **역할:** 실시간 엔티티 연관 그래프 데이터베이스
* **저장 방식:** 속성 그래프 모델 (17개 노드 레이블, 14개 관계 엣지), Cypher 쿼리
* **주요 사용처:** Graph-at-Ingest 실시간 관계망 구축, 피해 확산 반경(Blast Radius) 계산, 횡적 이동 경로 탐색

## 4. Qdrant 1.7 (`qdrant/qdrant:v1.7.0`)
* **역할:** 위협 인텔리전스 벡터 데이터베이스
* **저장 방식:** HNSW 인덱스 기반 고차원 벡터 스토어 (Cosine 유사도)
* **주요 사용처:** `services/threatintel`의 IOC/위협 그룹 TTP 임베딩 저장 및 의미론적 공격 기법 매칭 (RAG)

## 5. Redis 7 (`redis:7-alpine`)
* **역할:** 인메모리 캐시 및 실시간 Pub/Sub
* **저장 방식:** Key-Value, Hash, Set (`tenant:{tenant_id}:*` 네임스페이스)
* **주요 사용처:** `state.enrichment_cache`(외부 API 중복 호출 방지), `services/realtime` 웹소켓 실시간 이벤트 푸시, 분산 락

## 6. Kafka / Redpanda 7.5 (`confluentinc/cp-kafka:7.5.0`)
* **역할:** 분산 이벤트 스트리밍 백본 (Message Spine)
* **저장 방식:** 파티션 기반 Append-only 분산 커밋 로그
* **주요 사용처:** `raw_events` 토픽 (수집 이벤트의 중앙 버퍼링 및 다중 서비스 분배), Dead-Letter Queue(독성 이벤트 격리)

## 7. OpenSearch 2.11 (`opensearchproject/opensearch:2.11.0`)
* **역할:** 전문 텍스트 검색 엔진 (Full-text Search)
* **저장 방식:** 분산 역색인(Inverted Index) JSON 문서
* **주요 사용처:** 보안 지식 베이스(KB Documents) 및 룰 카탈로그 전문 텍스트 검색
