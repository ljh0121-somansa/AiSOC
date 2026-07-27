# 브랜치 통합 명세서 (`feature/splunk-siem-integration`)

본 문서는 `feature/splunk-siem-integration` 브랜치에서 수행된 모든 파일 수정 내역, 신규 생성 파일의 아키텍처적 역할, 그리고 마이크로서비스 간 상호 통신 연결 구조를 상세히 기록한 정식 명세서임.

---

## 1. 전체 아키텍처 및 마이크로서비스 간 연결 구조

스플렁크 SIEM 원시 로그 수집, 3-Tier AI 기반 위협 헌팅, Neo4j/PostgreSQL 토폴로지 그래프 연동, 그리고 상업적 제약이 없는 Abuse.ch / CISA KEV 위협 인텔리전스 미러링이 유기적으로 결합된 전체 데이터 및 API 흐름도임.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   [웹 콘솔 대시보드]                                   │
│  - HuntView.tsx (위협 수색 화면)                                                       │
│  - AttackGraphView.tsx (공격 토폴로지 그래프)                                          │
└─────────────────────────────┬──────────────────────────────────────────────────────────┘
                              │
                              │ (REST /api/v1/...)
                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 [핵심 API 게이트웨이]                                  │
│  - endpoints/hunts.py ──► services/hunt_query_generator.py (3-Tier AI / 폴백)        │
│  - endpoints/nl_query.py ──► SOA REST 위임 ──► agents 서비스                           │
│  - endpoints/graph.py ──► services/graph_service.py (Neo4j + Postgres 폴백)          │
│  - services/lake_sql.py ──► sqlglot AST 트랜스파일러 (logs-* ──► raw_events)          │
└──────────────┬──────────────────────────────┬──────────────────────────┬───────────────┘
               │                              │                          │
               ▼                              ▼                          ▼
┌──────────────────────────────┐┌──────────────────────────┐┌───────────────────────────┐
│     [Agents 에이전트 서비스] ││ [ThreatIntel TI 서비스]  ││   [Connectors 수집기]    │
│  - api/nl_query.py (네이티브)││  - clients/abuse_ch.py   ││  - connectors/splunk.py   │
│  - api/hunt_search.py        ││  - parsers/abuse_ch.py   ││    (원천 심각도 추출)     │
│    (ClickHouse 실데이터 수색)││  - feeds/pipeline.py     │└─────────────┬─────────────┘
└──────────────┬───────────────┘│    (ClickHouse 미러링)   │              │
               │                └─────────────┬────────────┘              │
               ▼                              │                           ▼
┌─────────────────────────────────────────────┴──────────────────────────────────────────┐
│                             [ClickHouse & Neo4j 데이터 레이크]                         │
│  - ClickHouse: aisoc.raw_events, aisoc.ioc_enrichments                                 │
│  - Neo4j: Host, User, IP, Alert, Technique 공격 토폴로지 노드                         │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 신규 생성 파일 목록 및 아키텍처 역할

| 파일 경로 | 컴포넌트 역할 | 아키텍처 연결 관계 |
| :--- | :--- | :--- |
| `docs/custom/threat_intelligence_clickhouse.md` | 상업적 무제한 CC0 위협 인텔리전스 ClickHouse 미러링 기술 백서. | `services/threatintel` 서비스의 로컬 미러링 파이프라인 구조를 설명함. |
| `docs/custom/branch_integration_manifest.md` | 통합 변경 명세서 (본 파일). | `feature/splunk-siem-integration` 브랜치의 정식 아키텍처 감사 기록용. |
| `services/agents/app/api/nl_query.py` | 에이전트 컨테이너 내부 네이티브 자연어 번역 전담 REST API 엔드포인트 (`/api/v1/nl-query/translate`). | `app.llm` 및 `app.nl_query` 패키지를 직접 가동하며 API 게이트웨이의 위임 호출을 수신함. |
| `services/api/app/services/hunt_query_generator.py` | 3-Tier 지능형 LLM / 정적 폴백 쿼리 자동 생성 코어 서비스. | `endpoints/hunts.py` 컨트롤러에서 호출되며 공용 `resolve_llm_config` 바인딩을 활용함. |
| `services/api/migrations/047_aisoc_hunts_query_generation_mode.sql` | `aisoc_hunts` 테이블에 `query_generation_mode` 및 `warnings` 컬럼을 추가하는 DB 마이그레이션. | API 부팅 시 `run_migrations.py`에 의해 데이터베이스에 자동 적용됨. |
| `services/api/tests/test_hunts_tiered_generation.py` | 3-Tier (Public ──► Private Local ──► Deterministic) 생성 흐름 검증 격리 단위 테스트. | CI/CD 및 로컬 테스트 파이프라인에서 자동 수행됨. |
| `services/threatintel/app/clients/abuse_ch.py` | Abuse.ch (ThreatFox C2, URLhaus) 오픈 API 전용 비동기 HTTP 클라이언트. | `services/threatintel/app/feeds/scheduler.py`에 의해 주기적 수집 기동됨. |
| `services/threatintel/app/parsers/abuse_ch.py` | ThreatFox 및 URLhaus 원시 JSON 응답을 플랫폼 표준 IOC 규격으로 가공하는 정규화 파서. | `feeds/handlers.py` 수집 핸들러에서 수신 데이터 변환용으로 호출됨. |

---

## 3. 기존 수정 파일 및 세부 변경 내역

### A. 인프라 및 환경 설정 (Infra & Config)
*   **`manage.sh`**: 개발자 샌드박스 클린 재기동 및 Kafka 볼륨 초기화 유틸리티 로직 강화.

### B. 핵심 API 서비스 (`services/api`)
*   **`services/api/app/api/v1/endpoints/hunts.py`**: 가설 수립 시 `generate_queries_tiered` 서비스로 쿼리 번역을 위임(SRP 준수)하고 생성 모드 및 경고 메시지를 세이브하도록 개편.
*   **`services/api/app/api/v1/endpoints/nl_query.py`**: 부모 디렉토리 추적 모듈 임포트를 폐기하고, `agents` 서비스로 자연어 번역 요청을 포워딩하는 SOA REST 위임 게이트웨이(`_delegate_translation_to_agents`)로 전환.
*   **`services/api/app/api/v1/endpoints/saved_hunts.py`**: `_translate` 헬퍼 함수를 비동기 REST 위임 구문으로 변경.
*   **`services/api/app/api/v1/endpoints/threat_intel.py`**: 프론트엔드 호환성을 위한 `GET /api/v1/threat-intel/indicators` 엔드포인트 및 `IndicatorsResponse` Pydantic 모델 구현.
*   **`services/api/app/api/v1/endpoints/graph.py`**: 전체 테넌트 공격 그래프 조회를 위한 `GET /api/v1/graph` 엔드포인트 개설 (Neo4j ──► PostgreSQL 관계형 DB 2단계 동적 폴백 적용).
*   **`services/api/app/services/graph_service.py`**: Neo4j DB에서 전체 노드 및 관계선을 수색하는 Cypher 쿼리 함수 `get_overview_graph()` 추가.
*   **`services/api/app/services/lake_sql.py`**: 정규식 치환 방식 대신 `sqlglot` AST 구문 분석기를 적용하여 SIEM 인덱스 표기(`logs-*`, `events` ──► `aisoc.raw_events`) 및 시간 칼럼(`_time` ──► `event_time`)을 문법 트리 레벨에서 치환.

### C. 에이전트 서비스 (`services/agents`)
*   **`services/agents/app/api/hunt_search.py`**: ad-hoc 수색을 ClickHouse `aisoc.raw_events` 데이터 레이크와 다이렉트 바인딩; `esql`/`kql`/`spl` 등 모든 Dialect에 대한 키워드 정밀 필터링 구현; 매칭 결과 0건 시 가짜 더미 출력을 소거하고 정직한 0건 반환.
*   **`services/agents/app/llm/contract.py`**: `safe_chat_completions_request`가 커스텀 Base URL 및 모델 오버라이드를 안전하게 수용하도록 파라미터 보정.
*   **`services/agents/app/main.py`**: 네이티브 자연어 번역 라우터(`nl_query_router`) 정식 등록.

### D. 커넥터 서비스 (`services/connectors`)
*   **`services/connectors/app/connectors/splunk.py`**: `normalize()` 함수 내 정규식을 보강하여 중첩 `_raw` 페이로드 내의 원천 심각도(`critical`/`high`)를 추출함으로써 `fusion` 엔진에서 실시간 경보 승격이 무결하게 이뤄지도록 수선.

### E. 위협 인텔리전스 서비스 (`services/threatintel`)
*   **`services/threatintel/app/feeds/handlers.py`**: `handle_threatfox_feed` 및 `handle_urlhaus_feed` 수집 핸들러 구현.
*   **`services/threatintel/app/feeds/pipeline.py`**: 수집된 지표를 ClickHouse `aisoc.ioc_enrichments` 테이블로 bulk 인서트하는 `_write_to_clickhouse()` 비동기 메소드 작성.
*   **`services/threatintel/app/main.py`**: ThreatFox 및 URLhaus 피드를 Daily 스케줄러에 등록하고 에어갭 허용 목록 검사를 정합함.

### F. 프론트엔드 웹 콘솔 (`apps/web`)
*   **`apps/web/src/components/graph/AttackGraphView.tsx`**: 하드코딩된 가짜 목업 노드(`DEMO_GRAPH`) 및 `buildDemoCoverage()` 완전히 소거; DB 유휴 시 정직한 한글 안내판 표출.
*   **`apps/web/src/components/hunt/HuntView.tsx`**: 수색 결과판 및 빈 결과 상태 문구를 정식 한글로 포맷팅; 결과 0건 시 가짜 더미 노출을 막고 `0건`을 명확히 시각화.
