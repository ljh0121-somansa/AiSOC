# AiSOC 개발망 격리 및 위협 수색(Hunts) 파이프라인 고도화 잔여 태스크 (TODO)

이 문서는 다중 개발 환경 샌드박스 격리 및 실시간 수집-탐지 배선 완료 후, 향후 세션에서 지속 추진할 설계 과제 및 튜닝 태스크를 기입한 이력 카드임.

---

## 1. 최우선 예정 과제: 경보 레벨 AI 수색 실배선 연계 (Alert-level AI Investigation Re-wiring)

*   **배경**: 현재 알림 상세 화면(`AlertDetailView.tsx`)에서 "Start Investigation"을 누르면 `POST /api/v1/agents/investigate` 더미 호출 실패로 인해 하드코딩된 가상 랜섬웨어 마크다운 보고서(Fallback)만 노출되는 상태임.
*   **목표**: 단독 경보 조사 시에도 가상 더미가 아닌, 실제로 구동 중인 케이스 탐색 엔진(`LangGraph` 기반 `FusionWorker`)을 호출하도록 표준 파이프라인을 재배선함.
*   **실행 세부 계획**:
    - [ ] **백엔드 프록시 API 생성 (`services/api`)**:
        *   `services/api/app/api/v1/endpoints/agents.py` 내에 `POST /api/v1/agents/investigate` 정식 라우터 개설.
        *   인입된 `alert_id`를 기반으로 대응되는 `case_id` 유무를 데이터베이스에 조회.
        *   케이스가 없을 시 가상 케이스를 1초 만에 자동 임시 생성(Seeding)함.
        *   확보된 `case_id`를 이용하여 검증 완료된 실 기동 API인 `POST /api/v1/cases/{case_id}/investigate`를 내부 포워딩(REST Proxy 호출) 처리함.
    - [ ] **프론트엔드 더미 제거 및 렌더링 배선 (`apps/web`)**:
        *   `apps/web/src/components/alerts/AlertDetailView.tsx` 350번 라인 부근의 `catch (err)` 우회 구문 소거.
        *   수신된 진짜 AI 수색 보고서 결과물 데이터를 에디터에 그대로 다이내믹 렌더링하도록 UI 연동 완료함.

---

## 2. 보안 데이터 레이크 고속화 및 임베딩 보강 과제 (Threat Intel & ClickHouse)

*   **배경**: 현재 Abuse.ch(ThreatFox, URLhaus) 및 CISA KEV 오픈 피드가 클릭하우스(`aisoc.ioc_enrichments`)에 안전하게 자동 격리 수집(Local Mirroring)되는 파이프라인이 수립됨.
*   **목표**: 수집된 데이터의 실시간 수색 매핑 효율화.
*   **실행 세부 계획**:
    - [ ] **상관 탐지 룰 동적 싱크**:
        *   ClickHouse 적재와 동시에 스플렁크 또는 EDR 로그 인입 시 `ioc_enrichments` 마스터 위협 테이블을 서브쿼리 조인(`JOIN`)하여 실시간 악성 통신 여부를 즉각 마킹하는 실무용 탐지 규칙(Rule) 신규 편찬 및 보강.
    - [ ] **Qdrant 시맨틱 벡터 인덱싱 성능 튜닝**:
        *   수만 건의 IOC 위협 지표 텍스트에 대한 임베딩 벡터 생성 시, CPU 과부하를 막기 위해 배치 사이즈 조율 및 로컬 임베딩 스레드 제한 튜닝 실시.

---

## 3. 다중 사용자 개발 환경 상시 운전 가이드 (Developer Sandbox Guide)

*   **목적**: 개발자 1, 2가 단일 공유 서버의 본 Git 저장소 내에서 충돌 없이 상시로 환경을 스위칭하고 버그 픽스를 지속해 나가기 위함.
*   **구동 표준 명령어**:
    ```bash
    # 개발자 1 환경 가동 시
    cp .env.dev1 .env
    ./manage.sh restart
    
    # 개발자 2 환경 가동 시
    cp .env.dev2 .env
    ./manage.sh restart
    ```
*   **주의 사항**: 도커 소켓 권한 거부 에러 발생 시, 호스트 단에서 `sudo usermod -aG docker rpteam` 및 `newgrp docker`를 실행하여 권한을 수동 복원 후 재진입함.
