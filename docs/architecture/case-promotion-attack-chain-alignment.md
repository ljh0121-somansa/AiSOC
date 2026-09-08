# Case Auto-Promotion & Attack Chain Alignment Technical Guide

## 1. 개요 (Overview)
AiSOC 플랫폼에서 보안 경보(Alert)가 발생하고 Fusion 및 Auto-Triage를 거쳐 사건(Case)으로 자동 승격(Auto-promote)될 때, **중복 알림의 무분별한 Case 난립을 방지**하고 **Attack Chain(공격 연관성 타임라인 및 엔티티 그래프)이 100% 정상 출력**되도록 파이프라인 정합성을 보정하였습니다.

---

## 2. 기존 문제점 및 원인 분석 (Root Cause)

### 2.1. 중복 알림의 무분별한 Case 생성
* **현상**: 동일한 보안 이벤트가 반복 유입될 때 Fusion 계층에서는 `dedup_hash`를 통해 DB 저장을 스킵하지만, Kafka에는 새 가상 ID로 메시지가 전송되었습니다.
* **문제**: 하위 에이전트(`fused_alert_consumer.py`)가 중복 알림인지 확인하지 않고 매번 `create_ticket / auto-create` 플레이북을 실행하여 동일한 알림에 대해 Case가 무한히 생성되었습니다.

### 2.2. Attack Chain 빈 화면 출력 (Seed Alert 누락)
* **현상**: Case 상세 화면에서 Attack Chain 탭 진입 시 연관 공격 그래프가 표시되지 않음(`Chain: None`).
* **문제**: 자동 생성된 Case의 `alert_ids`에 DB에 실제로 존재하지 않는 가상 Alert ID가 바인딩되면서, Attack Chain 연산 엔진이 시작점(Seed Alert)을 찾지 못해 연산을 건너뛰었습니다.

---

## 3. 수정 및 개선 사항 (Implementation)

### 3.1. 에이전트 워커 중복 및 오탐 트리거 가드레일 (`services/agents/app/workers/fused_alert_consumer.py`)
* **중복 알림 건너뛰기**: Fusion에서 `DUPLICATE`로 분류되었거나 Governor 캐시에서 `DEDUPLICATED`로 판정된 알림은 Case 생성 플레이북 트리거를 즉시 스킵(`skip_playbook_duplicate`).
* **자동 종결 알림 배제**: Auto-Triage에서 고신뢰 오탐(`false_positive`) 또는 정상(`benign`)으로 판단된 알림은 Case 승격을 수행하지 않고 종료(`skip_playbook_autoclosed`).

### 3.2. Case 자동 생성 엔드포인트의 Alert 매핑 보정 (`services/api/app/api/v1/endpoints/cases.py`)
* **실제 Alert UUID 역추적 Fallback**: `POST /api/v1/cases/auto-create` 호출 시 전달된 ID로 Alert를 찾지 못할 경우, `title`과 `tenant_id`를 기반으로 실제 `alerts` 테이블에 저장된 원본 레코드를 조회하여 **실제 DB의 Alert UUID를 Case에 100% 연결**.
* **열린 Case 중복 방지 (Merge)**: 동일 테넌트 및 동일 알림/엔티티에 대해 이미 진행 중인 Case(`open`, `investigating`)가 존재할 경우, 새 Case를 중복 생성하지 않고 기존 Case의 `alert_ids`와 엔티티 그래프에 병합(Merge).

---

## 4. 검증 결과 (Verification)

1. **중복 알림 억제 검증**:
   - 동일 이벤트 반복 발생 시 `skip_playbook_duplicate`가 동작하여 불필요한 Case 생성이 차단됨.
2. **Attack Chain 정상 렌더링 검증**:
   - `GET /api/v1/cases/{case_id}/attack-chain` 호출 시 유효한 Seed Alert를 바탕으로 7단계 공격 체인과 13개 노드 / 20개 엣지 그래프가 정상 연산 및 반환됨을 확인.

---

## 5. 변경된 파일 목록 (Modified Files)
* `services/agents/app/workers/fused_alert_consumer.py`: 중복/오탐 알림 플레이북 실행 방지 가드레일 추가.
* `services/api/app/api/v1/endpoints/cases.py`: 원본 Alert UUID Fallback 조회 및 열린 Case 병합 로직 강화.
