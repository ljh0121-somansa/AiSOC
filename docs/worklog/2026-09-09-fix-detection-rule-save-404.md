# [업무일지] 플랫폼 기본 탐지 규칙 저장 404 오류 수정 및 권한 분리

**일자**: 2026년 9월 9일  
**작업자**: AiSOC 개발팀  
**상태**: 완료 (테스트 및 브라우저 E2E 검증 통과)

---

## 1. 업무 개요 및 배경
* **이슈 현상**:
  - 관리자(`admin@somansa.com`, `role: platform_admin`)가 플랫폼 기본 내장 탐지 규칙인 `c19fbb15-14e8-4c25-810b-bff177e4a72e` (*"Burst Of File Extension Renames To Common Ransom Markers"*) 페이지에서 규칙 수정 후 [Save] 버튼 클릭 시 `API 404 Not Found — /api/v1/detection/rules/c19fbb15-14e8-4c25-810b-bff177e4a72e` 오류 발생.
* **근본 원인**:
  1. 조회 API(`GET /api/v1/detection/rules/{id}`)는 플랫폼 전역 규칙(`tenant_id IS NULL`) 조회를 허용하도록 구현됨.
  2. 그러나 수정(`PATCH /api/v1/detection/rules/{rule_id}`) 및 삭제(`DELETE`) API는 `tenant_id == current_user.tenant_id`로 강제 격리 쿼리를 수행함.
  3. 플랫폼 관리자(`platform_admin`)라도 특정 `tenant_id`를 보유하고 있으므로, `tenant_id`가 `NULL`인 기본 규칙 갱신 시 대상 레코드가 조회되지 않아 `404 Not Found`가 반환됨.
  4. 프론트엔드(`RuleEditor.tsx`) 또한 플랫폼 기본 규칙에 대한 권한 제어(읽기 전용 배너, 버튼 비활성화 등) 및 API 상세 에러 메시지 노출이 미흡했음.

---

## 2. 작업 내용 및 변경 파일

### 2.1. 백엔드 호환 엔드포인트 수정 (`services/api/app/api/v1/endpoints/detection_compat.py`)
* **규칙 수정 (`update_rule_compat`)**:
  - 룰 ID 기반 조회(`select(DetectionRule).where(DetectionRule.id == rule_id)`)로 변경.
  - 규칙 미존재 시 `404 Not Found`.
  - 플랫폼 기본 룰(`rule.tenant_id is None`)일 때 호출자가 `platform_admin`이 아니면 `403 Forbidden` (`"Built-in platform detection rules can only be modified by a platform administrator"`) 반환.
  - 타 테넌트 규칙이고 호출자가 `platform_admin`이 아니면 `404 Not Found` 반환 (테넌트 간 데이터 격리 유지).
  - 인메모리 `setattr` 및 `db.execute(update(...))`를 통해 변경 사항 즉시 반영 및 `isBuiltin` 포함 응답 반환.
* **규칙 삭제 (`delete_rule_compat`)**:
  - 동일한 RBAC 인가 로직 적용 (기본 룰 삭제 시 `platform_admin` 전용 허용, 타 권한 403 차단).
* **대량 토글 (`bulk_toggle_rules`)**:
  - `platform_admin`인 경우 `tenant_id == current_user.tenant_id OR tenant_id IS NULL` 모두 활성화/비활성화 대상에 포함. 일반 사용자는 기본 룰이 `skipped` 목록으로 처리됨.
* **응답 모델 확장**:
  - `FrontendDetectionRule`에 `isBuiltin: bool = False` 필드 추가 및 `_to_frontend()` 매핑.

### 2.2. 표준 REST API 엔드포인트 수정 (`services/api/app/api/v1/endpoints/detection_rules.py`)
* `update_rule` (`PATCH /api/v1/rules/{rule_id}`) 및 `delete_rule` (`DELETE /api/v1/rules/{rule_id}`):
  - 동일하게 기본 룰에 대한 `platform_admin` 수정/삭제 허용 및 일반 사용자 403 차단 적용.

### 2.3. 프론트엔드 API 클라이언트 및 타입 정의 (`apps/web/src/lib/api.ts`)
* `DetectionRule` 인터페이스에 `isBuiltin?: boolean;` 속성 추가.
* `authApi.currentUser()`:
  - `localStorage`에 캐시된 유저 정보(`AUTH_USER_KEY`)가 없을 경우, 저장된 JWT 액세스 토큰(`aisoc_access_token` / `AUTH_TOKEN_KEY`) 페이로드를 디코딩하여 `role`, `email`, `tenant_id`를 복원하는 안전한 Fallback 로직 추가.

### 2.4. 탐지 룰 에디터 및 목록 UI 개선 (`apps/web/src/components/detections/`)
* **`RuleEditor.tsx`**:
  - `useTenant()` 및 `authApi.currentUser()`를 통해 `platform_admin` 역할 여부 검증.
  - 상단 헤더에 보라색 `Built-in` 배지 표시.
  - 일반 분석가가 기본 룰 조회 시:
    - *"This is a platform built-in rule. Only platform administrators can modify it directly. Use 'Propose for review' to suggest updates."* 안내 배너 표시.
    - [Save], [Delete] 버튼 비활성화 및 툴팁 안내.
  - 플랫폼 관리자(`platform_admin`)의 경우 모든 수정/저장/삭제 버튼 활성화.
  - `handleSave` / `handleDelete` 오류 처리 시 단순 실패 메시지 대신 백엔드에서 전달된 실제 `ApiError` 상세(detail) 메시지를 Toast로 안내.
* **`DetectionsView.tsx`**:
  - 규칙 카드(`RuleCard`)에 `Built-in` 배지 추가.

---

## 3. 테스트 및 검증 결과

### 3.1. 백엔드 RBAC 단위 테스트 작성 및 통과
* 파일: `services/api/tests/test_detection_rule_mutation_rbac.py`
* 10개 시나리오 전수 작성 및 검증:
  1. `test_platform_admin_can_update_builtin_rule` (통과)
  2. `test_tenant_analyst_cannot_update_builtin_rule` (403 검증 통과)
  3. `test_update_nonexistent_rule_returns_404` (404 검증 통과)
  4. `test_tenant_analyst_cannot_update_other_tenant_rule` (404 테넌트 격리 통과)
  5. `test_tenant_analyst_can_update_own_rule` (일반 룰 수정 200 통과)
  6. `test_delete_rule_compat_rbac` (삭제 권한 분리 통과)
  7. `test_bulk_toggle_platform_admin_vs_analyst` (대량 토글 분리 통과)
  8. `test_platform_admin_can_update_builtin_canonical` (표준 API 통과)
  9. `test_analyst_cannot_update_builtin_canonical` (표준 API 403 통과)
  10. `test_delete_rule_canonical_rbac` (표준 API 삭제 분리 통과)
* 결과: **10 passed in 4.05s** (기존 탐지 관련 테스트 59건 포함 총 69건 전원 통과).

### 3.2. 실제 컨테이너 API 스모크 테스트
* 대상: `PATCH http://127.0.0.1:18000/api/v1/detection/rules/c19fbb15-14e8-4c25-810b-bff177e4a72e`
* 호출 결과:
  - HTTP 200 반환, `isBuiltin: true` 응답 확인.
  - PostgreSQL DB 조회: `description` 업데이트 및 `version` 1 → 2 증가 확인.

### 3.3. 웹 서비스 리빌드 및 브라우저 E2E 검증
* `docker compose -f docker-compose_server.yml build web` 프로덕션 이미지 빌드 및 `aisoc-dev1-web` 컨테이너 재배포 완료.
* 브라우저 자동화를 통해 `http://10.216.0.155/detection/c19fbb15-14e8-4c25-810b-bff177e4a72e` 접속:
  - `BUILT-IN` 배지 렌더링 확인.
  - `Save` 버튼 활성화 상태 확인.
  - `Save` 클릭 시 `Rule saved` Toast 정상 발생 (콘솔 404 에러 미발생).
  - PostgreSQL DB 확인 결과 `version: 3`, `updated_at` 갱신 정상 반영 확인.
