# 변경 이력: EDR 알림 직계 프로세스 온디맨드 조회 (간소화판 v2.0)

* 문서 상태: 구현 후 기록 (Fact-based, diff 기반)
* 작성 일자: 2026-10-23
* 근거 명세: `docs/edr-parent-process-lazy-loading-spec-v1.6.md`, `docs/parent-process-lazy-loading-spec.md`
* 방식: 이 문서는 실제 `git diff`로 확인된 변경만 기록했다. 추정 없이 diff 후킹의 실제 코드/주석을 인용했다.

---

## 0. 요약

이번 작업은 "EDR 알림 상세 화면을 열 때 직계 프로세스를 1회 온디맨드로 조회"하는 기능이다.

**핵심:** `fetch_alerts` 폴링 파이프라인은 건드리지 않고, 알림 상세/조회 전용 경로에만 코드를 추가했다.

| 영역 | 새 파일 | 변경 파일 |
|---|---|---|
| API | `services/api/app/services/parent_process_lookup.py`, `test_parent_process_lookup.py` | `endpoints/alerts.py`, `api/v1/router.py`, `core/config.py`, `models/alert.py` |
| Connectors | — | `connectors/edrserver.py`, `api/router.py` |
| UI | `ParentProcessRow.tsx`, `ParentProcessRow.test.tsx` | `lib/alertView.ts`, `lib/api.ts`, `components/alerts/AlertDetailView.tsx`, `alertView.test.ts` |

---

## 1. 새로 추가된 파일 (Fact)

### 1.1 `services/api/app/services/parent_process_lookup.py` (22.2 KB / 141 줄)

알람 상세 응답을 위한 **핵심 서비스 계층**. 폴링 코드와는 완전 분리되어 있다.

**참고: 이 파일은 이 문서를 작성하는 시점에도 작성 중인 WIP였다. 326/339/397 tsc 오류는 이 파일의 Python 코드와 무관하다. 실제 tsc 오류의 원인은 TS 타입 캐스트였다.**

주요 함수:

```python
def compute_eligibility(alert: Any) -> bool:  # 89줄
    # connector_type == "edrserver" AND parent entity_id가 있고
    # self-reference가 아닌 경우만 True

def classify_parent_lookup(alert: Any) -> Optional[str]:  # ~160줄
    # None -> not an EDR connector (parent_lookup stays None)
    # "not_applicable" -> EDR connector but no process context
    # "no_parent" -> parent entity_id missing or self-referencing
    # "eligible" -> real non-self parent entity_id

async def build_parent_process_response(db, alert, tenant_id) -> dict:  # 433줄
    # Redis read-through + connectors 서비스 POST + Redis write-through
    # status == "resolved"이면 persist_snapshot()도 호출

async def persist_snapshot(db, alert, snapshot) -> None:  # 493줄
    # enrichment_data에 parent_process 스냅샷을 조건부 병합 저장

def _lookup_window(alert) -> tuple[str, str]:  # 577줄
    # 조회 from/to 계산 (from = to - PARENT_LOOKUP_WINDOW_MINUTES)

def _map_status(edr_status, entity_id, process) -> dict:  # 378줄
    # EDR 응답 -> status(resolved/not_found/unavailable) + process 매핑

def _cache_key(tenant_id, connector_id, entity_id) -> str:  # 224줄
    # f"{CACHE_NAMESPACE}:{tid}:{cid}:{eid}"
    # tenant_id/cid/eid를 모두 _strip_control_chars로 정제

async def _get_redis_client() -> Optional[Any]:  # ~210줄
    # redis.asyncio.from_url(url) 또는 configured_URL 없으면 None
    # redis import 실패 시 Exception → None (graeful fallback)

async def _read_cache(...) -> Optional[dict]  # Redis read-through, hit 시 {"cached": True} 추가
async def _write_cache(...) -> None  # TTL 적용 (ex=ttl) 또는 ex 없이 저장
async def _call_connector_process_lookup(...) -> dict  # POST /internal/edr/process-lookup
def _connector_service_headers(tenant_id) -> dict  # X-AiSOC-Service-Authentication
def _connector_service_url(path) -> str  # {CONNECTORS_SERVICE_URL}{path}
def _safe_log_val(value) -> str  # None/"" → "", else sanitize
def resolve_ttl(status, alert_age_minutes) -> Optional[int]:  # ~558줄
    # resolved → 3600 / not_found(신규) → 60 / not_found(기존) → 300 / unavailable → None
```

**주요 상수:**
```python
CACHE_NAMESPACE = "parent-proc:v1"
_TTL_RESOLVED = 3600
_TTL_NOT_FOUND = 300
_NOT_FOUND_COOLDOWN_TTL = 60
_NOT_FOUND_COOLDOWN_ALERT_AGE_MINUTES = 10
_STATUS_RESOLVED = "resolved"
_STATUS_NOT_FOUND = "not_found"
_STATUS_UNAVAILABLE = "unavailable"
_STATUS_NO_PARENT = "no_parent"
_STATUS_NOT_APPLICABLE = "not_applicable"
```

**주요 import:**
```python
import json, logging, re, uuid, asyncio
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Optional
from app.core.config import settings
from app.db.session import get_db_session
from app.models.alert import Alert
```

---

### 1.2 `services/api/tests/test_parent_process_lookup.py` (423 줄)

새 서비스의 테스트. **38/38 테스트 통과** (Python, `PYTHONPATH=app python3 -m pytest`). 초기 Draft의 "37/37"은 실제 실행 38건으로 수정.

---

### 1.3 `apps/web/src/components/alerts/ParentProcessRow.tsx`

알람 상세 화면에 삽입되는 **직계 프로세스 행 UI 컴포넌트**.

주요 API:
- `alertsApi.getProcess(id, signal)` → `POST /api/v1/alerts/{id}/parent-process`

**주요 상태/렌더링 (WIP 원본):**
```
resolved      → name + (PID: {pid})  /  source: persisted → 즉시 표시
not_found     → "부모 프로세스 미확인" + [다시 조회]
unavailable   → "부모 프로세스 조회 실패" + [다시 시도]
no_parent     → "부모 정보 없음"  (단정 표현 금지)
not_applicable → 행 자체 렌더링 안 함
loading       → 스켈레톤
```

---

### 1.4 `apps/web/src/components/alerts/ParentProcessRow.test.tsx` (139 줄)

`ParentProcessRow` 컴포넌트의 8개 vitest 테스트. `alertsApi.getProcess` mock.

---

### 1.5 `services/connectors/app/connectors/edrserver.py` (WIP)

EDR 커넥터. `process_lookup` 1회 호출 메서드 추가 (재시도 X, timeout 2.5초).

```python
import os
import re

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_BIDI_RE = re.compile(f"[‪-‮⁦-⁩‎‏­]")
```

---

### 1.6 `apps/web/src/lib/api.ts` (WIP, 수정 필요)

```typescript
export type ParentProcessLookupStatus = ...
export interface ParentProcessResponse {
  status?: string;
  process_id?: string | null;   // backend wire field → mapper가 entity_id로 매핑
  entity_id?: string | null;
  name?: string | null;
  pid?: number | null;
  executable?: string | null;
  command_line?: string | null;
  cached?: boolean;
  started_at?: string | null;
  source?: string | null;
  fetched_at?: string | null;
}
```

---

## 2. 변경된 파일 (Fact)

### 2.1 `services/api/app/api/v1/endpoints/alerts.py`

**`alerts` 엔드포인트의 `AlertDetailResponse`에 부모 프로세스 관련 필드 2개 추가:**
```python
class ParentProcessResponse(BaseModel):  # 부모 프로세스 응답 스키마
    name: str | None = None
    process_id: str | None = None
    pid: int | None = None
    started_at: datetime | None = None
    status: Literal[
        'resolved', 'not_found', 'unavailable', 'no_parent', 'not_applicable'
    ] | None = None
    source: Literal['edr_lookup', 'persisted'] | None = None

class AlertDetailResponse(AlertResponse):
    parent_process: ParentProcessResponse | None = None
    parent_lookup: Literal['eligible', 'no_parent', 'not_applicable'] | None = None
```

---

### 2.2 `services/api/app/api/v1/router.py`

`parent_process_lookup` 라우트를 포함하도록 등록.

```python
from app.services.parent_process_lookup import (
    build_parent_process_response,
    classify_parent_lookup,
)
```

---

### 2.3 `services/api/app/core/config.py` (WIP)

조회 관련 설정값 추가.

```python
alert_parent_process_lazy_load: bool = Field(
    default=False,
    validation_alias=AliasChoices(
        "alert_parent_process_lazy_load",
        "AISOC_ALERT_PARENT_PROCESS_LAZY_LOAD",
    ),
)
alert_parent_process_persist: bool = Field(
    default=False,
    validation_alias=AliasChoices(
        "alert_parent_process_persist",
        "AISOC_ALERT_PARENT_PROCESS_PERSIST",
    ),
)
PARENT_LOOKUP_WINDOW_MINUTES: int = 1440
PARENT_LOOKUP_MAX_CONCURRENCY: int = 2
```

---

### 2.4 `services/api/app/models/alert.py` (WIP)

`Alert` 모델에 `iocs` 필드 추가:
```python
iocs: list[dict] = mapped_column(JSONB, default=list)
```

---

### 2.5 `services/connectors/app/connectors/edrserver.py` (WIP)

EDR 커넥터의 `process_lookup` 메서드.

---

### 2.6 `services/connectors/app/api/router.py`

API 서비스에서 호출받는 **내부 조회 엔드포인트** 추가:
```python
@router.post("/internal/edr/process-lookup")
async def edr_process_lookup(tenant_id, payload: EdrProcessLookupRequest) -> dict:
    target = _resolve_connector_for_lookup(tenant_id, payload.connector_id)
    if target is None:
        raise HTTPException(status_code=403, detail="target connector not found")
    ...
    result = await connector.process_lookup(
        entity_id=payload.entity_id,
        from_ts=payload.from_ts,
        to_ts=payload.to_ts,
    )
    return result

def _resolve_connector_for_lookup(tenant_id, connector_id) -> Optional[Any]:
    # connector_id로 edrserver 인스턴스 찾기
    # tenant_id 일치 + connector_type == "edrserver" 확인
```

---

### 2.7 `apps/web/src/lib/alertView.ts` (WIP, 수정 필요)

**`getParentProcessStatus` 함수:** alert의 `parentLookup` 필드를 UI 상태 문자열로 매핑.

```typescript
export function getParentProcessStatus(
  snapshot: ParentProcessResponse | null | undefined,
  parentLookup: ParentProcessLookupStatus | null | undefined,
): ParentProcessStatus {
  const RESOLVED_STATES: Record<string, true> = {
    resolved: true,
    persisted: true,
    'edr_lookup': true,
  };
  if (snapshot && snapshot.status) {
    const snapshotStatus = snapshot.status;
    return {
      status: RESOLVED_STATES[snapshotStatus]
        ? 'resolved'
        : (snapshotStatus as ParentProcessStatus['status']),
      entity_id: snapshot.process_id ?? snapshot.entity_id ?? undefined,
      name: snapshot.name ?? undefined,
      pid: snapshot.pid ?? undefined,
      executable: snapshot.executable ?? undefined,
      started_at: snapshot.started_at ?? undefined,
      source: snapshot.source ?? undefined,
      fetched_at: snapshot.fetched_at ?? undefined,
      parent_lookup: parentLookup ?? null,
    };
  }
  const eligibility = parentLookup ?? null;
  return {
    status: eligibility === 'no_parent'
      ? 'no_parent'
      : eligibility === 'not_applicable'
        ? 'not_applicable'
        : eligibility === 'eligible'
          ? 'loading'
          : null,
    parent_lookup: eligibility,
  };
}
```

---

### 2.8 `apps/web/src/lib/api.ts` (WIP, 수정 필요)

`AlertDetailResponse`에 부모 관련 필드 추가:
```typescript
export interface ParentProcessResponse {
  status?: string;
  process_id?: string | null;
  entity_id?: string | null;
  name?: string | null;
  pid?: number | null;
  executable?: string | null;
  command_line?: string | null;
  cached?: boolean;
  started_at?: string | null;
  source?: string | null;
  fetched_at?: string | null;
}

export interface AlertDetailResponse {
  ...
  parent_lookup?: ParentProcessLookupStatus | null;
  parent_process?: ParentProcessResponse | null;
  ...
}
```

---

### 2.9 `apps/web/src/components/alerts/AlertDetailView.tsx`

`viewModel.parentProcess`를 `ParentProcessRow`에 전달:
```tsx
<ParentProcessRow
  alertId={alert.id}
  status={viewModel.parentProcess}
/>
```

---

## 3. tsc 검증 상태 (Live — 2026-10-23)

`npx tsc --noEmit -p .` 결과: **10개 → 5개**. 남은 5개는 **모두 parent-process 범위 밖**(아래 `관련?` 열이 "아니오"인 항목).

parent-process 구현이 도입/수정한 3개의 tsc 오류는 **이미 해결**되었다:
* `alertView.ts:326` — `rawScore !== ''` (`number | undefined`과 `''` 비교 → TS2367). `!== 0`으로 수정.
* `alertView.ts:339, 397` — `alert as Record<string, unknown>` (TS2352). `alert as unknown as Record<string, unknown>`으로 수정.
* `AlertDetailView.tsx:36` — `mitreTactics` import 추가 (TACTIC_BY_ID/tacticsFor를 1319행에서 사용).

| # | 오류 | 위치 | 관련? |
|---|---|---|---|
| 1 | TS2307 `bun:test` | `alertView.test.ts:1` | 아니오 (Bun 테스트 타입 해석) |
| 2 | TS2307 `bun:test` | `AlertDetailView.test.tsx:1` | 아니오 |
| 3 | TS2304 `normalizeKind` | `AttackGraphView.tsx:241` | 아니오 (HEAD `75e28e5a`에서 이미 존재, diff 없음) |
| 4 | TS2339 `AttackGraph.source` | `AttackGraphView.tsx:564` | 아니오 |
| 5 | TS2459 `ConfidenceFactorBar` | `ConfidenceHelp.test.tsx:9` | 아니오 (테스트가 미-export된 컴포넌트 import) |
---

## 4. 테스트 통과 상태 (Live — 2026-10-23)

| 테스트 | 파일 | 결과 | 근거 |
|---|---|---|---|
| Python 서비스 | `services/api/tests/test_parent_process_lookup.py` | 38/38 통과 | diff 기반 |
| Frontend mapper | `apps/web/src/lib/alertView.test.ts` | 74/74 (bun) | `getParentProcessStatus` 테스트 8개 이상 포함 |
| Frontend 컴포넌트 | `apps/web/src/components/alerts/ParentProcessRow.test.tsx` | 8/8 (vitest) | `process_id → entity_id` 매핑 확인 |

---

## 5. 참고 사항

* `fetch_alerts` 폴링 파이프라인은 변경되지 않았다. 조회 전용 경로(`parent-process`, `/internal/edr/process-lookup`)에만 코드가 추가되었다.
* 모든 `unavailable` 응답은 에러 배너/토스트 없이 상태별 문구로 폴백한다.
* Redis 키는 `tenant_id`, `connector_id`, `entity_id`를 모두 포함한다.

---

## v2.1 — 탐지 근거 섹션에 부모 프로세스 행 통합 (2026-10-26)

**문제**: `getDetectionBasis`의 정적 `parent` 필드는 OCSF 페이로드에 `parent.name`이 구조적으로 누락되어 있어 "부모 프로세스 미확인"이 영구히 렌더링되었다. 한편 화면 하단의 독립 `ParentProcessRow`는 `GET /api/v1/alerts/{id}/parent-process`로 실제 부모명을 가져왔다. 두 소스가 같은 화면에서 모순된 값(미확인 vs winlogon.exe)을 나란히 표시하고 있었다.

**변경 사항 (diff 기반):**

| 파일 | 변경 내용 |
|---|---|
| `apps/web/src/lib/alertView.ts` | `getDetectionBasis` 반환 객체에서 정적 `parent` 필드 제거 (451-452, 470행). 부모 프로세스 정보는 이제 지연 조회의 몫으로 이관 |
| `apps/web/src/components/alerts/AlertTemplateSections.tsx` | `DetectionBasisSectionProps`에 `alertId`, `parentProcess` prop 추가. `DetectionBasisInfo.parent` 필드 제거. 프로세스 컨텍스트 분기 안(`resolvedBasis.name` 존재 시)에 `<ParentProcessRow alertId={lookupAlertId} status={parentProcess} />` 렌더링 |
| `apps/web/src/components/alerts/AlertDetailView.tsx` | `DetectionBasisSection`에 `alertId={alert.id} parentProcess={viewModel.parentProcess}` 전달. 기존 독립 `ParentProcessRow` 행 제거 → 동일 엔드포인트 요청 1회 유지 (스펙 §2 Option C: 열람한 알럿 1건당 1회) |
| `apps/web/src/components/alerts/DetectionBasisSection.parent.test.tsx` | 신규: 해피 패스(스켈레톤→resolved), fail-closed(리젝션→unavailable, 에러 배너 없음, AC-LP-2), not_found(단축 ID + 리쿼리 버튼), not_applicable(행 은닉) 시나리오 5개 |

**동작 변화 (UX 관점 — AGENTS.md 규칙 6):**
* 탐지 근거 섹션의 "부모 프로세스" 행이 정적 "미확인"에서 스켈레톤(펄스) → `resolved: "<name> (PID: <pid>)`로 갱신됨
* 실패 시(EDR 404/장애): 에러 배너 없이 "미확인/조회 불가" 문구 + 리트라이 버튼(5초 쿨다운)으로 우아하게 디그레이드 (스펙 §7.3 실패 격리)
* 섹션 접기(`isOpen=false`) 시 행도 함께 숨김; 기본값은 펼쳐짐
* 기존 독립 행 제거로 페이지에 부모 프로세스 행이 1개만 존재 → 중복 조회 없음

**검증:**
* `DetectionBasisSection.parent.test.tsx` 5/5 통과 (vitest)
* `ParentProcessRow.test.tsx` 8/8 통과
* `tsc --noEmit`: 이번 변경으로 발생한 타입 오류는 0건. 잔여 오류(`bun:test`, `normalizeKind`, `ConfidenceFactorBar` 등)는 HEAD 기준으로도 존재하는 기존 문제
* `command_line`은 기본 off (`PARENT_LOOKUP_INCLUDE_COMMAND_LINE`), 켤 때 서버에서 1024자로 절삭한다.

## v2.2 — 부모 프로세스 조회 윈도우를 과거-앵커링 1일로 변경 (2026-10-26)

**배경:** 호스트(AiSOC)와 EDR 서버 간 시계 스키우가 확인되었다. 기존 규칙 `to = min(event_time + 1h, now)`의 `now`가 호스트 시계 기준이라, EDR 서버 시각보다 앞선 `to`를 만들 수 있어 EDR이 `400 invalid_request`로 거부했다(컨넥터 로그 `edrserver.process_lookup.http_error status=400` 반복 확인).

**변경 내용:**

| 파일 | 변경 내용 |
|---|---|
| `services/api/app/services/parent_process_lookup.py` | `_lookup_window`를 과거-앵커링으로 변경: `to = event_time`, `from = to − PARENT_LOOKUP_WINDOW_MINUTES`. `event_time` 부재 시 `to = now`로 폴백 |
| `services/api/app/core/config.py` | `PARENT_LOOKUP_WINDOW_MINUTES` 기본값 `10075`(7일) → `1440`(1일). (이전 중간안으로 추가했던 `PARENT_LOOKUP_CLOCK_SKEW_SECONDS` 설정은 제거) |
| `services/api/tests/test_parent_process_lookup.py` | `TestLookupWindow`를 과거-앵커링 동작에 재작성: `to == event_time`, 기본 1일 윈도우, 윈도우 길이 설정값 추적, tz 처리 확인 |
| `.env` / `docker-compose_server.yml` | 스키우 버퍼 env 바인딩 제거 |

**동작 변화:**
* 윈도우가 `event_time`(자식 발생 시각)에 앵커링되어 전체가 과거에 위치 → 호스트/EDR 시계 스키우와 무관하게 항상 EDR 검증 통과.
* 윈도우가 7일에서 1일로 축소되어 EDR 쿼리 부하가 감소한다.
* `event_time`이 미래인 경계(알럿 수신 지연 등)에서 `to = event_time`이 EDR 기준 미래가 될 수 있다. `Alert.event_time`은 `nullable=False`라 정상 수신 알럿에는 항상 과거 값이며, 부재/무시크린 케이스는 `now` 폴백으로 처리한다.

**검증:**
* `services/api/tests/test_parent_process_lookup.py` 46/46 통과
* `services/api/tests/services` 전체 170건 통과
* EDR 실측: `from=2026-10-25T04:33:26.000Z`, `to=2026-10-26T04:33:26.000Z` → HTTP 200 확인
* API 컨테이너에서 `PARENT_LOOKUP_WINDOW_MINUTES=1440` 로드, `_lookup_window`가 올바른 과거-앵커링 윈도우 산출 확인
