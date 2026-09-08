# Dashboard Metrics & Funnel Percentages Normalization Plan

## 1. 아키텍처 및 불일치 원인 분석 (Design First)

### 🚨 원인 1: Security Operations Center 카드 하드코딩
`apps/web/src/components/dashboard/DashboardView.tsx`의 454, 461번 라인에서 `Active Alerts`와 `Critical` 카드의 `trend` 속성에 `value: 0`을 하드코딩하여 넘기고 있습니다. 백엔드 `/api/v1/metrics/dashboard` API가 일일 증감률(Trend) 데이터를 제공하지 않았기 때문입니다.

### 🚨 원인 2: Operations Funnel의 100배 곱셈 버그 및 베이스라인 누락
*   **백엔드 (`metrics.py:702`)**: `((current - previous) / previous) * 100.0` ➡️ 이미 100이 곱해진 백분율(예: +50%일 때 `50.0`)을 반환.
*   **프론트엔드 (`FunnelKpiBar.tsx:72`)**: `const pct = delta * 100` ➡️ 백엔드에서 받은 50.0에 또 100을 곱함 ➡️ 화면에 **`+5000%`**로 표시되는 치명적 계산 버그 발생!
*   **베이스라인 부재 시 `0%` 왜곡**: 직전 주기 데이터(`previous`)가 0건일 때 `0.0`을 반환하여, 오늘 새로운 이벤트가 발생해도 `+0%`로 잘못 표시됨.

---

## 2. 해결 계획 (Root Cause Resolution)

### A. 백엔드 API 개선 (`services/api/app/api/v1/endpoints/metrics.py`)
1. **`_pct_delta` 수식 정규화 (Ratio 반환)**:
   ```python
   def _pct_delta(current: float | int, previous: float | int) -> float | None:
       if previous == 0:
           if current == 0:
               return 0.0
           return None  # 이전 비교군이 없으면 None (UI에서 '—' 표시)
       return round((current - previous) / previous, 4)  # 50% -> 0.5000
   ```
2. **`AlertMetrics`에 실시간 일일 트렌드 필드 추가**:
   * `total_trend: float | None = None`
   * `critical_trend: float | None = None`
   * `get_dashboard_metrics`에서 오늘(00시 이후) vs 어제(직전 24시간) 알람 수를 쿼리하여 실제 `_pct_delta`를 계산해 전달.

### B. 프론트엔드 인터페이스 및 렌더링 수정
1. **`apps/web/src/lib/api.ts`**:
   * `DashboardMetrics['alerts']`에 `total_trend?: number | null`, `critical_trend?: number | null` 추가.
   * `FunnelMetrics['deltas']`의 필드 타입을 `number | null`로 명시.
2. **`apps/web/src/components/dashboard/DashboardView.tsx`**:
   * 하드코딩된 `value: 0`을 제거하고 `metrics.alerts.total_trend`, `metrics.alerts.critical_trend`와 연동. 데이터가 없으면 트렌드 배지를 숨기거나 대시(`—`)로 렌더링.

### C. 단위 테스트 수정 (`services/api/tests/test_funnel_and_pipeline.py`)
* 변경된 `_pct_delta`의 비율(Ratio) 반환 규격(예: 100 -> 150일 때 50.0이 아니라 `0.50`)에 맞게 테스트 단언문 동기화.

---
위 설계안에 동의하시면 백엔드, 프론트엔드, 단위 테스트에 걸친 동기화 수정을 진행하겠습니다. 진행할까요?