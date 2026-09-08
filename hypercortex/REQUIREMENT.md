[PROBLEM]
- 1. Security Operations Center (DashboardView.tsx): The `Active Alerts` and `Critical` metric cards display hardcoded `+0% vs yesterday` (`trend={{ value: 0, label: 'vs yesterday' }}`).
- 2. Operations Funnel (FunnelKpiBar.tsx & metrics.py):
  - Double 100x Multiplication Bug: Backend `_pct_delta` returns percentage (e.g., 50.0 for 50%), while frontend `formatDelta` multiplies it by 100 again (`delta * 100`), turning a 50% delta into 5000%!
  - Misleading `+0%` when `previous == 0`: When there are no prior events in the previous window (`previous == 0`), `_pct_delta` returns `0.0`, resulting in a false `+0%` display instead of indicating "no baseline" (`—`).

[REQUIREMENT]
- Design and execute a fundamental fix for both issues:
  1. Add real 24h trend calculation in `GET /api/v1/metrics/dashboard` for `total` and `critical` alerts, update TypeScript types in `apps/web/src/lib/api.ts`, and replace hardcoded trends in `DashboardView.tsx`.
  2. Normalize `_pct_delta` in `metrics.py` to return fractional ratios (`round((current - previous) / previous, 4)`) or `None` when `previous == 0` and `current > 0`, aligning with the frontend contract (`FunnelMetrics.deltas`).
  3. Update unit tests in `services/api/tests/test_funnel_and_pipeline.py` to match the corrected contract.

[CONSTRAINTS]
- Design First, Code Later.
- Holistic Impact Verification: Ensure backend, frontend, and tests are completely synchronized.
- Root Cause Resolution.

[REVIEW_LOG]
- Reviewer: Confirmed both root causes. 
  1. `trend={{ value: 0 }}` is literally hardcoded on lines 454 and 461 of `DashboardView.tsx`.
  2. `metrics.py:702` returns `((current - previous) / previous) * 100.0`, whereas `FunnelKpiBar.tsx:72` executes `delta * 100`, compounding into a 100x multiplication error.
  Aligning the contract to standard ratio (`0.5` = 50%) and returning dynamic trends resolves all inaccurate percentage displays.