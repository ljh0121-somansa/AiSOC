제목: Detection Confidence 부표시 부호 정정
원인: `AlertDetailView`의 `Detection Confidence` 계수 라벨에 고정 `+`가 붙어 부정 기여도가 `+-0.30`처럼 겹쳐 표시되던 문제를 수정하기 위해
작업 내역:
- `apps/web/src/components/alerts/AlertDetailView.tsx`의 `ConfidenceFactorBar` 하드 코딩된 `+` 부호를 `factor.contribution`의 부호에 동기화된 식으로 수정
- `tsc --noEmit` typecheck 및 부호 거동(`+0.60`, `-0.30`, `0.00`) 검증 후 COMMIT(`50bc604a`)
