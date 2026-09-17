# Detection Hub — 작업 완료 기록 (2026-09-10)

## 핵심 목표 (해결됨)
`detections/<category>/*.yaml` (869개 native 규칙)이 Web 콘솔(`/detection`)에 노출되지 않던 문제 해결.

## 원인 분석
1. **볼륨 마운트 없음** — `docker-compose_server.yml`의 `api` 서비스에 `detections/` 볼륨이 빠져 있어 부팅 시 boot hook이 corpus를 못 찾음 → native 시드 실패.
2. **시드 버그** — insert 경로에서 `name`을 세하지 않아 `NotNullViolation` (`detection_rules.name` NOT NULL).
3. **legacy-cleanup scope 너넉** — `rule_language='sigma' AND name IN (전통 이름)`이 brute-force/ransomware **native** 행도 삭제 → 매번 삭제→재삽입, 토글 상태 소실.

## 작업 내용

### 1. 볼륨 마운트 추가
`docker-compose_server.yml` api 서비스:
```yaml
volumes:
  - ./services/api/app:/app/app
  - ./detections:/app/detections:ro
```
(서버 compose는 repo 루트에 위치 → `./detections`. dev compose는 `infra/compose/`라 `../../detections`.)

### 2. 시드 버그 수정
`services/api/app/services/detections/native_ruleset.py`: `new_rule = DetectionRule(...)` 생성자에 `name=name` 추가 (update 경로에서는 이미 할당됨).

### 3. legacy-cleanup scope 한정
`DELETE FROM detection_rules WHERE rule_type <> 'native' AND rule_language='sigma' AND name IN (...)`
- native 행이 전통 이름과 같아도 삭제되지 않도록 한정.
- 재시드 시 churn 방지 + toggle-off 상태 보존.

### 4. 데이터 정합성 — 중복 이름 정리
4개 파일이 2개의 같은 규칙 이름을 가졌음 (내용은 진짜 다른 별도 규칙):
| id | 변경된 이름 |
|----|----|
| det-cloud-126 | Azure Key Vault Purge Protection Disabled (KeyVault Write Event) |
| det-cloud-212 | Azure Key Vault Purge Protection Disabled (Activity Log) |
| det-cloud-192 | M365 Exchange Transport Rule Redirects Mail Externally (Redirect + BCC) |
| det-cloud-221 | M365 Exchange Transport Rule Redirects Mail Externally (External Redirect Action) |

id는 불변 → uuid5 유지 → 시드 재적용.

## 검증 결과
- **DB**: `total 870`, `native 869`, `custom 1` (fsdfs — pre-existing, native 아님)
- **HTTP E2E** (admin 로그인 → `GET /api/v1/detection/rules`): `869` isBuiltin 반환, body는 원본 YAML 그대로
- **필드 정합**: `id, name, body, isBuiltin, enabled, severity, tags, mitre` 등 모두 present
- **idempotent**: `rows_read: 869, rows_inserted: 0, rows_updated: 869, errors: 0`
- **이름 고유**: `869 unique names, 0 duplicates`
- **상태 보존**: `AWS CloudFront Origin Changed Mid-Service` (`inactive`로 둔 규칙)이 재시드 후에도 `inactive` 유지

## Fusion 경계 (보고용)
native 규칙은 콘솔에서 토글만 가능. **실제 fusion 파이프라인에는 영향 없음** (`services/fusion/app/data/detection_ruleset.json`이 관리). 토글해도 live 감지엔 변화 없음 — 버그가 아니라 설계상 의도.

## 미완성 항목
전혀 없음. 계획의 모든 Step(1-5) 검증 완료.

## 참고
`docker compose -f docker-compose_server.yml up -d api` 재기동시 boot hook이 이 볼륨을 발견해 native 시드를 자동 실행합니다.
