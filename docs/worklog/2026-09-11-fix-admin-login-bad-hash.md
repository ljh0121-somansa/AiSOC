# [업무일지] admin@somansa.com 로그인 실패 (Email or password incorrect) 수정

**일자**: 2026년 9월 11일
**작업자**: AiSOC 개발팀
**상태**: 완료 (실제 컨테이너 API E2E 로그인 검증 통과)

---

## 1. 업무 개요 및 배경
* **이슈 현상**:
  - 관리자(`admin@somansa.com`, pw: `admin`)로 로그인 시도 시 브라우저에서 **`Email or password incorrect`** 메시지가 출력되며 인증 실패.
* **근본 원인**:
  - 로그인 API(`/api/v1/auth/login`), 패스워드 해싱/검증(`services/api/app/core/security.py` bcrypt), JWT 발급 로직은 모두 **정상**.
  - 문제는 **실제 PostgreSQL DB에 저장된 admin의 `hashed_password`**가 마이그레이션 파일에 기재된 값과 **일치하지 않았기 때문**.
  - 마이그레이션(`001_init.sql:215`)의 해시는 `admin`과 일치했으나, DB 행은 그보다 **일찍 wrong bcrypt 값으로 시드**되어 있었고, `ON CONFLICT (email) DO NOTHING`으로 인해 마이그레이션이 이 bad hash를 **덮어쓰지 못해(sticky)** 고정됨.

---

## 2. 진단 결과 (근본 원인)

| 항목 | 값 | `admin` 검증 |
|---|---|---|
| 마이그레이션 파일 해시 (`001_init.sql:215`) | `$2b$12$b4lDfeFRZFPAoW.0ccPl..kxZarIgm4NrwFvXjJS65phRFv46nILK` | ✅ 일치 |
| **실제 DB admin hash** | `$2b$12$PN0adzCIHBs4fp4KFf1VmOiJQMuM7VeL7v0FNp.m5HLriWblCr/Y6` | ❌ 일치 안 함 |

* DB 조회 (`aisoc-dev1-postgres`): admin 행 존재, `is_active=t`, `is_verified=t`, `role=platform_admin` — **계정 자체는 활성**, 오직 패스워드 해싱 값만 부正确.
* bcrypt로 `admin`을 72종 plaintext(`admin, Admin, ADMIN, password, admin123, somansa, changeme` 등)로 확인 — **live DB hash는 일치하는 plaintext가 없음**.

---

## 3. 작업 내용

### 3.1. live DB corrective UPDATE
* admin의 `hashed_password`를 `admin`과 일치하는 bcrypt hash로 덮어 씌움:
  ```sql
  UPDATE users
  SET hashed_password = '$2b$12$0123456789abcdefABCDE.bBIgXZPLJTb51FwbICORiXFmEfFvjkW'
  WHERE email = 'admin@somansa.com';
  ```
  * 실행 결과: `UPDATE 1` (1행 반영).
  * 생성된 hash 결정적으로 `admin`을 검증하도록 bcrypt로 re-validate 확인.

---

## 4. 테스트 및 검증 결과

### 4.1. bcrypt 검증
* 수정 후 live DB hash를 bcrypt로 검증 → `admin matches: True`.

### 4.2. 실제 컨테이너 API E2E 로그인
* 호출: `POST http://127.0.0.1:18000/api/v1/auth/login`
  ```json
  { "email": "admin@somansa.com", "password": "admin" }
  ```
* 결과:
  - **HTTP 200** 반환.
  - `access_token` (JWT, exp 86400s), `refresh_token`, `token_type: bearer` 정상 발급.
  - JWT payload 디코딩:
    ```json
    {
      "sub": "00000000-0000-0000-0000-000000000002",
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "role": "platform_admin",
      "email": "admin@somansa.com",
      "type": "access"
    }
    ```
* **결론**: `admin@somansa.com` / `admin`으로 성공적 로그인. 브라우저에서 `Email or password incorrect` 현상 재현되지 않음.

---

## 5. 향후 참고 사항
* 마이그레이션 파일(`001_init.sql`)은 이미 `admin`과 일치하는 해시를 올바르게 가지고 있으므로 **신규 DB 생성 시 재발 없음**.
* 기존 DB(이미 bad hash로 시드된 경우)만 corrective UPDATE가 필요 — 본 작업으로 `aisoc-dev1-postgres`는 해결됨.
* 다른 환경(예: demo, airgap)에서도 동일한 bad-hash로 시드된 admin이 존재할 수 있으므로, DB 마이그레이션 스크립트를 통해 동일 UPDATE를 재사용하는 것을 권장.
