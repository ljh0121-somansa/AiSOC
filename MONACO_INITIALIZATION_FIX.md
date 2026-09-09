# Monaco 에디터 로컬 번들 로딩 및 무한 Loading 문제 해결 보고서

- **작성 일자**: 2026-09-09
- **대상 URL**: `http://10.216.0.155/detection/f0012f18-da73-4401-ad09-60e0b314545a` (및 탐지/헌팅 등 Monaco Editor 사용 페이지)

---

## 1. 개요 (Summary)

- **제목**: Monaco 에디터 오프라인 로컬 번들 로딩 실패 및 무한 Loading 현상 해결
- **증상**:
  - `/detection/[id]` 페이지 접속 시 화면 중앙에 `<div style="display: flex; height: 100%; width: 100%; justify-content: center; align-items: center;">Loading...</div>`가 계속 표시되며 에디터가 로드되지 않음.
  - 브라우저 개발자 도구(F12) 콘솔에 `Monaco initialization: error: Event` 에러 발생.

---

## 2. 문제 근본 원인 (Root Cause Analysis)

### 2.1. Next.js App Router (RSC) 사이드 이펙트 모듈 누락
- 오프라인/폐쇄망 환경 지원을 위해 로컬 정적 에셋 경로(`${window.location.origin}/monaco-editor/0.55.1/vs`)를 `@monaco-editor/loader`에 등록하는 `apps/web/src/lib/monaco-env.ts`가 이미 프로젝트에 준비되어 있었습니다.
- 그러나 이 모듈이 서버 컴포넌트인 `apps/web/src/app/(app)/layout.tsx`에만 `import '@/lib/monaco-env';` 형태로 포함되어 있었습니다.
- Next.js App Router는 서버 컴포넌트 내부에서 JSX 컴포넌트로 렌더링되지 않는 클라이언트 모듈(`'use client'` 파일)의 부수효과(side-effects)를 클라이언트 JS 번들 엔트리포인트에 등록하지 않고 빌드 최적화 과정에서 제거합니다.
- 이에 따라 클라이언트 브라우저 환경에서는 `loader.config({ paths: { vs: ... } })`가 전혀 호출되지 않았습니다.

### 2.2. 클라이언트의 외부 CDN(`cdn.jsdelivr.net`) Fallback 시도 및 통신 단절
- `@monaco-editor/loader`는 `loader.config`가 호출되지 않으면 기본 하드코딩된 원격 CDN 경로(`https://cdn.jsdelivr.net/npm/monaco-editor@0.55.1/min/vs/loader.js`)로 동적 `<script>` 태그를 삽입합니다.
- 외부 인터넷/CDN 연결이 차단된 사내망/로컬 서버 환경(`10.216.0.155`)에서 해당 CDN 스크립트 요청이 실패하여 브라우저 DOM `onerror` 이벤트(`Event` 객체)가 발생했습니다.
- `@monaco-editor/react`가 해당 에러를 catch하여 `console.error("Monaco initialization: error:", f)`를 출력하고, 에디터 마운트 완료 상태(`isEditorReady: true`)로 전이되지 못해 스켈레톤 로딩(`Loading...`) div에 갇혀 있었습니다.

---

## 3. 작업 내역 (Implementation Details)

외부 CDN 의존을 완전히 배제하고 서버 자체 서빙(`/monaco-editor/0.55.1/vs`) 기반의 완전한 오프라인/에어갭(Air-gap) 환경으로 수정했습니다.

### 3.1. `apps/web/src/lib/monaco-env.ts` 개선
- SSR 렌더링 시점 안전성 보장(`typeof window === 'undefined'`) 추가.
- 다중 호출 시 중복 설정을 방지하는 멱등성 가드(`configured`) 적용.
- 어디서든 명시적으로 즉시 호출할 수 있는 `initMonacoEnv()` 함수 export.

```typescript
'use client';

import loader from '@monaco-editor/loader';

let configured = false;

export function initMonacoEnv() {
  if (typeof window === 'undefined' || configured) return;
  loader.config({
    paths: {
      vs: `${window.location.origin}/monaco-editor/0.55.1/vs`,
    },
  });
  configured = true;
}

if (typeof window !== 'undefined') {
  initMonacoEnv();
}
```

### 3.2. 클라이언트 컴포넌트 계층에 초기화 보장 적용
- **`apps/web/src/components/layout/AppShell.tsx`**:
  - 최상위 클라이언트 래퍼에 `import '@/lib/monaco-env';`를 선언하여 모든 인증 앱 화면 마운트 시 로컬 경로가 설정되도록 보장.
- **`apps/web/src/components/detections/RuleEditor.tsx`**:
  - `MonacoEditor` 동적 import 직전에 `initMonacoEnv()`가 반드시 선행 호출되도록 수정.
- **`apps/web/src/components/hunt/HuntView.tsx`**:
  - 헌팅 에디터 로드 전 `initMonacoEnv()` 호출 적용.
- **`apps/web/src/app/(app)/settings/business-context/BusinessContextSettings.tsx`**:
  - 비즈니스 컨텍스트 규칙 YAML 에디터 로드 전 `initMonacoEnv()` 호출 적용.
- **`apps/web/src/app/(app)/layout.tsx`**:
  - 동작하지 않던 서버 컴포넌트 내 불필요한 import 제거.

### 3.3. 컨테이너 빌드 및 재배포
- `docker compose -f docker-compose_server.yml build web`
- `docker compose -f docker-compose_server.yml up -d web`

---

## 4. 검증 결과 (Verification)

실제 브라우저 런타임에서 `http://10.216.0.155/detection/f0012f18-da73-4401-ad09-60e0b314545a` 접속 검증:

1. **외부 CDN 호출 0건 (`cdnScriptsCount: 0`)**:
   - `cdn.jsdelivr.net`으로의 모든 네트워크 호출이 완전히 사라짐.
2. **로컬 에셋 정상 로드 (`localMonacoScriptsCount: 13`)**:
   - `loader.js`, `editor.main.js`, `editor.api-CalNCsUg.js` 등 Monaco 핵심 스크립트 13개가 서버(`http://10.216.0.155/monaco-editor/0.55.1/vs/`)에서 로컬로 서빙됨.
3. **콘솔 에러 해소**:
   - `Monaco initialization: error: Event` 에러 완전 제거.
4. **UI 정상 렌더링 확인**:
   - `Loading...` div 소멸 (`hasLoadingDiv: false`).
   - `.monaco-editor` 및 `.view-lines`가 정상 마운트되어 탐지 룰(Sigma YAML)의 구문 강조(Syntax Highlighting), 라인 번호(1~27줄), 커서 편집 기능이 모두 정상 동작함을 확인.
