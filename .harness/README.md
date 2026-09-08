# Harness-Dev: 통합 AI 코딩 어시스턴트 하네스

AI 어시스턴트를 전문 엔지니어 팀(아키텍트, 개발자, 리뷰어, SDET, 프론트엔드/디자이너)으로 변환하도록 설계된 엘리트 SDLC 방법론 및 페르소나 기반 하네스입니다.

> **중요**: 이 하네스는 **pi** 환경에 최적화되어 설계되었습니다. pi 기동 시 `AGENTS.md` 파일을 자동으로 로드하므로 별도의 추가 설정 없이 원활하게 작동합니다.

## 핵심 개념

### 1. 5가지 페르소나
이 하네스는 AI가 상황에 따라 엔지니어링 역할을 전환할 수 있도록 다섯 가지 전문화된 정체성을 정의합니다:
- **시스템 아키텍트 (System Architect)**: 전역 시스템 비전, 객체 지향 설계(OOD) 및 아키텍처 트레이드오프 분석.
- **소프트웨어 개발자 (Software Developer)**: 정밀한 구현, 메모리 안전 및 동시성 코드 작성.
- **리뷰어 (Reviewer)**: 타협하지 않는 품질 감사, 보안 검증 및 아키텍처 정렬 확인.
- **테스트 엔지니어 (SDET)**: 극한의 엣지 케이스 검증 및 격리된 자동화 테스트 구축.
- **프론트엔드 엔지니어 및 UX/UI 디자이너 (Frontend Engineer & UX/UI Designer)**: 사용자 경험 설계, 웹 접근성(a11y) 및 i18n 전담 구현.

### 2. 하이퍼코텍스(Hypercortex) 지식 시스템
`hypercortex/` 디렉토리는 AI의 영구 메모리이자 지식 그래프 역할을 합니다. 요구 사항, 설계, 사양, 개발 패턴 및 품질 기록 간의 추적성을 유지합니다.

### 3. 지속적 검증 워크플로우 (Shift-Left)
6단계 SDLC 프로세스는 모든 결정이 구현 전에 검증되도록 보장합니다:
- **Phase 1-3 (분석/설계/명세)**: 리뷰어 페르소나가 결과물을 교차 검토하는 의무적인 [검증] 루프를 포함합니다.
- **Phase 4 (개발)**: 코드를 확정하기 전 의무적인 [자체 리뷰] 및 기본적인 기능 검증을 수행합니다.
- **Phase 5 (감사)**: 코드 보안 취약점, 성능 병목 구간, 설계 정렬 상태를 심층적으로 검증 및 분석합니다.
- **Phase 6 (테스트)**: 시스템 한계를 입증하기 위한 격리된 테스트를 구축합니다.

---

## 시작하기

이 하네스를 프로젝트에 적용하는 방법은 두 가지가 있습니다:
1. **Git Submodule 방식 (권장)**: 협업 환경에서 버전 핀 기능(특정 커밋 고정)을 지원하고 관리가 매우 직관적입니다.
2. **Git Sparse-Checkout 방식**: 다른 리소스를 제외하고 오직 핵심 `harness/` 디렉토리만 가볍게 가져옵니다.

---

### 귀찮으면 다음과 같이

```bash
curl -k https://gitlab.somansa.com/crowmania/harness-dev/-/raw/main/setup.sh | bash -
```

---

### 방법 A: Git Submodule 방식 (권장 ⭐)
팀 전체가 동일한 하네스 버전을 추적하고 유지할 수 있는 가장 표준적이고 안전한 방법입니다.

#### 1단계: 서브모듈 추가
프로젝트 루트에서 다음 명령어를 실행하여 하네스를 `.harness` 디렉토리로 추가합니다.
```bash
git submodule add https://gitlab.somansa.com/crowmania/harness-dev.git .harness
```

> 💡 **업데이트 방법**: 하네스의 최신 변경 사항을 동기화하고 상위 레포지토리에 커밋하려면 다음 명령을 사용합니다:
> ```bash
> git submodule update --remote --merge
> ```

---

### 방법 B: Git Sparse-Checkout 방식 (대안)
`harness-ko/` 등 불필요한 파일들을 제외하고 핵심 `harness/` 디렉토리만 골라서 가져오고 싶을 때 사용합니다.

#### 1단계: Sparse-Checkout으로 초기화
프로젝트 루트에서 다음 명령을 순서대로 실행합니다.
```bash
# 1. 하네스 레포지토리를 .harness 디렉토리에 복제 (체크아웃 제외)
git clone --no-checkout https://gitlab.somansa.com/crowmania/harness-dev.git .harness

# 2. .harness 디렉토리로 이동
cd .harness

# 3. Sparse-checkout 활성화 및 harness 폴더만 지정
git sparse-checkout init --cone
git sparse-checkout set harness

# 4. 파일 체크아웃
git checkout main

# 5. 원래 프로젝트 루트로 복귀
cd ..
```

> 💡 **업데이트 방법**: 향후 하네스가 업데이트되면, `.harness` 폴더 안으로 이동하여 풀을 받아옵니다:
> ```bash
> cd .harness && git pull origin main && cd ..
> ```

---

### 2단계: 디렉토리 설정
`hypercortex/` 및 `workspace/` 디렉토리를 생성합니다.
- `hypercortex/`: 방법론 문서(REQUIREMENT, DESIGN 등)를 저장합니다.
- `workspace/`: 모든 기술적 구현(코드, 자산, 테스트)은 프로젝트 루트 오염을 방지하기 위해 반드시 이 안에 위치해야 합니다.

### 3단계: 로컬 익스텐션 등록 (Harness Prompt Extension)
하네스의 가이드라인과 페르소나 설정(`PERSONA.md` 및 `WORKFLOW.md`)을 시스템 프롬프트에 자동으로 주입해 주는 프로젝트 로컬 익스텐션을 등록합니다.

pi의 `settings.json` 기능을 활용하면, 복사나 심볼릭 링크 생성 없이 안전하게 하네스 익스텐션을 로드할 수 있습니다. 이 방식은 Windows, Mac, Linux 전 환경에서 완벽히 호환되며 향후 하네스가 업데이트되어도 자동으로 최신 코드가 적용됩니다.

1. `.pi` 폴더를 생성하고 그 안에 `settings.json` 파일을 생성하거나 업데이트합니다.
```bash
mkdir -p .pi
```

2. `.pi/settings.json` 파일에 아래 내용을 작성합니다. (이미 설정이 존재한다면 `extensions` 배열에 경로를 추가합니다.)
```json
{
  "extensions": [
    "../.harness/harness/extensions/harness-prompts.ts"
  ]
}
```
> 💡 **경로 해석 기준**: `.pi/settings.json`에 정의된 상대 경로는 `.pi` 폴더를 기준으로 해석되므로, `../.harness/...` 경로가 프로젝트 루트 밑의 `.harness` 폴더를 정확히 가리키게 됩니다.

이제 pi를 **종료 후 재실행**(또는 `/reload` 입력)하면 익스텐션이 자동으로 로드되고 하네스 규칙이 시스템 프롬프트에 실시간으로 적용됩니다.

---

## 전역 실행 규칙
- **오염 제로 (Zero-Contamination)**: 기술적 구현은 절대로 프로젝트 루트에서 수행되어서는 안 됩니다.
- **지식 추적성 (Traceability)**: 모든 결정은 마크다운 상호 참조를 통해 하이퍼코텍스의 기원으로 연결되어야 합니다.
- **국제화 (i18n) 의무화**: 모든 UI 구성 요소는 시작부터 다국어 지원이 가능하도록 설계되어야 합니다.
- **검증 우선 (Validation-First)**: 오류는 발생한 단계 내에서 즉시 수정되어야 합니다.
