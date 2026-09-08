# ChatML Role Separation Architecture for Multi-Model Support

## 1. 개요 (Overview)
Qwen(ChatML), DeepSeek, OpenAI(GPT-4o), Anthropic(Claude) 등 다양한 상용 및 오픈소스 LLM 아키텍처에 맞춰, **`system`과 `user` 메시지 역할을 명확히 분리(Role Separation)**하고 프롬프트 과적합을 해소한 표준 프롬프트 아키텍처를 구축했습니다.

---

## 2. 역할 분담 원칙 (Role Separation Principles)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ [role: "system"]  -> 불변의 헌법 (Persona, Rules, JSON Schema, Language)    │
│  • 페르소나 및 핵심 임무 선언                                              │
│  • 절대적 출력 제약 (오직 유효한 단 하나의 JSON 출력 등)                   │
│  • 언어 규칙 (분석/요약 필드는 한국어, 키/기법ID는 영어)                    │
│  • 범용 Response JSON Schema 정의                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ [role: "user"]    -> 가변의 입력 데이터 (Alert, AttackChain, Context)       │
│  • Alert 요약 & 원시 구조체                                                 │
│  • Recon 정찰 결과 및 MITRE 기법                                            │
│  • === ATTACK CHAIN PROGRESSION (Multi-stage Campaign) ===                  │
│  • ContextBundle (엔티티 그래프, UEBA, CTI 평판)                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 프롬프트 변경 및 제거/정리 항목 (Changes & Removals)

### 3.1. 제거/정리된 항목 (Removed Items)
1. **`User` 메시지 내 `_SYSTEM_PROMPT` 중복 삽입 제거**:
   - 기존에 프롬프트 지침이 `system`과 `user` 양쪽에 2중 복사되어 프롬프트 길이가 2배로 비대해지던 결함을 완전히 제거.
2. **장황한 다국어 산문체 금지 지침 제거**:
   - `"Write values of rationale in Korean, keep commands in English..."`와 같이 모델의 언어 고민을 유발하던 서술형 분기 지침을 스키마 태그(`<사고 근본 원인 in Korean>`) 방식으로 간결화.
3. **특정 시나리오 하드코딩 예시 제거**:
   - 스키마 내에 고정되어 있던 특정 호스트명/계정명(`demo`, `hy`, `somansa`, `DESKTOP-8SEUPMF`)을 범용 플레이스홀더(`<affected_hostname_or_ip>`)로 전면 개편.

### 3.2. 유지 및 강화된 항목 (Retained & Strengthened)
1. **핵심 3대 제약조건 유지**:
   - (1) 유효한 단일 JSON만 출력, (2) 요약/설명 필드는 전문 한국어 작성, (3) JSON 키/기법 ID는 영문 유지.
2. **`confidence` 필드 스키마 고정**:
   - `forensic_agent` 등에 `confidence: <float 0.0-1.0>`를 명시하여 신뢰도 0% 누락 방지.
3. **Attack Chain 다단계 캠페인 맥락 주입**:
   - `user` 입력 메시지에 다단계 공격 체인 진행 흐름(`ATTACK CHAIN PROGRESSION`)이 온전히 전달되도록 유지.

---

## 4. 검증 결과 (Verification)

1. **독립 단위 테스트 (Isolated Test)**:
   - `ReconAgent`: 28초 만에 정찰 요약 및 침해 지표 도출 완료.
   - `ForensicAgent`: 12초 만에 포렌식 타임라인, 근본 원인, 신뢰도(65~90%+) 정상 산출.
   - `ResponderAgent`: 56초 만에 P1/P2 대응 계획 및 실행 명령어 정상 산출.
2. **회귀 테스트**:
   - 16종 전체 단위 테스트 100% 통과 (Pass).
