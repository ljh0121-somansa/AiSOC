# Attack Chain Integrated AI Investigation Architecture

## 1. 개요 (Overview)
AiSOC 플랫폼의 **AI 심층 조사(Investigation with AI / Agent)** 파이프라인(`Recon` ➔ `Forensic` ➔ `Responder` ➔ `ReportWriter`)이 단일 Alert의 단편적 시야에서 벗어나, **Attack Chain(다단계 공격 체인 진행 흐름)**을 인지하고 전체 공격 캠페인 맥락에서 심층 분석 및 대응을 수행하도록 아키텍처를 고도화했습니다.

---

## 2. 아키텍처 설계 및 데이터 흐름 (Architecture & Data Flow)

```
[Case / Alert Trigger]
         │
         ▼
[1. ContextBundleBuilder (Layer 1)]
   - prefetch_context_bundle_dict:
       ├── Graph Neighbourhood (Neo4j)
       ├── Institutional Memory (과거 유사 사례)
       ├── UEBA Baseline (행위 이상 징후)
       ├── Threat Intel (CTI 평판)
       └── ⭐️ AttackChain (GET /api/v1/cases/{seed_alert_id}/attack-chain)
           [Auth Header: HMAC-SHA256 Service Token]
         │
         ▼
[2. Contract-safe Serialization (Layer 2)]
   - summary_for_llm / prompt_context_lines:
     === ATTACK CHAIN PROGRESSION (Multi-stage Campaign) ===
     * Step 1 [T1071.001]: C2 Beaconing Detected (Severity: high)
     * Step 2 [T1003.001]: LSASS Credential Dump (Severity: high)
     * Step 3 [T1021.002]: SMB Lateral Movement (Severity: high)
     * Step 4 [T1490/T1486]: Ransomware Impact (Severity: critical)
         │
         ▼
[3. Multi-Agent Investigation Pipeline (Layer 3)]
   - ReconAgent: 전체 체인의 호스트/IP/계정을 포괄하는 공격 표면(Attack Surface) 산출
   - ForensicAgent: 전/후 단계 인과관계를 반영한 완벽한 시계열 침해 타임라인 재구성
   - ResponderAgent: 공격 진행 단계를 파악하여 Kill-Chain 절단 최우선 대응 전략 수립
   - ReportWriterAgent: 경영진 및 기술팀용 다단계 침해 사고 종합 전개 스토리 자동 합성
```

---

## 3. 핵심 수정 내용 (Key Implementation)

### 3.1. ContextBundle 모델 및 빌더 확장 (`services/agents/app/context/bundle.py`)
1. **`AttackChainStep` 서브모델 정의**:
   - `alert_id`, `title`, `severity`, `mitre_techniques`, `shared_entities`, `distance`, `score` 필드 구조화.
2. **`ContextBundle` 필드 및 LLM 허용 키 추가**:
   - `attack_chain: list[AttackChainStep]` 필드 추가 및 `LLM_SAFE_KEYS`에 `attack_chain_summary`, `attack_chain_step_count` 등록.
3. **병렬 비동기 수집기 (`_fetch_attack_chain`) 및 서비스 인증 구현**:
   - `asyncio.gather` 팬아웃 루프에 `_fetch_attack_chain`을 추가하여, 조사 시작 시점에 `GET /api/v1/cases/{id}/attack-chain`을 비차단(Non-blocking) 비동기로 사전 로드.
   - Case ID 및 Seed Alert ID를 다중 탐색하도록 개선하고, 내부 마이크로서비스 간 호출 시 표준 HMAC-SHA256 JWT 내부 서비스 토큰 자동 생성 및 주입.
4. **프롬프트 안전 직렬화 (`prompt_context_lines`)**:
   - 공격 체인 진행 순서(Step 1 ➔ Step N)를 `=== ATTACK CHAIN PROGRESSION ===` 헤더 아래에 직관적으로 포맷팅하여 모든 하위 에이전트 프롬프트에 자동 주입.

### 3.2. 에이전트 시스템 프롬프트 Few-Shot 및 다단계 캠페인 지침 강화
1. **`ReconAgent` (`recon_agent.py`)**:
   - `Multi-Stage Attack Chain & Campaign Context` 업무 지침을 추가하여 단일 알림에 국한되지 않고 체인 전반의 IOC 및 공격 표면(Attack Surface)을 포괄 식별.
2. **`ForensicAgent` (`forensic_agent.py`)**:
   - Few-Shot 입출력 구조로 프롬프트를 전면 개편하여 비정형 독백 출력을 원천 억제하고, C2 통신부터 LSASS 덤프, SMB 횡적이동, 랜섬웨어 파일 암호화에 이르는 **6단계 전체 침해 타임라인(`attack_timeline`)과 근본 원인(`root_cause_hypothesis`)**을 완벽히 재구성.
3. **`ResponderAgent` & `ReportWriterAgent` (`responder_agent.py`, `report_writer_agent.py`)**:
   - Few-Shot 정형 템플릿과 공격 체인 연계 완화 지침을 적용하여 Kill-Chain 절단 최우선 대응책 및 종합 인시던트 보고서 자동 생성.

---

## 4. 실환경 문제 분석 및 해결 내역 (Troubleshooting & Resolution)

### 4.1. 웹 콘솔 조사 시 Attack Chain 누락 문제 해결
* **현상**: Case 상세 화면에서 "Investigate with agent" 버튼 실행 시 Attack Chain이 Recon 및 Forensic 결과에 반영되지 않고 단일 Alert 수준으로만 분석되는 현상 발생.
* **원인**:
  1. `ContextBundleBuilder`의 내부 API 호출 시 인증 토큰 누락으로 `401 Unauthorized`가 발생하여 체인 데이터 수집이 스킵됨.
  2. `_fetch_attack_chain` 호출 시 전달되는 ID가 Case ID와 Alert ID 간에 불일치하여 404가 반환됨.
  3. `ForensicAgent` 프롬프트에 Few-Shot 예시가 없어 Qwen 모델이 긴 내적 독백을 출력하다 토큰 한도(4096)에 걸려 JSON 출력이 누락됨.
* **조치**:
  1. `bundle.py`에 내부 서비스 전용 JWT 인증 헤더 생성 및 Case ID/Alert ID 다중 탐색 로직 추가.
  2. `forensic_agent.py`에 직관적인 Few-Shot 템플릿을 적용하고 최대 토큰 상한을 8192로 확장.
  3. `safe_parse_agent_json`의 JSON 추출 범위를 양방향 인덱스(`find('{')` ~ `rfind('}')`)로 고도화.

---

## 5. 최종 검증 결과 (E2E Verification)

실제 Case(`INC-7C08D8A3`)에 대해 `Investigate with agent` 전체 파이프라인 E2E 검증 완료:

```
[ReconAgent]
  * Recon Summary: 현재 경보는 단일 C2가 아니라 C2, LSASS 덤프, VSS 삭제, SMB 횡적이동, 파일 암호화까지 이어진 다단계 랜섬웨어 캠페인으로 판단된다. 10.203.255.230, demo, DESKTOP-8SEUPMF를 즉시 격리하고 자격증명 탈취 및 추가 확산 여부를 검증해야 한다.
  * Threat Actor: LockBit 3.0

[ForensicAgent]
  * Forensic Summary: C2 비콘, demo LSASS 덤프, demo VSS 삭제, SMB 횡적이동, DESKTOP-8SEUPMF VSS 삭제 및 파일 암호화로 이어진 랜섬웨어 캠페인이 재구성됨.
  * Root Cause: 10.203.255.230 기반 C2 침투 후 demo에서 LSASS 자격증명 탈취와 VSS 삭제가 발생하고, 탈취된 자격증명을 이용해 SMB로 DESKTOP-8SEUPMF로 횡적이동한 뒤 VSS 삭제 및 파일 암호화까지 진행한 다단계 랜섬웨어 공격으로 추정됨.
  * Forensic Timeline: 6개 전체 침해 단계(C2 Beaconing -> LSASS Dump -> VSS Deletion -> SMB Movement -> Ransomware) 완벽 복원.

[ReportWriterAgent]
  * Final Incident Report (Markdown): 3,496자 분량의 수석 분석관급 다단계 침해 분석 보고서 자동 합성 완료 (status=completed).
```

---

## 6. 기대 효과 (Enterprise Business Value)

* **Incident-Centric 분석 완성**: 단일 Alert 기반의 파편화된 대응을 종식하고, 공격 캠페인 전체를 하나의 일관된 인시던트로 포괄 추론.
* **환각(Hallucination) 방지**: 정밀한 다단계 공격 체인 지형도를 바탕으로 에이전트가 완벽히 근거(Grounding) 있는 침해 타임라인과 완화 대책을 수립.
* **엔터프라이즈 SOC 콘솔 일관성**: 웹 화면의 Attack Chain 시각화 데이터와 AI 에이전트의 조사 보고서가 100% 일치하는 데이터 정합성 달성.
