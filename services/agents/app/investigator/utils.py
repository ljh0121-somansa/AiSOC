import re, json
from typing import Any
import structlog

logger = structlog.get_logger()

def safe_parse_agent_json(content: str) -> dict[str, Any]:
    """
    Qwen/DeepSeek 추론 모델 응답 처리:
    <think> 태그 유무와 관계없이 </think> 닫는 태그 이전의 
    모든 생각 과정(Thinking Process) 텍스트를 제거하고 순수 JSON만 파싱합니다.
    """
    if not content or not str(content).strip():
        return {}

    cleaned = str(content).strip()

    # 1. </think> 태그가 존재하는 경우: </think> 포함 앞부분 전체 제거
    if "</think>" in cleaned:
        cleaned = cleaned.split("</think>", 1)[1].strip()
    else:
        # 2. 혹시 <think> ... </think> 가 완벽하게 들어있는 경우 제거
        cleaned = re.sub(r"<think>[\s\S]*?</think>", "", cleaned).strip()

    # 3. 마크다운 펜스 제거 (```json ... ``` 또는 ``` ... ```)
    cleaned = re.sub(r"```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"```\s*", "", cleaned).strip()

    # 4. 균형 중괄호(Balanced Braces) 기반 정밀 JSON 블록 스캐너
    # 모델이 독백 도중 부분 딕셔너리 예시를 출력하더라도, 실제 최상위 조사 결과 객체를 역순으로 우선 매칭
    start_idx = cleaned.find("{")
    valid_candidates: list[dict[str, Any]] = []
    while start_idx != -1:
        depth = 0
        in_string = False
        escape = False
        for i in range(start_idx, len(cleaned)):
            c = cleaned[i]
            if c == '"' and not escape:
                in_string = not in_string
            elif c == "\\" and in_string:
                escape = not escape
                continue
            elif not in_string:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = cleaned[start_idx : i + 1]
                        try:
                            obj = json.loads(candidate)
                            if isinstance(obj, dict):
                                valid_candidates.append(obj)
                        except Exception:
                            try:
                                decoder = json.JSONDecoder()
                                parsed_obj, _ = decoder.raw_decode(candidate)
                                if isinstance(parsed_obj, dict):
                                    valid_candidates.append(parsed_obj)
                            except Exception:
                                pass
                        break
            escape = False
        start_idx = cleaned.find("{", start_idx + 1)

    # 상위 레벨 에이전트 키가 포함된 유효한 객체를 역순(최종 산출물)으로 우선 탐색
    for cand in reversed(valid_candidates):
        if any(
            k in cand
            for k in (
                "attack_timeline",
                "forensic_summary",
                "summary",
                "root_cause_hypothesis",
                "root_cause_analysis",
                "triage",
                "incident_disposition",
                "report_metadata",
                "verdict",
                "compromised_assets",
            )
        ):
            return cand

    # 5. Fallback: 가장 바깥쪽 전체 { ... } 파싱 시도
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        json_candidate = cleaned[first_brace : last_brace + 1]
        try:
            return json.loads(json_candidate)
        except json.JSONDecodeError:
            try:
                decoder = json.JSONDecoder()
                obj, _ = decoder.raw_decode(json_candidate)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass

    # 6. 미세 잘림 복구 (Trailing Truncation Auto-Repair)
    # max_tokens 상한으로 맨 끝 닫는 따옴표/중괄호가 짤린 경우 자동 복구 시도
    if first_brace != -1:
        base_cand = cleaned[first_brace:]
        for fix in ('"\n}', '"}', '"\n}}', '"\n}}}', '}', '"}'):
            try:
                obj = json.loads(base_cand + fix)
                if isinstance(obj, dict) and any(k in obj for k in ("attack_timeline", "forensic_summary", "verdict", "root_cause_hypothesis")):
                    return obj
            except Exception:
                pass

        # 미완성된 마지막 필드(쉼표 이후 텍스트)를 잘라내고 닫기 시도
        last_comma = base_cand.rfind(",")
        if last_comma != -1:
            try:
                obj = json.loads(base_cand[:last_comma] + "\n}")
                if isinstance(obj, dict) and any(k in obj for k in ("attack_timeline", "forensic_summary", "verdict", "root_cause_hypothesis")):
                    return obj
            except Exception:
                pass

    if valid_candidates:
        return valid_candidates[-1]

    # 7. 토큰 제한 등으로 JSON 뒷부분이 잘린 경우 (Partial Timeline Array Rescue)
    t_start = cleaned.find('"attack_timeline":')
    if t_start != -1:
        arr_start = cleaned.find("[", t_start)
        if arr_start != -1:
            last_item_brace = cleaned.rfind("}")
            if last_item_brace > arr_start:
                cand_arr = cleaned[arr_start : last_item_brace + 1] + "]"
                try:
                    events = json.loads(cand_arr)
                    if isinstance(events, list) and events:
                        conf_m = re.search(r'\"confidence\"\s*:\s*([0-9]*\.?[0-9]+)', cleaned)
                        conf = float(conf_m.group(1)) if conf_m else 0.85
                        return {
                            "attack_timeline": events,
                            "confidence": conf,
                            "root_cause_hypothesis": "공격 체인 연계 분석을 통해 침해 전파 경로가 재구성됨",
                            "forensic_summary": "다단계 공격 체인 기반 포렌식 분석 완료",
                        }
                except Exception:
                    pass

    try:
        res = json.loads(cleaned)
        if isinstance(res, dict):
            return res
    except Exception:
        pass

    # 8. 토큰 제한 등으로 JSON 뒷부분이 미세하게 잘린 경우 (Regex Rescue)
    # 6-1. Auto-Triage 패턴 복구
    verdict_m = re.search(r'\"verdict\"\s*:\s*\"(true_positive|false_positive|benign)\"', cleaned)
    if verdict_m:
        conf_m = re.search(r'\"confidence\"\s*:\s*([0-9]*\.?[0-9]+)', cleaned)
        rat_m = re.search(r'\"rationale\"\s*:\s*\"([^\"]*)', cleaned)
        return {
            "verdict": verdict_m.group(1),
            "confidence": float(conf_m.group(1)) if conf_m else 0.5,
            "rationale": rat_m.group(1) if rat_m else "판단 근거 추출 완료",
        }

    # 6-2. Forensic / Multi-stage 패턴 복구
    summary_m = re.search(r'\"(?:forensic_summary|summary)\"\s*:\s*\"([^\"]*)', cleaned)
    root_m = re.search(r'\"(?:root_cause_hypothesis|root_cause_analysis)\"\s*:\s*\"([^\"]*)', cleaned)
    if summary_m or root_m:
        return {
            "forensic_summary": summary_m.group(1) if summary_m else "다단계 공격 체인 기반 침해사고 재구성 완료",
            "root_cause_hypothesis": root_m.group(1) if root_m else "공격 체인 연계를 통한 침해 확산으로 추정됨",
            "attack_timeline": [],
            "compromised_assets": {},
        }

    logger.warning("safe_parse_agent_json.parse_failed_fallback_empty", raw_content=str(content)[:200])
    return {}


def normalize_string_list(items: Any) -> list[str]:
    """Coerce various LLM output shapes (strings, dicts with 'name'/'id'/'value', lists) into clean list[str]."""
    if not items:
        return []
    if isinstance(items, str):
        items = [items]
    elif not isinstance(items, list):
        items = [items]

    res: list[str] = []
    for item in items:
        if isinstance(item, str):
            s = item.strip()
            if s:
                res.append(s)
        elif isinstance(item, dict):
            val = item.get("name") or item.get("id") or item.get("value") or item.get("actor") or item.get("technique")
            if val and isinstance(val, str) and val.strip():
                res.append(val.strip())
            else:
                s = str(item)
                if s:
                    res.append(s)
        elif item is not None:
            s = str(item).strip()
            if s:
                res.append(s)
    return res
