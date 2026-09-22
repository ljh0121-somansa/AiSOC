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

    # 4. 가장 바깥쪽 { ... } 객체 파싱
    json_match = re.search(r"\{[\s\S]*\}", cleaned)
    if json_match:
        json_str = json_match.group(0)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            try:
                decoder = json.JSONDecoder()
                obj, _ = decoder.raw_decode(json_str)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass

    try:
        res = json.loads(cleaned)
        if isinstance(res, dict):
            return res
    except Exception:
        pass

    logger.warning("safe_parse_agent_json.parse_failed_fallback_empty", raw_content=str(content)[:200])
    return {}
