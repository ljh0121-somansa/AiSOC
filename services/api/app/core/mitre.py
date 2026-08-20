import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parents[3]
MAP_PATH = PROJECT_ROOT / "app" / "core" / "data" / "mitre_map.json"

MITRE_MAP: dict[str, str] = {}
try:
    with open(MAP_PATH, "r", encoding="utf-8") as f:
        MITRE_MAP = json.load(f)
        logger.info(f"Successfully loaded {len(MITRE_MAP)} items from {MAP_PATH}")
except FileNotFoundError:
    logger.warning(
        f"[Warning] {MAP_PATH} not found. Run scripts/generate_mitre_map.py first."
    )
except Exception as e:
    logger.error(f"[Error] Failed to load {MAP_PATH}: {e}")

TOTAL_MITRE_TECHNIQUES = len(
    set(tech_id.split('.')[0] for tech_id in MITRE_MAP.keys())
)

def resolve_tactic(technique_id: str, alert_tactic_hint: str | None = None) -> str:
    """Technique ID를 입력받아 표준 Tactic 문자열을 반환합니다."""
    # 1. Alert/Rule 자체에 Tactic 힌트가 있다면 최우선 채택
    if alert_tactic_hint:
        return alert_tactic_hint.lower()

    if not technique_id:
        return "unmapped"

    tech_id_clean = technique_id.strip().upper()

    # 2. Exact Match (예: T1059.001)
    if tech_id_clean in MITRE_MAP:
        return MITRE_MAP[tech_id_clean]

    # 3. Sub-technique Fallback (예: T1059.001 -> T1059 상위 ID 검색)
    parent_id = tech_id_clean.split('.')[0]
    if parent_id in MITRE_MAP:
        return MITRE_MAP[parent_id]

    # 4. 등록되지 않은 Technique인 경우
    return "unmapped"

def total_techniques_count() -> int:
    return TOTAL_MITRE_TECHNIQUES