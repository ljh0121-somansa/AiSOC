import json
import os
from pathlib import Path
import requests

# 프로젝트 루트 기준 경로 설정
BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_PATH = BASE_DIR / "app" / "core" / "data" / "mitre_map.json"

def generate_map():
    print("Downloading MITRE ATT&CK Enterprise STIX data...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()

    mapping = {}
    
    for obj in data.get("objects", []):
        # Technique (attack-pattern) 개체만 필터링
        if obj.get("type") == "attack-pattern":
            # Technique ID (예: T1059 또는 T1059.001)
            tech_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                None,
            )
            # Primary Tactic (예: execution)
            tactics = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]

            if tech_id and tactics:
                # 첫 번째 Tactic을 Primary Tactic으로 지정
                mapping[tech_id] = tactics[0]

    # 디렉터리 생성 및 JSON 저장
    os.makedirs(OUTPUT_PATH.parent, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=False)

    print(f"Successfully generated MITRE map with {len(mapping)} techniques at: {OUTPUT_PATH}")

if __name__ == "__main__":
    generate_map()