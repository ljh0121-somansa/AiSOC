import asyncio
import os
import json
import asyncpg
from app.investigator.state import InvestigatorState, ReconFindings, ForensicFindings, ResponderPlan
from app.investigator.report_writer_agent import run_report_writer
import app.investigator.report_writer_agent as rwa

# Mock DB writes so we don't pollute audit tables during test
def mock_log(*args, **kwargs): pass
def mock_log_prompt(*args, **kwargs): return "test-hash"
def mock_log_response(*args, **kwargs):
    print(f"=== TELEMETRY ===")
    print(f"Tokens Used: {kwargs.get('tokens_used')}")
    print(f"Cost USD: {kwargs.get('cost_usd')}")
    print(f"Latency ms: {kwargs.get('latency_ms')}")

InvestigatorState.log = mock_log
InvestigatorState.log_llm_prompt = mock_log_prompt
InvestigatorState.log_llm_response = mock_log_response
rwa.record_llm_call = lambda *args, **kwargs: None

async def verify_real_incident():
    state = InvestigatorState(
        case_id="7c08d8a3-9d07-48da-9832-58647c7ae451",
        alert_summary="Host 'demo' (10.203.255.230) initiated network connection to target '10.216.4.165:8888' via TCP8888 service with action 'allowed' (676 bytes sent, Severity: high)."
    )
    state.recon = ReconFindings(
        summary="demo 호스트에서 10.216.4.165:8888로 발생한 TCP 연결은 C2 beaconing, LSASS credential dumping, VSS 삭제, SMB lateral movement, ransomware file impact로 이어지는 다단계 ransomware campaign의 일부로 판단됩니다. 현재 demo와 DESKTOP-8SEUPMF가 직접 영향을 받았으며, 내부 네트워크로의 추가 확산 가능성이 높습니다. 즉각적인 격리, 자격 증명 무효화, ransomware binary 식별, 백업 및 복구 준비가 필요합니다.",
        iocs=[{"type": "ip", "value": "10.203.255.230"}, {"type": "ip", "value": "10.216.4.165"}, {"type": "ip", "value": "10.216.193.143"}],
        mitre_techniques=["T1486", "T1490", "T1021.002", "T1571", "T1071.001", "T1003.001"],
        threat_actors=["Ransomware Campaign (근거: LSASS 덤프 및 VSS 삭제 확인)"]
    )
    state.forensic = ForensicFindings(
        summary="demo(10.203.255.230)에서 10.216.4.165:8888로 발생한 TCP 8888 C2 beaconing을 기점으로, demo에서 반복된 LSASS credential dumping과 VSS 삭제가 확인되었습니다. 이후 demo에서 DESKTOP-8SEUPMF(10.216.193.143)로 SMB lateral movement가 감지되고, DESKTOP-8SEUPMF에서 VSS 삭제와 ransomware file impact가 이어져 다단계 ransomware campaign으로 판단됩니다.",
        root_cause_hypothesis="demo 호스트가 10.216.4.165:8888 C2 채널과 연결된 초기 침해로 인해 악성 코드가 실행되고, LSASS credential dumping을 통해 자격 증명이 탈취된 것으로 추정됩니다.",
        blast_radius="demo와 DESKTOP-8SEUPMF가 직접 침해되었습니다.",
        confidence=0.85,
        artefacts=["TCP 10.203.255.230 -> 10.216.4.165:8888", "lsass.exe", "vssadmin.exe"],
        timeline=[
            {"step": 1, "host": "demo", "event_type": "C2_BEACONING", "description": "C2 beaconing connection", "mitre_technique": "T1071.001"},
            {"step": 2, "host": "demo", "event_type": "CREDENTIAL_DUMP", "description": "LSASS memory dumping", "mitre_technique": "T1003.001"},
            {"step": 3, "host": "DESKTOP-8SEUPMF", "event_type": "RANSOMWARE_IMPACT", "description": "File encryption impact", "mitre_technique": "T1486"}
        ]
    )
    state.responder = ResponderPlan(
        summary="C2 endpoint 10.216.4.165를 통한 추가 확산을 즉시 차단하기 위한 공격적 격리가 필요합니다.",
        risk_level="critical",
        containment_steps=[
            "[NETWORK_ISOLATION] demo 호스트 격리",
            "[FIREWALL_BLOCK] C2 10.216.4.165 트래픽 차단"
        ],
        recommended_actions=[
            {"priority": "critical", "action": "Isolate affected hosts immediately."},
            {"priority": "high", "action": "Revoke domain credentials."}
        ]
    )
    
    print("Executing run_report_writer with tuned prompt...")
    res = await run_report_writer(state.to_dict())
    
    print("\n=== GENERATED REPORT MD PREVIEW ===")
    print(res.get("report_md", "None")[:1500])

if __name__ == "__main__":
    asyncio.run(verify_real_incident())
