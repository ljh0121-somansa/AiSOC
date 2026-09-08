import asyncio
import os
import time

# Set up env to allow isolated testing
os.environ["OPENAI_MODEL"] = "gpt-4o-mini"
os.environ["AISOC_MAX_TOKENS"] = "4000"

# Mock the database/ledger to avoid errors during test
import app.investigator.state
from app.investigator.state import InvestigatorState, ReconState, ForensicState, ResponderState

async def run_test():
    # Construct a robust dummy state mimicking the real pipeline's output
    state = InvestigatorState(
        case_id="TEST-1234",
        alert_summary="Multiple RDP brute force attempts followed by suspicious PowerShell execution on WIN-SRV-01.",
        recon=ReconState(
            summary="Attacker successfully brute-forced RDP on WIN-SRV-01 and established a C2 connection via PowerShell.",
            iocs={"192.168.1.100": "C2_IP", "invoke_shell.ps1": "MALWARE_FILE"},
            mitre_techniques=["T1110", "T1059.001"],
            threat_actors=["FIN7 (Suspected)"]
        ),
        forensic=ForensicState(
            summary="Forensic analysis confirms execution of 'invoke_shell.ps1' leading to lateral movement to DC-01.",
            root_cause_hypothesis="Weak RDP credentials allowed initial access.",
            blast_radius="WIN-SRV-01 and DC-01 compromised.",
            confidence=0.95,
            artefacts=["C:\\Windows\\Temp\\invoke_shell.ps1", "Security Event ID 4624 (WIN-SRV-01)"],
            timeline=[
                {"step": 1, "host": "WIN-SRV-01", "event_type": "Network", "description": "RDP brute force from 203.0.113.5", "mitre_technique": "T1110"},
                {"step": 2, "host": "WIN-SRV-01", "event_type": "Process", "description": "Execution of invoke_shell.ps1", "mitre_technique": "T1059.001"}
            ]
        ),
        responder=ResponderState(
            summary="Initiated host isolation for WIN-SRV-01 and DC-01. Blocking C2 IP at firewall.",
            risk_level="CRITICAL",
            containment_steps=["CONTAINMENT: Isolate WIN-SRV-01", "CONTAINMENT: Block IP 203.0.113.5"],
            recommended_actions=[
                {"priority": "critical", "action": "Reset all domain admin passwords."},
                {"priority": "high", "action": "Deploy EDR signature for invoke_shell.ps1."}
            ]
        ),
        enrichment_cache={"203.0.113.5": "Tor Exit Node", "invoke_shell.ps1": "Known malicious hash"}
    )
    
    # Print the restructured Context Payload
    from app.investigator.report_writer_agent import _build_context, _SYSTEM_PROMPT
    print("=== [1] RESTRUCTURED CONTEXT PAYLOAD ===")
    print(_build_context(state))
    print("\n" + "="*50 + "\n")
    
    # We will simulate the LLM call to verify it doesn't crash, but since we are in 
    # a mocked environment without valid API keys, we will just print the prompt construction.
    print("=== [2] SYSTEM PROMPT ===")
    print(_SYSTEM_PROMPT.format(case_id=state.case_id))

if __name__ == "__main__":
    asyncio.run(run_test())