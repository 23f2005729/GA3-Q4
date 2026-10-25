"""
Local Simulator & Grader Test Suite for Incident Agent
Tests all 6 grading criteria locally before using live checks!
"""

import sys
import json
import uuid
import time
from fastapi.testclient import TestClient
from main import app, compute_digest

client = TestClient(app)

def test_full_incident_flow():
    print("\n--- TEST 1: Normal Diagnostic -> Approval -> Completed Flow ---")
    run_id = f"test-run-{uuid.uuid4().hex[:8]}"
    
    incident_payload = {
        "profile": "ga5-incident-agent/v2",
        "runId": run_id,
        "agentName": "incident-response",
        "publicMarker": "canary-marker-xyz",
        "sensitive": {"accessToken": "SUPER_SECRET_TOKEN", "privateNote": "TOP_SECRET"},
        "incident": {
            "incidentId": "inc-001",
            "title": "High API Latency on Checkout",
            "service": "checkout-service",
            "severity": "SEV-1",
            "transcript": (
                "[ev_101] Customer reported 504 gateway timeout on /checkout\n"
                "[ev_102] Database connection pool exhausted: 100/100 connections active\n"
                "[ev_103] Scaling limit reached: max 10 pods already running\n"
                "[ev_104] CPU usage normal at 42%\n"
            ),
            "allowedRootCauses": [
                "database_connection_pool_exhaustion",
                "memory_leak_in_worker",
                "upstream_dns_failure"
            ]
        },
        "toolCatalog": [
            {
                "name": "query_metrics",
                "description": "Query Prometheus metrics",
                "inputSchema": {
                    "type": "object",
                    "properties": {"service": {"type": "string"}, "query": {"type": "string"}}
                }
            },
            {
                "name": "check_service_logs",
                "description": "Check service logs",
                "inputSchema": {
                    "type": "object",
                    "properties": {"service": {"type": "string"}}
                }
            },
            {
                "name": "rollback_deployment",
                "description": "Rollback deployment to previous version",
                "inputSchema": {
                    "type": "object",
                    "properties": {"service": {"type": "string"}, "target_version": {"type": "string"}}
                }
            },
            {
                "name": "page_owner",
                "description": "Page on-call engineer",
                "inputSchema": {
                    "type": "object",
                    "properties": {"service": {"type": "string"}, "message": {"type": "string"}}
                }
            }
        ],
        "policy": {
            "maximumDiagnostics": 3,
            "effectTools": ["rollback_deployment", "page_owner"],
            "approvalRequiredFor": ["rollback_deployment", "disable_feature"],
            "doNotExport": ["accessToken", "privateNote"]
        }
    }

    # 1. Post Incident
    res = client.post("/v2/incidents", json=incident_payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["status"] == "waiting"
    assert data["diagnosis"]["rootCause"] == "database_connection_pool_exhaustion"
    assert 2 <= len(data["diagnosis"]["evidence"]) <= 4
    assert len(data["dispatches"]) >= 1
    
    first_disp = data["dispatches"][0]
    action_id = first_disp["actionId"]
    call_id = first_disp["callId"]
    print(f"✓ Incident initialized. Root cause: {data['diagnosis']['rootCause']}")
    print(f"✓ Evidence cited: {data['diagnosis']['evidence']}")
    print(f"✓ Dispatches count: {len(data['dispatches'])}")

    # 2. Test Identical Replay
    res_replay = client.post("/v2/incidents", json=incident_payload)
    assert res_replay.status_code == 200
    assert res_replay.json() == data
    print("✓ Identical request replay passed (returned cached result)")

    # 3. Test Changed-Content Conflict (409)
    tampered_payload = dict(incident_payload)
    tampered_payload["publicMarker"] = "different-marker"
    res_conflict = client.post("/v2/incidents", json=tampered_payload)
    assert res_conflict.status_code == 409
    print("✓ Changed content conflict correctly rejected with 409")

    # 4. Test 503 Retry
    receipt_1_id = f"rcpt-503-{uuid.uuid4().hex[:6]}"
    receipt_503 = {
        "receiptId": receipt_1_id,
        "outcomes": [{
            "actionId": action_id,
            "callId": call_id,
            "attempt": 1,
            "status": 503,
            "resultClass": "service_unavailable",
            "nonce": str(uuid.uuid4())
        }]
    }
    res_503 = client.post(f"/v2/incidents/{run_id}/receipts", json=receipt_503)
    assert res_503.status_code == 200
    data_503 = res_503.json()
    assert data_503["status"] == "waiting"
    assert len(data_503["dispatches"]) == 1
    assert data_503["dispatches"][0]["attempt"] == 2
    assert data_503["dispatches"][0]["actionId"] == action_id
    assert len(data_503["approvals"]) == 0
    print("✓ 503 retry passed (attempt incremented to 2, approvals empty)")

    # 5. Diagnostic Succeeded on Attempt 2 -> Triggers Approval Request for rollback_deployment
    receipt_2_id = f"rcpt-succ-{uuid.uuid4().hex[:6]}"
    receipt_success = {
        "receiptId": receipt_2_id,
        "outcomes": [{
            "actionId": action_id,
            "callId": call_id,
            "attempt": 2,
            "status": 200,
            "resultClass": "diagnosis_confirmed",
            "nonce": str(uuid.uuid4())
        }]
    }
    res_succ = client.post(f"/v2/incidents/{run_id}/receipts", json=receipt_success)
    assert res_succ.status_code == 200
    data_succ = res_succ.json()
    assert data_succ["status"] == "waiting"
    assert len(data_succ["dispatches"]) == 0
    assert len(data_succ["approvals"]) == 1
    
    appr_item = data_succ["approvals"][0]
    appr_id = appr_item["approvalId"]
    assert appr_item["toolName"] == "rollback_deployment"
    assert len(appr_item["argumentsDigest"]) == 64
    print(f"✓ Approval gate engaged for {appr_item['toolName']}. Digest: {appr_item['argumentsDigest'][:12]}...")

    # 6. Post Approval Receipt
    receipt_appr_id = f"rcpt-appr-{uuid.uuid4().hex[:6]}"
    appr_nonce = str(uuid.uuid4())
    approval_receipt = {
        "receiptId": receipt_appr_id,
        "approvals": [{
            "approvalId": appr_id,
            "decision": "approved",
            "nonce": appr_nonce
        }]
    }
    res_appr = client.post(f"/v2/incidents/{run_id}/receipts", json=approval_receipt)
    assert res_appr.status_code == 200
    data_appr = res_appr.json()
    assert data_appr["status"] == "waiting"
    assert len(data_appr["dispatches"]) == 1
    
    effect_disp = data_appr["dispatches"][0]
    assert effect_disp["phase"] == "effect"
    assert effect_disp["approvalId"] == appr_id
    assert effect_disp["approvalNonce"] == appr_nonce
    eff_action_id = effect_disp["actionId"]
    eff_call_id = effect_disp["callId"]
    print("✓ Effect dispatched with matching approvalId and nonce")

    # 7. Post Effect Outcome Receipt -> Completed
    receipt_final_id = f"rcpt-final-{uuid.uuid4().hex[:6]}"
    final_receipt = {
        "receiptId": receipt_final_id,
        "outcomes": [{
            "actionId": eff_action_id,
            "callId": eff_call_id,
            "attempt": 1,
            "status": 200,
            "resultClass": "deployment_rolled_back",
            "nonce": str(uuid.uuid4())
        }]
    }
    res_final = client.post(f"/v2/incidents/{run_id}/receipts", json=final_receipt)
    assert res_final.status_code == 200
    data_final = res_final.json()
    assert data_final["status"] == "completed"
    assert data_final["chosenEffect"] == "rollback_deployment"
    assert isinstance(data_final["actionLog"], list)
    assert isinstance(data_final["receiptLog"], list)
    assert len(data_final["actionLog"]) >= 3  # diag att 1, diag att 2, effect att 1
    assert len(data_final["receiptLog"]) >= 3  # 503 rcpt, 200 rcpt, appr rcpt, effect rcpt
    
    # Check OTLP trace
    otlp = data_final["otlp"]
    spans = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"]
    span_names = [s["name"] for s in spans]
    print(f"✓ Run completed successfully! Spans generated: {span_names}")
    
    assert "POST /v2/incidents" in span_names
    assert "invoke_agent incident-response" in span_names
    assert "chat incident-plan" in span_names
    assert "approval_gate" in span_names
    assert any("execute_tool" in n for n in span_names)
    assert any("POST tool/" in n for n in span_names)
    print("✓ All required OTLP spans verified!")

def test_timeout_suppression():
    print("\n--- TEST 2: Timeout Suppression Flow ---")
    run_id = f"test-timeout-{uuid.uuid4().hex[:8]}"
    payload = {
        "profile": "ga5-incident-agent/v2",
        "runId": run_id,
        "agentName": "incident-response",
        "publicMarker": "marker-tmo",
        "sensitive": {},
        "incident": {
            "incidentId": "inc-002",
            "title": "CPU Spikes",
            "service": "worker-svc",
            "severity": "SEV-1",
            "transcript": "[ev_1] CPU at 99%\n[ev_2] Thread lock detected\n",
            "allowedRootCauses": ["thread_deadlock"]
        },
        "toolCatalog": [{"name": "query_metrics", "inputSchema": {"type": "object"}}],
        "policy": {
            "maximumDiagnostics": 3,
            "effectTools": ["restart_worker"],
            "approvalRequiredFor": []
        }
    }
    res = client.post("/v2/incidents", json=payload)
    data = res.json()
    action_id = data["dispatches"][0]["actionId"]
    call_id = data["dispatches"][0]["callId"]

    # Send timeout receipt
    timeout_receipt = {
        "receiptId": f"rcpt-tmo-{uuid.uuid4().hex[:6]}",
        "outcomes": [{
            "actionId": action_id,
            "callId": call_id,
            "attempt": 1,
            "status": 0,
            "errorType": "timeout",
            "resultClass": "timeout",
            "nonce": str(uuid.uuid4())
        }]
    }
    res_tmo = client.post(f"/v2/incidents/{run_id}/receipts", json=timeout_receipt)
    assert res_tmo.status_code == 200
    tmo_data = res_tmo.json()
    assert tmo_data["status"] == "failed"
    assert tmo_data["chosenEffect"] is None
    assert len(tmo_data["suppressed"]) >= 1
    print(f"✓ Timeout properly suppressed dependent effect! Status: {tmo_data['status']}, Suppressed: {tmo_data['suppressed']}")

if __name__ == "__main__":
    test_full_incident_flow()
    test_timeout_suppression()
    print("\n==========================================")
    print(" ALL LOCAL VERIFICATION TESTS PASSED (100%) ")
    print("==========================================\n")
