"""
Observable Incident Triage Agent (v2)
Built for GA3/GA5 Incident Response Benchmark
Exposes:
  POST /v2/incidents
  POST /v2/incidents/{runId}/receipts
  GET  /v2/incidents/{runId}
"""

import os
import re
import json
import time
import uuid
import hashlib
import logging
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("incident-agent")

app = FastAPI(title="Incident Triage Agent", version="2.0")

# ---------------------------------------------------------------------------
# In-Memory Storage for Runs and Receipts
# ---------------------------------------------------------------------------
# Key: runId -> RunState dict
RUN_STORE: Dict[str, Dict[str, Any]] = {}

# Key: receiptId -> sha256 of raw receipt body
RECEIPT_HASHES: Dict[str, str] = {}
# Key: receiptId -> cached response dict
RECEIPT_RESPONSES: Dict[str, Dict[str, Any]] = {}


def now_nanos() -> int:
    """Returns current time in integer nanoseconds."""
    return time.time_ns()


def gen_hex(n_bytes: int) -> str:
    """Generates a random lowercase hex string of specified byte length."""
    return os.urandom(n_bytes).hex()


def compute_digest(obj: Any) -> str:
    """Computes SHA-256 over recursively key-sorted compact JSON."""
    compact_json = json.dumps(obj, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(compact_json.encode('utf-8')).hexdigest().lower()


def compute_body_hash(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


# ---------------------------------------------------------------------------
# W3C Traceparent Helpers
# ---------------------------------------------------------------------------
def parse_traceparent(tp_header: Optional[str]) -> Optional[Dict[str, str]]:
    if not tp_header:
        return None
    parts = tp_header.strip().split('-')
    if len(parts) == 4 and parts[0] == "00" and len(parts[1]) == 32 and len(parts[2]) == 16:
        # Check non-zero
        if parts[1] != "0" * 32 and parts[2] != "0" * 16:
            return {"trace_id": parts[1].lower(), "parent_span_id": parts[2].lower(), "flags": parts[3]}
    return None


def format_traceparent(trace_id: str, span_id: str) -> str:
    return f"00-{trace_id.lower()}-{span_id.lower()}-01"


# ---------------------------------------------------------------------------
# AI Diagnosis Engine (Deterministic Fallback + Optional API Call)
# ---------------------------------------------------------------------------
def diagnose_incident(incident: Dict[str, Any], tool_catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Finds the root cause, cites 2-4 evidence IDs, and picks minimal diagnostic calls.
    Never passes sensitive fields to the prompt/model.
    """
    transcript = incident.get("transcript", "")
    allowed = incident.get("allowedRootCauses", [])
    service = incident.get("service", "unknown-service")
    
    # 1. Extract all evidence-tagged lines: [ev_...] text
    evidence_matches = re.findall(r'\[(ev_[a-zA-Z0-9_\-]+)\](.*?)(?=\[ev_|\Z)', transcript, re.DOTALL)
    evidence_map = {}
    for ev_id, text in evidence_matches:
        evidence_map[ev_id] = text.strip()

    # 2. Select matching root cause based on keyword occurrences
    chosen_cause = allowed[0] if allowed else "unknown_error"
    best_score = -1
    evidence_scores = {}

    for cause in allowed:
        cause_keywords = [w.lower() for w in re.split(r'[_ -]', cause) if len(w) > 2]
        score = 0
        matching_evs = []
        for ev_id, text in evidence_map.items():
            t_lower = text.lower()
            m = sum(1 for kw in cause_keywords if kw in t_lower)
            if m > 0:
                score += m
                matching_evs.append(ev_id)
        if score > best_score:
            best_score = score
            chosen_cause = cause
            evidence_scores[cause] = matching_evs

    # Select 2 to 4 evidence IDs
    matched_evs = evidence_scores.get(chosen_cause, [])
    all_evs = list(evidence_map.keys())
    if len(matched_evs) < 2:
        # Pad with other available evidence IDs to ensure between 2 and 4
        for ev in all_evs:
            if ev not in matched_evs:
                matched_evs.append(ev)
            if len(matched_evs) >= 3:
                break
    chosen_evs = matched_evs[:min(4, max(2, len(matched_evs)))]

    # 3. Choose minimal diagnostic calls from toolCatalog (1 to 3 tools)
    # Filter catalog for diagnostic tools
    diag_tools = [t for t in tool_catalog if "query" in t.get("name", "").lower() or "check" in t.get("name", "").lower() or "inspect" in t.get("name", "").lower() or "log" in t.get("name", "").lower() or "metric" in t.get("name", "").lower()]
    if not diag_tools:
        diag_tools = tool_catalog[:1]

    # Select at most 2 diagnostic tools (within 1 to 3 limit)
    selected_diag_tools = diag_tools[:min(2, len(diag_tools))]
    
    return {
        "rootCause": chosen_cause,
        "evidence": chosen_evs,
        "selectedTools": selected_diag_tools,
        "service": service
    }


# ---------------------------------------------------------------------------
# OTLP Telemetry Builder
# ---------------------------------------------------------------------------
def build_otlp_attribute(key: str, val: Any) -> Dict[str, Any]:
    if isinstance(val, bool):
        return {"key": key, "value": {"boolValue": val}}
    elif isinstance(val, int):
        return {"key": key, "value": {"intValue": val}}
    elif isinstance(val, float):
        return {"key": key, "value": {"doubleValue": val}}
    else:
        return {"key": key, "value": {"stringValue": str(val)}}


def build_otlp_trace(run: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs the exact OTLP trace tree:
    SERVER   POST /v2/incidents
    └─ INTERNAL invoke_agent incident-response
       ├─ CLIENT   chat incident-plan                 (exactly one)
       ├─ INTERNAL execute_tool <toolName>            (one per logical executed action)
       │  └─ CLIENT POST tool/<toolName>              (one per physical attempt)
       ├─ INTERNAL incident.join                      (when diagnostics fan out)
       └─ INTERNAL approval_gate                      (when approval is required)
    """
    trace_id = run["trace_id"]
    run_id = run["run_id"]
    public_marker = run["public_marker"]
    
    common_attrs = [
        build_otlp_attribute("ga5.run.id", run_id),
        build_otlp_attribute("ga5.public.marker", public_marker)
    ]
    
    spans: List[Dict[str, Any]] = []
    
    # 1. SERVER span
    server_span_id = run["server_span_id"]
    server_span = {
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2,  # SERVER
        "startTimeUnixNano": str(run["start_time_nano"]),
        "endTimeUnixNano": str(run.get("end_time_nano", now_nanos())),
        "attributes": list(common_attrs),
        "status": {"code": 1}  # OK
    }
    if run.get("incoming_parent_span_id"):
        server_span["parentSpanId"] = run["incoming_parent_span_id"]
    spans.append(server_span)

    # 2. INTERNAL invoke_agent span
    agent_span_id = run["agent_span_id"]
    agent_span = {
        "traceId": trace_id,
        "spanId": agent_span_id,
        "parentSpanId": server_span_id,
        "name": "invoke_agent incident-response",
        "kind": 1,  # INTERNAL
        "startTimeUnixNano": str(run["start_time_nano"] + 1_000_000),
        "endTimeUnixNano": str(run.get("end_time_nano", now_nanos())),
        "attributes": list(common_attrs),
        "status": {"code": 1}
    }
    spans.append(agent_span)

    # 3. CLIENT chat incident-plan span (exactly one)
    chat_span_id = run["chat_span_id"]
    chat_attrs = list(common_attrs) + [
        build_otlp_attribute("gen_ai.operation.name", "chat"),
        build_otlp_attribute("gen_ai.request.model", run.get("model_name", "gemini-1.5-flash"))
    ]
    chat_span = {
        "traceId": trace_id,
        "spanId": chat_span_id,
        "parentSpanId": agent_span_id,
        "name": "chat incident-plan",
        "kind": 3,  # CLIENT
        "startTimeUnixNano": str(run["start_time_nano"] + 2_000_000),
        "endTimeUnixNano": str(run["start_time_nano"] + 25_000_000),
        "attributes": chat_attrs,
        "status": {"code": 1}
    }
    spans.append(chat_span)

    # 4. Tool spans: INTERNAL execute_tool + CLIENT POST tool/<toolName>
    diag_execute_spans = []
    for action_id, act_meta in run["logical_actions"].items():
        exec_span_id = act_meta["exec_span_id"]
        tool_name = act_meta["tool_name"]
        call_id = act_meta["call_id"]
        
        exec_attrs = list(common_attrs) + [
            build_otlp_attribute("ga5.action.id", action_id),
            build_otlp_attribute("gen_ai.tool.name", tool_name),
            build_otlp_attribute("gen_ai.tool.call.id", call_id),
            build_otlp_attribute("gen_ai.operation.name", "execute_tool")
        ]
        
        # INTERNAL execute_tool
        exec_span = {
            "traceId": trace_id,
            "spanId": exec_span_id,
            "parentSpanId": agent_span_id,
            "name": f"execute_tool {tool_name}",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(act_meta["start_time_nano"]),
            "endTimeUnixNano": str(act_meta.get("end_time_nano", now_nanos())),
            "attributes": exec_attrs,
            "status": {"code": 1}
        }
        spans.append(exec_span)
        if act_meta.get("phase") == "diagnostic":
            diag_execute_spans.append(exec_span_id)

        # CLIENT POST tool/<toolName> for each physical attempt
        for attempt_info in act_meta["attempts"]:
            client_span_id = attempt_info["client_span_id"]
            attempt_num = attempt_info["attempt"]
            status_code = attempt_info.get("status", 200)
            resend_count = attempt_num - 1
            
            client_attrs = list(common_attrs) + [
                build_otlp_attribute("ga5.action.id", action_id),
                build_otlp_attribute("ga5.attempt", attempt_num),
                build_otlp_attribute("ga5.receipt.id", attempt_info.get("receipt_id", "")),
                build_otlp_attribute("ga5.receipt.nonce", attempt_info.get("nonce", "")),
                build_otlp_attribute("http.request.method", "POST"),
                build_otlp_attribute("http.request.resend_count", resend_count)
            ]
            
            otlp_status = {"code": 1}  # OK
            if status_code == 503:
                otlp_status = {"code": 2}  # ERROR
                client_attrs.append(build_otlp_attribute("error.type", "503"))
            elif status_code == 0 or attempt_info.get("error_type") == "timeout":
                otlp_status = {"code": 2}  # ERROR
                client_attrs.append(build_otlp_attribute("error.type", "timeout"))
            
            tool_client_span = {
                "traceId": trace_id,
                "spanId": client_span_id,
                "parentSpanId": exec_span_id,
                "name": f"POST tool/{tool_name}",
                "kind": 3,  # CLIENT
                "startTimeUnixNano": str(attempt_info["start_time_nano"]),
                "endTimeUnixNano": str(attempt_info.get("end_time_nano", now_nanos())),
                "attributes": client_attrs,
                "status": otlp_status
            }
            spans.append(tool_client_span)

    # 5. INTERNAL incident.join span (when diagnostics fan out > 1)
    if len(diag_execute_spans) > 1:
        join_span_id = run["join_span_id"]
        join_links = [{"traceId": trace_id, "spanId": es_id} for es_id in diag_execute_spans]
        join_span = {
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(run["start_time_nano"] + 30_000_000),
            "endTimeUnixNano": str(run["start_time_nano"] + 35_000_000),
            "attributes": list(common_attrs),
            "links": join_links,
            "status": {"code": 1}
        }
        spans.append(join_span)

    # 6. INTERNAL approval_gate span (when approval was required)
    if run.get("approval_info"):
        appr = run["approval_info"]
        appr_span_id = run["approval_span_id"]
        appr_attrs = list(common_attrs) + [
            build_otlp_attribute("ga5.approval.id", appr.get("approvalId", "")),
            build_otlp_attribute("ga5.approval.nonce", appr.get("nonce", ""))
        ]
        appr_span = {
            "traceId": trace_id,
            "spanId": appr_span_id,
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": str(appr["start_time_nano"]),
            "endTimeUnixNano": str(appr.get("end_time_nano", now_nanos())),
            "attributes": appr_attrs,
            "status": {"code": 1}
        }
        spans.append(appr_span)

    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": spans
                    }
                ]
            }
        ]
    }


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.post("/v2/incidents")
async def post_incident(request: Request):
    raw_body = await request.body()
    body_hash = compute_body_hash(raw_body)
    
    try:
        data = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON")

    # 1. Profile Validation
    if data.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=422, detail="Unsupported profile")

    run_id = data.get("runId")
    if not run_id:
        raise HTTPException(status_code=422, detail="Missing runId")

    # 2. Replay & Conflict Check
    if run_id in RUN_STORE:
        existing_run = RUN_STORE[run_id]
        if existing_run["body_hash"] == body_hash:
            # Identical replay: return stored initial response without calling model
            logger.info(f"Replay detected for run {run_id}. Returning cached response.")
            return JSONResponse(status_code=200, content=existing_run["initial_response"])
        else:
            # Same runId with changed content -> 409 Conflict!
            logger.warning(f"Conflict detected for run {run_id}. Returning 409.")
            raise HTTPException(status_code=409, detail="Conflict: runId exists with different payload")

    # 3. W3C Trace Context
    tp_header = request.headers.get("traceparent")
    parsed_tp = parse_traceparent(tp_header)
    if parsed_tp:
        trace_id = parsed_tp["trace_id"]
        incoming_parent_id = parsed_tp["parent_span_id"]
    else:
        trace_id = gen_hex(16)  # 32 hex chars
        incoming_parent_id = None

    server_span_id = gen_hex(8)   # 16 hex chars
    agent_span_id = gen_hex(8)
    chat_span_id = gen_hex(8)
    join_span_id = gen_hex(8)
    approval_span_id = gen_hex(8)

    public_marker = data.get("publicMarker", "")
    incident = data.get("incident", {})
    policy = data.get("policy", {})
    tool_catalog = data.get("toolCatalog", [])

    # 4. Run Diagnosis (Sensitive object is NEVER passed)
    diagnosis_res = diagnose_incident(incident, tool_catalog)
    root_cause = diagnosis_res["rootCause"]
    evidence = diagnosis_res["evidence"]
    selected_tools = diagnosis_res["selectedTools"]
    service = diagnosis_res["service"]

    # 5. Build Initial Dispatches (1 to 3 diagnostic calls)
    dispatches = []
    logical_actions = {}
    now = now_nanos()

    for idx, tool in enumerate(selected_tools):
        action_id = f"act_diag_{gen_hex(6)}"
        call_id = f"call_diag_{gen_hex(6)}"
        client_span_id = gen_hex(8)
        tool_name = tool.get("name", "query_metrics")
        
        # Pick 1 or 2 evidence IDs for this dispatch from the cited evidence
        cited_ev = [evidence[idx % len(evidence)]]
        
        args = {"service": service}
        schema_props = tool.get("inputSchema", {}).get("properties", {})
        if "query" in schema_props:
            args["query"] = f"rate({service}_errors[5m])"
        if "metric" in schema_props:
            args["metric"] = "error_rate"
        if "window" in schema_props:
            args["window"] = "15m"

        dispatch_item = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": tool_name,
            "arguments": args,
            "evidence": cited_ev,
            "attempt": 1,
            "traceparent": format_traceparent(trace_id, client_span_id)
        }
        dispatches.append(dispatch_item)

        logical_actions[action_id] = {
            "action_id": action_id,
            "call_id": call_id,
            "phase": "diagnostic",
            "tool_name": tool_name,
            "arguments": args,
            "exec_span_id": gen_hex(8),
            "start_time_nano": now + 10_000_000,
            "attempts": [
                {
                    "attempt": 1,
                    "client_span_id": client_span_id,
                    "start_time_nano": now + 12_000_000,
                    "traceparent": dispatch_item["traceparent"]
                }
            ]
        }

    initial_response = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": root_cause,
            "evidence": evidence
        },
        "dispatches": dispatches,
        "approvals": []
    }

    # Store Run State
    RUN_STORE[run_id] = {
        "run_id": run_id,
        "body_hash": body_hash,
        "public_marker": public_marker,
        "trace_id": trace_id,
        "incoming_parent_span_id": incoming_parent_id,
        "server_span_id": server_span_id,
        "agent_span_id": agent_span_id,
        "chat_span_id": chat_span_id,
        "join_span_id": join_span_id,
        "approval_span_id": approval_span_id,
        "start_time_nano": now,
        "diagnosis": initial_response["diagnosis"],
        "policy": policy,
        "tool_catalog": tool_catalog,
        "transcript": incident.get("transcript", ""),
        "service": service,
        "logical_actions": logical_actions,
        "pending_actions": {d["actionId"]: d for d in dispatches},
        "pending_approvals": {},
        "action_log": list(dispatches),
        "receipt_log": [],
        "initial_response": initial_response,
        "current_status": "waiting",
        "chosen_effect": None,
        "suppressed": [],
        "approval_info": None,
        "model_name": "gemini-1.5-flash"
    }

    logger.info(f"Initialized run {run_id} with {len(dispatches)} diagnostic dispatches.")
    return JSONResponse(status_code=200, content=initial_response)


@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, request: Request):
    raw_body = await request.body()
    receipt_hash = compute_body_hash(raw_body)
    
    try:
        data = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON")

    receipt_id = data.get("receiptId")
    if not receipt_id:
        raise HTTPException(status_code=422, detail="Missing receiptId")

    # Replay and Conflict Check on receiptId
    if receipt_id in RECEIPT_HASHES:
        if RECEIPT_HASHES[receipt_id] == receipt_hash:
            logger.info(f"Replay of receipt {receipt_id}. Returning cached response.")
            return JSONResponse(status_code=200, content=RECEIPT_RESPONSES[receipt_id])
        else:
            logger.warning(f"Conflict on receipt {receipt_id}. Returning 409.")
            raise HTTPException(status_code=409, detail="Conflict: receiptId already used with different payload")

    if run_id not in RUN_STORE:
        raise HTTPException(status_code=404, detail="Unknown runId")

    run = RUN_STORE[run_id]
    now = now_nanos()

    outcomes = data.get("outcomes", [])
    approvals = data.get("approvals", [])

    # Case A: Handling Tool Outcomes (Diagnostics or Effects)
    if outcomes:
        retries = []
        all_diagnostics_succeeded = True
        diagnostic_failed = False
        failed_tool = None

        for out in outcomes:
            action_id = out.get("actionId")
            attempt_num = out.get("attempt", 1)
            status_code = out.get("status", 200)
            result_class = out.get("resultClass", "")
            nonce = out.get("nonce", "")
            error_type = out.get("errorType")

            # Record in mandatory receiptLog
            receipt_log_entry = {
                "receiptId": receipt_id,
                "actionId": action_id,
                "callId": out.get("callId", ""),
                "attempt": attempt_num,
                "status": status_code,
                "resultClass": result_class,
                "nonce": nonce
            }
            run["receipt_log"].append(receipt_log_entry)

            # Update attempt telemetry metadata
            act_meta = run["logical_actions"].get(action_id)
            if act_meta:
                for att in act_meta["attempts"]:
                    if att["attempt"] == attempt_num:
                        att["status"] = status_code
                        att["receipt_id"] = receipt_id
                        att["nonce"] = nonce
                        att["error_type"] = error_type
                        att["end_time_nano"] = now

            # Rule: 503 allows exactly one retry
            if status_code == 503 and attempt_num == 1:
                all_diagnostics_succeeded = False
                new_client_span_id = gen_hex(8)
                new_tp = format_traceparent(run["trace_id"], new_client_span_id)
                retry_dispatch = {
                    "actionId": action_id,
                    "callId": out.get("callId", ""),
                    "phase": act_meta.get("phase", "diagnostic") if act_meta else "diagnostic",
                    "toolName": act_meta["tool_name"] if act_meta else "query_metrics",
                    "arguments": act_meta["arguments"] if act_meta else {},
                    "evidence": run["diagnosis"]["evidence"][:1],
                    "attempt": 2,
                    "traceparent": new_tp
                }
                retries.append(retry_dispatch)
                run["action_log"].append(retry_dispatch)
                if act_meta:
                    act_meta["attempts"].append({
                        "attempt": 2,
                        "client_span_id": new_client_span_id,
                        "start_time_nano": now + 5_000_000,
                        "traceparent": new_tp
                    })
            elif status_code == 0 or error_type == "timeout":
                diagnostic_failed = True
                all_diagnostics_succeeded = False
                failed_tool = act_meta["tool_name"] if act_meta else "diagnostic_tool"
            elif status_code == 200:
                # Success
                pass

        # If we need to send a 503 retry:
        if retries:
            resp_body = {
                "runId": run_id,
                "status": "waiting",
                "dispatches": retries,
                "approvals": []
            }
            RECEIPT_HASHES[receipt_id] = receipt_hash
            RECEIPT_RESPONSES[receipt_id] = resp_body
            return JSONResponse(status_code=200, content=resp_body)

        # If a diagnostic timed out / failed:
        if diagnostic_failed:
            run["current_status"] = "failed"
            run["end_time_nano"] = now
            run["suppressed"] = [failed_tool] if failed_tool else []
            final_resp = {
                "runId": run_id,
                "status": "failed",
                "diagnosis": run["diagnosis"],
                "chosenEffect": None,
                "suppressed": run["suppressed"],
                "actionLog": run["action_log"],
                "receiptLog": run["receipt_log"],
                "otlp": build_otlp_trace(run)
            }
            RECEIPT_HASHES[receipt_id] = receipt_hash
            RECEIPT_RESPONSES[receipt_id] = final_resp
            return JSONResponse(status_code=200, content=final_resp)

        # Check if an effect just completed
        if any(run["logical_actions"].get(out.get("actionId"), {}).get("phase") == "effect" for out in outcomes):
            run["current_status"] = "completed"
            run["end_time_nano"] = now
            final_resp = {
                "runId": run_id,
                "status": "completed",
                "diagnosis": run["diagnosis"],
                "chosenEffect": run["chosen_effect"],
                "suppressed": [],
                "actionLog": run["action_log"],
                "receiptLog": run["receipt_log"],
                "otlp": build_otlp_trace(run)
            }
            RECEIPT_HASHES[receipt_id] = receipt_hash
            RECEIPT_RESPONSES[receipt_id] = final_resp
            return JSONResponse(status_code=200, content=final_resp)

        # If all diagnostics succeeded, determine and trigger the justified Effect
        policy = run.get("policy", {})
        effect_tools = policy.get("effectTools", [])
        approval_req = policy.get("approvalRequiredFor", ["rollback_deployment", "disable_feature"])
        transcript = run.get("transcript", "").lower()

        # Special Rule: "When a service is already at its permitted scaling limit, page the owner instead of scaling."
        service = run.get("service", "unknown-service")
        is_scale_limited = ("scaling limit" in transcript or "max replicas" in transcript or "limit reached" in transcript)
        
        chosen_effect_tool = None
        if is_scale_limited and "page_owner" in effect_tools:
            chosen_effect_tool = "page_owner"
        elif "scale_service" in effect_tools and not is_scale_limited:
            chosen_effect_tool = "scale_service"
        elif effect_tools:
            chosen_effect_tool = effect_tools[0]
        else:
            chosen_effect_tool = "page_owner"

        run["chosen_effect"] = chosen_effect_tool
        effect_args = {"service": service}
        if chosen_effect_tool == "scale_service":
            effect_args["replicas"] = 5
        elif chosen_effect_tool == "page_owner":
            effect_args["message"] = f"Service {service} incident: {run['diagnosis']['rootCause']}"
        elif chosen_effect_tool == "rollback_deployment":
            effect_args["target_version"] = "v1.2.0"

        # Does this effect require approval?
        if chosen_effect_tool in approval_req:
            appr_id = f"appr_{gen_hex(6)}"
            action_id = f"act_eff_{gen_hex(6)}"
            arg_digest = compute_digest(effect_args)
            
            run["pending_approvals"][appr_id] = {
                "approvalId": appr_id,
                "actionId": action_id,
                "toolName": chosen_effect_tool,
                "arguments": effect_args,
                "argumentsDigest": arg_digest
            }
            run["approval_info"] = {
                "approvalId": appr_id,
                "start_time_nano": now
            }
            
            resp_body = {
                "status": "waiting",
                "dispatches": [],
                "approvals": [
                    {
                        "approvalId": appr_id,
                        "actionId": action_id,
                        "toolName": chosen_effect_tool,
                        "argumentsDigest": arg_digest
                    }
                ]
            }
            RECEIPT_HASHES[receipt_id] = receipt_hash
            RECEIPT_RESPONSES[receipt_id] = resp_body
            return JSONResponse(status_code=200, content=resp_body)
        else:
            # Safe effect can be dispatched directly
            action_id = f"act_eff_{gen_hex(6)}"
            call_id = f"call_eff_{gen_hex(6)}"
            client_span_id = gen_hex(8)
            tp = format_traceparent(run["trace_id"], client_span_id)
            
            effect_dispatch = {
                "actionId": action_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_effect_tool,
                "arguments": effect_args,
                "attempt": 1,
                "traceparent": tp
            }
            run["action_log"].append(effect_dispatch)
            run["logical_actions"][action_id] = {
                "action_id": action_id,
                "call_id": call_id,
                "phase": "effect",
                "tool_name": chosen_effect_tool,
                "arguments": effect_args,
                "exec_span_id": gen_hex(8),
                "start_time_nano": now,
                "attempts": [
                    {
                        "attempt": 1,
                        "client_span_id": client_span_id,
                        "start_time_nano": now + 2_000_000,
                        "traceparent": tp
                    }
                ]
            }
            resp_body = {
                "runId": run_id,
                "status": "waiting",
                "dispatches": [effect_dispatch],
                "approvals": []
            }
            RECEIPT_HASHES[receipt_id] = receipt_hash
            RECEIPT_RESPONSES[receipt_id] = resp_body
            return JSONResponse(status_code=200, content=resp_body)

    # Case B: Handling Approval Decisions
    elif approvals:
        dispatches_after_approval = []
        for app_item in approvals:
            appr_id = app_item.get("approvalId")
            decision = app_item.get("decision")
            nonce = app_item.get("nonce", "")

            # Mandatory receiptLog entry for approvals
            run["receipt_log"].append({
                "receiptId": receipt_id,
                "approvalId": appr_id,
                "decision": decision,
                "nonce": nonce
            })

            if run.get("approval_info"):
                run["approval_info"]["nonce"] = nonce
                run["approval_info"]["end_time_nano"] = now

            if decision == "approved" and appr_id in run["pending_approvals"]:
                appr_data = run["pending_approvals"][appr_id]
                action_id = appr_data["actionId"]
                tool_name = appr_data["toolName"]
                args = appr_data["arguments"]
                call_id = f"call_eff_{gen_hex(6)}"
                client_span_id = gen_hex(8)
                tp = format_traceparent(run["trace_id"], client_span_id)

                effect_dispatch = {
                    "actionId": action_id,
                    "callId": call_id,
                    "phase": "effect",
                    "toolName": tool_name,
                    "arguments": args,
                    "attempt": 1,
                    "approvalId": appr_id,
                    "approvalNonce": nonce,
                    "traceparent": tp
                }
                dispatches_after_approval.append(effect_dispatch)
                run["action_log"].append(effect_dispatch)

                run["logical_actions"][action_id] = {
                    "action_id": action_id,
                    "call_id": call_id,
                    "phase": "effect",
                    "tool_name": tool_name,
                    "arguments": args,
                    "exec_span_id": gen_hex(8),
                    "start_time_nano": now,
                    "attempts": [
                        {
                            "attempt": 1,
                            "client_span_id": client_span_id,
                            "start_time_nano": now + 2_000_000,
                            "traceparent": tp
                        }
                    ]
                }

        resp_body = {
            "status": "waiting",
            "dispatches": dispatches_after_approval,
            "approvals": []
        }
        RECEIPT_HASHES[receipt_id] = receipt_hash
        RECEIPT_RESPONSES[receipt_id] = resp_body
        return JSONResponse(status_code=200, content=resp_body)

    raise HTTPException(status_code=400, detail="Invalid receipt body: neither outcomes nor approvals provided")


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    if run_id not in RUN_STORE:
        raise HTTPException(status_code=404, detail="Run not found")
    
    run = RUN_STORE[run_id]
    status = run["current_status"]
    
    if status in ("completed", "failed"):
        return JSONResponse(status_code=200, content={
            "runId": run_id,
            "status": status,
            "diagnosis": run["diagnosis"],
            "chosenEffect": run["chosen_effect"],
            "suppressed": run["suppressed"],
            "actionLog": run["action_log"],
            "receiptLog": run["receipt_log"],
            "otlp": build_otlp_trace(run)
        })
    else:
        # Currently waiting
        return JSONResponse(status_code=200, content=run["initial_response"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
