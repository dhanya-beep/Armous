from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import time
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rate_limiting import TrafficAnalyzer

# -----------------------------------------------------------------------------
# App + CORS
# -----------------------------------------------------------------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Stores and persistence
# -----------------------------------------------------------------------------
CAPTURE_STORE: List[dict] = []
TRAFFIC = TrafficAnalyzer(rate_limit=10, window_seconds=60, anomaly_score_threshold=5)

PERSIST_DIR = Path(".persist")
PERSIST_DIR.mkdir(exist_ok=True)
FILE_CURRENT = PERSIST_DIR / "current_analysis.json"
FILE_ACTIONS = PERSIST_DIR / "actions.json"
FILE_CAPTURES = PERSIST_DIR / "captures.json"
FILE_ALERTS = PERSIST_DIR / "alerts.json"
FILE_ANALYSES = PERSIST_DIR / "analyses.json"

def _load_json(p: Path, default):
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8") or json.dumps(default))
    except Exception:
        pass
    return default

def _save_json(p: Path, obj):
    try:
        p.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    except Exception:
        pass

CURRENT_ANALYSIS: Optional[dict] = _load_json(FILE_CURRENT, None)
ACTION_LOG: Dict[str, List[dict]] = _load_json(FILE_ACTIONS, {})
CAPTURE_STORE = _load_json(FILE_CAPTURES, [])
ALERT_STORE: List[dict] = _load_json(FILE_ALERTS, [])
ANALYSIS_STORE: Dict[str, dict] = _load_json(FILE_ANALYSES, {})  # key: str(capture_id) -> unified

def _persist_all():
    _save_json(FILE_CAPTURES, CAPTURE_STORE)
    _save_json(FILE_ACTIONS, ACTION_LOG)
    _save_json(FILE_CURRENT, CURRENT_ANALYSIS)
    _save_json(FILE_ALERTS, ALERT_STORE)
    _save_json(FILE_ANALYSES, ANALYSIS_STORE)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _norm_req(capture: dict) -> Tuple[str, str, dict, str]:
    req = capture.get("request") or {}
    method = capture.get("method") or req.get("method") or "GET"
    url = capture.get("url") or req.get("url") or "/"
    headers = capture.get("headers") or req.get("headers") or {}
    body = capture.get("request_body_text") \
        or req.get("request_body_text") \
        or capture.get("requestbodytext") \
        or ""
    return method, url, headers, body

def _capture_extract_client_ip_headers(headers: dict) -> str:
    if not headers:
        return "127.0.0.1"
    if headers.get("X-Forwarded-For"):
        return headers["X-Forwarded-For"].split(",")[0].strip()
    if headers.get("X-Real-IP"):
        return headers["X-Real-IP"].strip()
    return "127.0.0.1"

def _capture_form_submission(method: str, headers: dict) -> bool:
    if method and method.upper() != "POST":
        return False
    ctype = (headers or {}).get("Content-Type", "").lower()
    return ("application/x-www-form-urlencoded" in ctype) or ("multipart/form-data" in ctype)

def _capture_to_raw_http(capture: dict) -> str:
    method, url, headers, body = _norm_req(capture)
    path = url
    try:
        m = re.match(r"^https?://[^/]+(.*)$", url)
        if m:
            path = m.group(1) or "/"
    except Exception:
        pass
    http_line = f"{method} {path} HTTP/1.1"
    host = ""
    try:
        mh = re.match(r"^https?://([^/]+)", url)
        if mh:
            host = mh.group(1)
    except Exception:
        pass

    lines = [http_line]
    if host:
        lines.append(f"Host: {host}")
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k.lower() == "host" and host:
                continue
            lines.append(f"{k}: {v}")

    if body and method.upper() in ("POST", "PUT", "PATCH"):
        lines.append("")
        lines.append(str(body))

    ip = _capture_extract_client_ip_headers(headers)
    lines.append(f"# client-ip: {ip}")
    return "\n".join(lines)

def _origin_label(http_norm: dict, capture: dict) -> str:
    cls = (http_norm or {}).get("classification", "") or ""
    src_cls = (capture or {}).get("classification", "") or ""
    s = (cls or src_cls).lower()
    if any(k in s for k in ["llm", "ai", "openai", "gpt", "anthropic", "agent"]):
        return "LLM-like"
    if any(k in s for k in ["bot", "crawler", "scrap", "headless", "selenium", "playwright", "curl", "python-requests"]):
        return "Bot-like"
    return "Human-likely"

def _collect_reasons(final_action: str, http_norm: dict, rl: dict, ti: dict) -> List[str]:
    reasons = ["analyzed"]
    if final_action in ("BLOCK", "CHALLENGE"):
        reasons.append(f"final_action={final_action}")
    if (http_norm or {}).get("riskscore", 0) >= 60:
        reasons.append("risk_score>=60")
    if rl.get("rate_limited"):
        reasons.append("rate_limited")
    if rl.get("behavioral_score", 0) >= rl.get("threshold", 5):
        reasons.append("behavioral_anomaly")
    if (ti or {}).get("action") in ("BLOCK", "CHALLENGE"):
        reasons.append("threat_intel")
    return reasons

def _latest_action_for(cap_id: int) -> Optional[Tuple[str, str]]:
    """Return (action, timestamp) of the latest non-NOTE action for a capture, or None."""
    events = ACTION_LOG.get(str(cap_id), [])
    for e in reversed(events):
        a = (e.get("action") or "").upper()
        if a in ("ALLOW", "CHALLENGE", "BLOCK"):
            return a, e.get("timestamp") or ""
    return None

# -----------------------------------------------------------------------------
# API: capture ingestion and listing
# -----------------------------------------------------------------------------
@app.post("/capture")
async def capture_endpoint(req: Request):
    payload = await req.json()
    payload["id"] = len(CAPTURE_STORE) + 1
    payload["received_at"] = time.time()

    method, url, headers, _ = _norm_req(payload)
    m = re.match(r"^https?://[^/]+(.*)$", url)
    path = m.group(1) if m and m.group(1) else url
    ip = _capture_extract_client_ip_headers(headers)
    form = _capture_form_submission(method, headers)

    CAPTURE_STORE.append(payload)
    TRAFFIC.process_traffic_instance(ip, path, method, payload["received_at"], form_submission=form)

    _persist_all()
    return {"ok": True, "id": payload["id"], "count": len(CAPTURE_STORE)}

@app.get("/captures")
async def list_captures(limit: int = 200, offset: int = 0):
    rev = list(reversed(CAPTURE_STORE))
    if limit < 1:
        limit = 200
    if offset < 0:
        offset = 0
    return rev[offset : offset + limit]

@app.get("/capture/{cap_id}")
async def get_capture(cap_id: int):
    for c in CAPTURE_STORE:
        if c.get("id") == cap_id:
            return c
    raise HTTPException(404, "capture not found")

# -----------------------------------------------------------------------------
# API: analysis, selection, batch send, actions, download
# -----------------------------------------------------------------------------
@app.post("/capture/{cap_id}/analyze")
async def analyze_capture(cap_id: int):
    capture = next((c for c in CAPTURE_STORE if c.get("id") == cap_id), None)
    if not capture:
        raise HTTPException(404, "capture not found")

    raw_http = _capture_to_raw_http(capture)
    tmp_dir = Path(".analysis_tmp")
    tmp_dir.mkdir(exist_ok=True)
    req_file = tmp_dir / f"capture_{cap_id}.txt"
    req_file.write_text(raw_http, encoding="utf-8")

    # HTTP analyzer
    try:
        from main_code_http import HTTPRequestAnalyzer
        analyzer = HTTPRequestAnalyzer()
        http_result = analyzer.analyze_request_file(str(req_file))
        http_normalized = {
            "filename": http_result.get("file_name") or req_file.name,
            "classification": http_result.get("classification", "UNKNOWN"),
            "threatlevel": http_result.get("threat_level", "UNKNOWN"),
            "riskscore": http_result.get("risk_score", 0),
            "confidence": http_result.get("confidence", 0),
            "requestdetails": http_result.get("request_details", {}),
            "useragentanalysis": http_result.get("user_agent_analysis", {}),
            "findings": http_result.get("findings", []),
            "analysistimestamp": http_result.get("analysis_timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        }
    except Exception:
        method, url, headers, _ = _norm_req(capture)
        http_normalized = {
            "filename": str(req_file.name),
            "classification": "UNKNOWN",
            "threatlevel": "UNKNOWN",
            "riskscore": 0,
            "confidence": 0,
            "requestdetails": {
                "method": method,
                "path": url,
                "ip": _capture_extract_client_ip_headers(headers),
                "headercount": len(headers),
            },
            "useragentanalysis": {
                "useragent": (headers or {}).get("User-Agent", "MISSING"),
                "length": len((headers or {}).get("User-Agent", "") or ""),
                "entropy": 0.0,
            },
            "findings": ["Analyzer import error; fallback used"],
            "analysistimestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # JA3/TLS (stub)
    try:
        import ja3_tls as ja3mod
        tls_stub = {"sslversion": 771,"ciphers": "4865-4866-4867-49195-49199","extensions": "0-11-10-35-16-43-45","ellipticcurves": "23-24-25","ecpointformats": "0"}
        jstr = ja3mod.ja3string_from_tls(tls_stub)
        jhash = ja3mod.md5hex(jstr)
        famua = ja3mod.uafamily((_norm_req(capture)[2] or {}).get("User-Agent", ""))
        decision, reason = ja3mod.decide_action({
            "isknownbadhash": False,"spoofmismatch": False,"cloudip": False,
            "uaiscli": famua in ("python-requests", "curl"),
            "hdrmissingreferer": not bool((_norm_req(capture)[2] or {}).get("Referer", "")),
            "hdrcontenttypeanom": False,
            "hdracceptlangempty": not bool((_norm_req(capture)[2] or {}).get("Accept-Language", "").strip()),
        })
        ja3_result = {"ja3": jstr,"ja3hash": jhash,"ua_family": famua,"ja3_family": "unknown","decision": decision,"reason": reason}
    except Exception:
        ja3_result = {"ja3": "","ja3hash": "","ua_family": "unknown","ja3_family": "unknown","decision": "ALLOW","reason": "fallback"}

    # Threat Intel
    try:
        from threat_intelligence import ThreatIntelEngine
        engine = ThreatIntelEngine(abuseipdb_key=os.environ.get("ABUSEIPDB_KEY"), virustotal_key=os.environ.get("VT_KEY"))
        _, url, headers, _ = _norm_req(capture)
        ip = _capture_extract_client_ip_headers(headers)
        ip_score, ip_info, _ = engine.check_abuseipdb(ip)
        vt_ip_score, vt_ip_info, _ = engine.check_virustotal_ip(ip)
        vt_url_score, vt_url_info, _ = (0, "URL not checked", {})
        if url:
            vt_url_score, vt_url_info, _ = engine.check_virustotal_url(url)
        ua = (headers or {}).get("User-Agent", "")
        ua_score, ua_info, _ = engine.check_useragent(ua)
        total = ip_score + vt_ip_score + vt_url_score + ua_score
        if total >= engine.thresholds["malicious"]:
            action = "BLOCK"
        elif total >= engine.thresholds["suspicious"]:
            action = "CHALLENGE"
        else:
            action = "ALLOW"
        ti_result = {"scores":{"abuseipdb_ip": ip_score,"virustotal_ip": vt_ip_score,"virustotal_url": vt_url_score,"user_agent": ua_score,"total": total},
                     "details":{"abuseipdb": ip_info,"virustotal_ip": vt_ip_info,"virustotal_url": vt_url_info,"user_agent": ua_info},
                     "action": action}
    except Exception as e:
        ti_result = {"scores": {}, "details": {"error": f"threat intelligence unavailable: {e}"}, "action": "ALLOW"}

    # Behavioral / rate limiting
    method, url, headers, _ = _norm_req(capture)
    m = re.match(r"^https?://[^/]+(.*)$", url)
    path = m.group(1) if m and m.group(1) else url
    ip = _capture_extract_client_ip_headers(headers)
    form = _capture_form_submission(method, headers)
    now_ts = time.time()

    TRAFFIC.log_request(ip, path, method, now_ts, form_submission=form)
    beh_score, beh_details = TRAFFIC.assign_behavioral_anomaly_score(ip)
    rate_limit_hit = TRAFFIC.detect_rate_limit(ip)
    req_count_window = TRAFFIC.get_request_count(ip, TRAFFIC.window_seconds)
    spike_freq = TRAFFIC.detect_spike_frequency(ip)
    parallel_req = TRAFFIC.detect_parallel_requests(ip)
    crawl_pattern = TRAFFIC.analyze_crawl_depth_and_linearity(ip)
    non_human = TRAFFIC.identify_non_human_delay_patterns(ip)
    form_flood = TRAFFIC.detect_form_submission_flood(ip)
    repetitive = TRAFFIC.profile_repetitive_access(ip)

    rate_limit_info = {
        "ip": ip, "window_seconds": TRAFFIC.window_seconds,
        "count_in_window": req_count_window, "rate_limit": TRAFFIC.rate_limit,
        "rate_limited": rate_limit_hit,
        "signals": {"spike_frequency": spike_freq,"parallel_requests": parallel_req,"linear_crawl": crawl_pattern,"non_human_delays": non_human,"form_flood": form_flood,"repetitive_access": repetitive},
        "behavioral_score": beh_score, "behavioral_details": beh_details, "threshold": TRAFFIC.anomaly_score_threshold,
    }

    # Final decision
    final_action = (ti_result.get("action") or ja3_result.get("decision") or "ALLOW")
    if beh_score >= TRAFFIC.anomaly_score_threshold and final_action == "ALLOW":
        final_action = "CHALLENGE"
    if rate_limit_hit:
        final_action = "BLOCK"

    origin = _origin_label(http_normalized, capture)

    unified = {
        "capture_id": cap_id,
        "http_analysis": http_normalized,
        "ja3_tls": ja3_result,
        "threat_intel": ti_result,
        "rate_limit_analysis": rate_limit_info,
        "final_action": final_action,
        "origin_label": origin,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "original_capture": capture,
    }

    # Selection and stores
    global CURRENT_ANALYSIS
    CURRENT_ANALYSIS = unified
    ANALYSIS_STORE[str(cap_id)] = unified

    # Always create an alert for the analyzed item
    ALERT_STORE.append({
        "alert_id": len(ALERT_STORE) + 1,
        "capture_id": cap_id,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "active",
        "reasons": _collect_reasons(final_action, http_normalized, rate_limit_info, ti_result),
        "final_action": final_action,
        "risk": http_normalized.get("riskscore", 0),
        "ip": rate_limit_info.get("ip"),
        "classification": http_normalized.get("classification"),
        "origin_label": origin,
    })

    _persist_all()
    return JSONResponse(unified)

@app.get("/analysis/{cap_id}")
async def get_analysis(cap_id: int):
    a = ANALYSIS_STORE.get(str(cap_id))
    if not a:
        raise HTTPException(404, "analysis not found")
    return a

@app.get("/analyses")
async def list_analyses(limit: int = 200, offset: int = 0):
    arr = list(ANALYSIS_STORE.values())
    arr.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return arr[offset : offset + limit]

@app.get("/analysis/{cap_id}/download")
async def download_analysis(cap_id: int):
    a = ANALYSIS_STORE.get(str(cap_id))
    if not a:
        raise HTTPException(404, "analysis not found")
    payload = json.dumps(a, indent=2)
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=analysis_{cap_id}.json"}
    )

@app.post("/capture/{cap_id}/sendforanalysis")
async def send_for_analysis(cap_id: int):
    res = await analyze_capture(cap_id)
    data = json.loads(res.body)
    data["view_url"] = "/final_dashboard"
    return JSONResponse(data)

@app.post("/captures/sendforanalysis")
async def send_many_for_analysis(req: Request):
    body = await req.json()
    ids = body.get("ids") or []
    processed = []
    for cid in ids:
        try:
            _ = await analyze_capture(int(cid))
            processed.append(int(cid))
        except Exception:
            continue
    return {"ok": True, "processed": processed, "view_url": "/final_dashboard", "last_selected": processed[-1] if processed else None}

@app.get("/current_analysis")
async def get_current_analysis():
    if CURRENT_ANALYSIS is None:
        stored = _load_json(FILE_CURRENT, None)
        if stored is not None:
            globals()["CURRENT_ANALYSIS"] = stored
    if CURRENT_ANALYSIS is None:
        return {"selected": False}
    return {"selected": True, "data": CURRENT_ANALYSIS}

@app.post("/analysis/{cap_id}/action")
async def save_action(cap_id: int, req: Request):
    body = await req.json()
    action = body.get("action") or "NOTE"
    note = body.get("note") or ""
    entry = {
        "capture_id": cap_id,
        "action": action,
        "note": note,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    key = str(cap_id)
    ACTION_LOG.setdefault(key, []).append(entry)
    _persist_all()
    return {"ok": True, "saved": entry, "all_actions": ACTION_LOG[key]}

@app.get("/analysis/{cap_id}/actions")
async def list_actions(cap_id: int):
    return {"capture_id": cap_id, "actions": ACTION_LOG.get(str(cap_id), [])}

# -----------------------------------------------------------------------------
# API: alerts, stats, decisions history
# -----------------------------------------------------------------------------
@app.get("/alerts")
async def list_alerts(status: Optional[str] = None, limit: int = 200, offset: int = 0):
    items = ALERT_STORE
    if status in ("active", "resolved"):
        items = [a for a in items if a.get("status") == status]
    items = list(reversed(items))
    return items[offset : offset + limit]

@app.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int):
    found = next((a for a in ALERT_STORE if a.get("alert_id") == alert_id), None)
    if not found:
        raise HTTPException(404, "alert not found")
    if found.get("status") != "resolved":
        found["status"] = "resolved"
        found["resolved_at"] = datetime.utcnow().isoformat() + "Z"
    _persist_all()
    return {"ok": True, "alert": found}

@app.get("/stats")
async def get_stats():
    total_captures = len(CAPTURE_STORE)
    active_alerts = sum(1 for a in ALERT_STORE if a.get("status") == "active")
    selected_id = CURRENT_ANALYSIS["capture_id"] if CURRENT_ANALYSIS else None

    overall_counts: Dict[str, int] = {}
    for lst in ACTION_LOG.values():
        for e in lst:
            overall_counts[e["action"]] = overall_counts.get(e["action"], 0) + 1

    return {
        "total_captures": total_captures,
        "active_alerts": active_alerts,
        "selected_capture_id": selected_id,
        "overall_action_counts": overall_counts,
        "has_selection": CURRENT_ANALYSIS is not None,
    }

@app.get("/decision_counts")
async def decision_counts():
    counts = {"ALLOW": 0, "CHALLENGE": 0, "BLOCK": 0}
    for cap_id in ANALYSIS_STORE.keys():
        latest = _latest_action_for(int(cap_id))
        if latest:
            counts[latest[0]] += 1
    return counts

@app.get("/decisions_history")
async def decisions_history(limit: int = 200, offset: int = 0):
    rows = []
    for cap_id_str, analysis in ANALYSIS_STORE.items():
        cap_id = int(cap_id_str)
        latest = _latest_action_for(cap_id)
        if latest:
            action, ts = latest
            rows.append({
                "capture_id": cap_id,
                "action": action,
                "updated_at": ts,
                "classification": (analysis.get("http_analysis") or {}).get("classification"),
                "origin_label": analysis.get("origin_label"),
                "risk": (analysis.get("http_analysis") or {}).get("riskscore", 0),
            })
    rows.sort(key=lambda x: x.get("updated_at",""), reverse=True)
    return rows[offset : offset + limit]

# -----------------------------------------------------------------------------
# UI routes
# -----------------------------------------------------------------------------
@app.get("/final_dashboard", response_class=HTMLResponse)
async def final_dashboard():
    path = Path("final_dashboard.html")
    if not path.exists():
        raise HTTPException(404, "final_dashboard.html not found")
    return HTMLResponse(path.read_text(encoding="utf-8"))

@app.get("/", response_class=HTMLResponse)
async def traffic_ui():
    # Single list with checkboxes and a batch “Send Selected to Analysis”
    html = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Traffic Captures</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    html, body { margin:0; padding:0; font-family: system-ui, sans-serif; background:#0b1020; color:#e8ebf3; }
    header { padding:12px 16px; background:#121a33; border-bottom:1px solid #1b2547; display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
    header h1 { font-size:18px; margin:0; color:#a6b3ff; }
    header .btn { background:#22305f; color:#e8ebf3; border:1px solid #2a3b7a; padding:8px 12px; border-radius:6px; cursor:pointer; }
    main { padding:16px; }
    .list { display:flex; flex-direction:column; gap:8px; }
    .row { display:grid; grid-template-columns: 28px 78px 1fr 80px 230px 110px; gap:10px; align-items:center; padding:10px; border:1px solid #1b2547; background:#0f1630; border-radius:10px; }
    .cell { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid #2a3b7a; background:#121a33; color:#a6b3ff; font-size:12px; }
    .method { min-width:70px; text-align:center; }
    .host { color:#c8d0ff; margin-right:6px; }
    .path { color:#9aa6d1; }
    .status-ok { color:#66e3a2; }
    .status-bad { color:#ff9e9e; }
    .muted { color:#9aa6d1; }
    .toolbar { display:flex; gap:8px; align-items:center; margin-bottom:12px; flex-wrap:wrap; }
    .checkbox { display:flex; justify-content:center; }
  </style>
</head>
<body>
  <header>
    <h1>Traffic Captures</h1>
    <button class="btn" onclick="selectAll()">Select All</button>
    <button class="btn" onclick="clearAll()">Clear</button>
    <button class="btn" onclick="sendSelected()">Send Selected to Analysis</button>
    <button class="btn" onclick="window.open('/final_dashboard','_blank')">Open Security Dashboard</button>
  </header>
  <main>
    <div class="toolbar muted">Select requests with the checkboxes, then send for analysis.</div>
    <div class="list" id="captures"></div>
  </main>

<script>
let selection = new Set();

async function fetchJSON(url, opts={}) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
}

function parseURL(u) {
  try {
    const x = new URL(u);
    return { host: x.host, path: x.pathname + (x.search||"") };
  } catch(e) {
    return { host: (u.split('/')[2] || u), path: u };
  }
}

function statusClass(code) {
  return code >= 200 && code < 400 ? "status-ok" : "status-bad";
}

function hintClassification(c) {
  if (!c) return "—";
  const s = c.toLowerCase();
  if (s.includes("llm") || s.includes("ai")) return "LLM";
  if (s.includes("bot") || s.includes("crawler") || s.includes("scrap")) return "BOT";
  return "HUMAN";
}

async function refreshCaptures() {
  const data = await fetchJSON('/captures?limit=200');
  const el = document.getElementById('captures');
  el.innerHTML = `
    <div class="row" style="background:#121a33;border-color:#1b2547;">
      <div class="cell"></div>
      <div class="cell"><span class="muted">Method</span></div>
      <div class="cell"><span class="muted">URL</span></div>
      <div class="cell"><span class="muted">Status</span></div>
      <div class="cell"><span class="muted">When</span></div>
      <div class="cell"><span class="muted">Hint</span></div>
    </div>
  `;
  data.forEach(c => {
    const req = c.request || {};
    const method = c.method || req.method || 'GET';
    const url = c.url || req.url || '/';
    const { host, path } = parseURL(url);
    const status = (c.response && c.response.status) || c.response_status || 0;
    const cls = (c.classification || '').trim();
    const id = c.id;
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML = `
      <div class="cell checkbox"><input type="checkbox" data-id="${id}" ${selection.has(id) ? 'checked' : ''} /></div>
      <div class="cell"><span class="pill method">${escapeHtml(method)}</span></div>
      <div class="cell">
        <span class="host">${escapeHtml(host||'')}</span>
        <span class="path">${escapeHtml(path.length>100?path.slice(0,100)+'…':path)}</span>
      </div>
      <div class="cell ${status?statusClass(status):'muted'}">${status||'—'}</div>
      <div class="cell muted">${new Date((c.received_at||Date.now())*1000).toLocaleString()}</div>
      <div class="cell"><span class="pill">${escapeHtml(hintClassification(cls))}</span></div>
    `;
    row.querySelector('input[type=checkbox]').addEventListener('change', (e)=>{
      const cid = Number(e.target.getAttribute('data-id'));
      if (e.target.checked) selection.add(cid); else selection.delete(cid);
    });
    el.appendChild(row);
  });
}

function selectAll() {
  document.querySelectorAll('#captures input[type=checkbox]').forEach(cb => {
    cb.checked = true;
    selection.add(Number(cb.getAttribute('data-id')));
  });
}

function clearAll() {
  document.querySelectorAll('#captures input[type=checkbox]').forEach(cb => cb.checked = false);
  selection.clear();
}

async function sendSelected() {
  if (!selection.size) return alert('Select at least one request');
  const ids = Array.from(selection);
  const res = await fetchJSON('/captures/sendforanalysis', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ ids })
  });
  clearAll();
  window.open(res.view_url || '/final_dashboard','_blank');
}

refreshCaptures();
setInterval(refreshCaptures, 5000);
</script>
</body>
</html>
    """
    return HTMLResponse(html)

if __name__ == "__main__":
    uvicorn.run("dashboard_app:app", host="127.0.0.1", port=9000, reload=True)
