# capture_playwright.py
# Unified Playwright traffic capture that posts normalized JSON to the dashboard.

import asyncio
import base64
import json
import time
from pathlib import Path

import httpx
from playwright.async_api import async_playwright

# Config
DASHBOARD_CAPTURE_URL = "http://127.0.0.1:9000/capture"  # dashboard receiver
LOCAL_STORE_FILE = "captures.json"                       # local persistent store
MAX_BODY_BYTES = 2 * 1024 * 1024                         # limit huge bodies (2 MB)

# ---------------------------------------------------------------------------
# Heuristic classification (human-like / bot-like / llm-like)
# ---------------------------------------------------------------------------
def classify_capture(capture: dict) -> str:
    """
    capture: dict with keys method, url, headers, request_body_text, response_body_text, resource_type
    returns: label string
    """
    url = (capture.get("url") or "").lower()
    headers = capture.get("headers") or {}
    ua = ""
    if isinstance(headers, dict):
        ua = headers.get("user-agent", "") or headers.get("User-Agent", "") or ""

    # Heuristic #1: common LLM endpoints
    llm_indicators = [
        "/v1/chat/completions", "/v1/completions", "api.openai.com",
        "replicate.com", "/v1/engines", "gpt", "openai", "anthropic", "cohere"
    ]
    for term in llm_indicators:
        if term in url:
            return "llm-like"

    # Heuristic #2: JSON POST with long text or LLM-shaped fields
    body = capture.get("request_body_text") or ""
    ctype = (headers.get("content-type", "") + headers.get("Content-Type", "")).lower()
    if capture.get("method", "").upper() in ("POST", "PUT") and "application/json" in ctype:
        if len(body) > 200 or '"messages"' in body or '"prompt"' in body:
            return "llm-like"

    # Heuristic #3: Bot-like UAs
    bot_ua_terms = ["python-requests", "python-urllib", "golang", "node-fetch", "aws-sdk", "java/", "curl/"]
    for t in bot_ua_terms:
        if t in ua.lower():
            return "bot-like"

    # Heuristic #4: Missing common browser headers
    if not headers.get("accept") and not headers.get("Accept"):
        return "bot-like"

    return "human-likely"

# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
async def persist_local(capture: dict):
    """Append capture to local JSON file (simple append)."""
    p = Path(LOCAL_STORE_FILE)
    arr = []
    if p.exists():
        try:
            arr = json.loads(p.read_text(encoding="utf8") or "[]")
        except Exception:
            arr = []
    arr.append(capture)
    p.write_text(json.dumps(arr, indent=2), encoding="utf8")

async def send_to_dashboard(capture: dict):
    """POST capture JSON to dashboard; tolerant of failures."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.post(DASHBOARD_CAPTURE_URL, json=capture)
            if r.status_code not in (200, 201):
                print(f"[dashboard] non-200: {r.status_code} {r.text[:200]}")
    except Exception as e:
        print("[dashboard] send error:", e)

# ---------------------------------------------------------------------------
# Playwright runner
# ---------------------------------------------------------------------------
async def run_capture(headless: bool = False, keep_open: bool = True):
    async with async_playwright() as p:
        # Use Chromium for maximal compatibility
        browser = await p.chromium.launch(
            headless=headless,
            args=["--disable-features=IsolateOrigins,site-per-process"]
        )
        context = await browser.new_context()
        page = await context.new_page()

        # Map request-id -> {request, response}
        in_progress = {}

        # ---- Request handler ----
        async def on_request(req):
            try:
                req_info = {
                    "timestamp": time.time(),
                    "request_id": getattr(req._impl_obj, "_guid", None),  # internal guid
                    "url": req.url,
                    "method": req.method,
                    "resource_type": req.resource_type,
                    "headers": dict(req.headers),
                    "post_data_b64": None,
                    "request_body_text": None,
                }

                # Acquire post data safely
                try:
                    post = req.post_data
                    d = post() if callable(post) else post
                    if d:
                        if isinstance(d, bytes):
                            b = d
                        else:
                            b = d.encode() if isinstance(d, str) else str(d).encode()
                        if len(b) > MAX_BODY_BYTES:
                            req_info["post_data_b64"] = None
                            req_info["request_body_text"] = "[TOO_LARGE]"
                        else:
                            req_info["post_data_b64"] = base64.b64encode(b).decode()
                            try:
                                req_info["request_body_text"] = b.decode("utf8", errors="replace")
                            except Exception:
                                req_info["request_body_text"] = None
                except Exception:
                    # not all requests expose post data
                    pass

                in_progress[req_info["request_id"]] = {"request": req_info, "response": None}
            except Exception as e:
                print("on_request error:", e)

        # ---- Response handler ----
        async def on_response(resp):
            try:
                # match to originating request
                req = resp.request
                req_id = getattr(req._impl_obj, "_guid", None)
                obj = in_progress.get(req_id, {"request": None, "response": None})

                response_body_b64 = None
                response_text = None
                try:
                    b = await resp.body()
                    if b:
                        if len(b) > MAX_BODY_BYTES:
                            response_text = "[TOO_LARGE]"
                            response_body_b64 = None
                        else:
                            response_body_b64 = base64.b64encode(b).decode()
                            try:
                                response_text = b.decode("utf8", errors="replace")
                            except Exception:
                                response_text = None
                except Exception:
                    # body not available (aborted / opaque)
                    response_text = None

                resp_info = {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "response_body_b64": response_body_b64,
                    "response_body_text": response_text,
                }
                obj["response"] = resp_info

                # Build final capture with both nested and top-level fields for compatibility
                req_info = obj["request"] or {}
                capture = {
                    "captured_at": time.time(),
                    "request": req_info,
                    "response": obj["response"],
                    "page_url": page.url,
                    # top-level duplicates (server normalizes either shape)
                    "method": req_info.get("method"),
                    "url": req_info.get("url"),
                    "headers": req_info.get("headers"),
                    "resource_type": req_info.get("resource_type"),
                    "request_body_text": req_info.get("request_body_text"),
                    "response_status": resp_info.get("status"),
                    "response_body_text": resp_info.get("response_body_text"),
                }

                # Heuristic label
                flat_for_label = {
                    "url": capture["url"],
                    "method": capture["method"],
                    "headers": capture["headers"],
                    "request_body_text": capture["request_body_text"],
                    "response_body_text": capture["response_body_text"],
                    "resource_type": capture["resource_type"],
                }
                capture["classification"] = classify_capture(flat_for_label)

                # Persist and publish
                await persist_local(capture)
                await send_to_dashboard(capture)

                # Cleanup
                in_progress.pop(req_id, None)
                print(f"[captured] {capture['method']} {capture['url']} -> {capture['classification']}")
            except Exception as e:
                print("on_response error:", e)

        # Attach listeners
        context.on("request", lambda r: asyncio.create_task(on_request(r)))
        context.on("response", lambda r: asyncio.create_task(on_response(r)))

        # Open a neutral page; interact manually to generate traffic
        await page.goto("about:blank")
        print("Playwright launched; browse in the opened window and traffic will be posted to", DASHBOARD_CAPTURE_URL)

        # Keep alive for manual browsing
        if keep_open:
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\nInterrupted, closing browser...")
        await browser.close()

if __name__ == "__main__":
    # Headful by default so you can interact with pages
    asyncio.run(run_capture(headless=False, keep_open=True))
