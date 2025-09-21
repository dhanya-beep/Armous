#!/usr/bin/env python3
"""
ja3_toolkit.py

Offline JA3 / TLS analysis + fusion demo script.

Inputs:
- sessions.jsonl           : one JSON object per line (contains session_id, timestamp, client_ip, http.headers, tls fields)
- known_bad_ja3.json       : mapping ja3_hash -> label (malicious feed)
- known_good_ja3.json      : mapping ja3_hash -> label (trusted browsers)
- ip_geo_asn.csv           : mapping ip -> country,asn,asn_name,is_cloud

Outputs (generated in ./ja3_toolkit_out):
- decisions.csv            : per-session decision + metadata
- threat_intel_log.csv     : events like MATCH_BAD_JA3, UNKNOWN_JA3
- unknown_ja3_alerts.csv   : first-seen unknown JA3 hashes
- features_for_ml.csv      : structured features per session for ML training/analysis

Usage:
- Provide sample sessions.jsonl or use the included sample structure from project notes.
- Adjust feed files (known_bad_ja3.json / known_good_ja3.json) with real values when available.
- Run: python ja3_toolkit.py
"""

import os
import json
import csv
import hashlib
from datetime import datetime
from collections import defaultdict

OUT_DIR = "./ja3_toolkit_out"
os.makedirs(OUT_DIR, exist_ok=True)

# --------------------------
# File paths (edit as needed)
# --------------------------
SESSIONS_PATH = "./sessions.jsonl"               # input: one JSON object per line
KNOWN_BAD_PATH = "./known_bad_ja3.json"          # input: ja3_hash -> label (malicious)
KNOWN_GOOD_PATH = "./known_good_ja3.json"        # input: ja3_hash -> label (benign)
IP_GEO_ASN_PATH = "./ip_geo_asn.csv"             # input: ip -> country,asn,asn_name,is_cloud

DECISIONS_CSV = os.path.join(OUT_DIR, "decisions.csv")
THREAT_LOG_CSV = os.path.join(OUT_DIR, "threat_intel_log.csv")
FEATURES_CSV = os.path.join(OUT_DIR, "features_for_ml.csv")
UNKNOWN_ALERTS_CSV = os.path.join(OUT_DIR, "unknown_ja3_alerts.csv")

# --------------------------
# Helpers: Loading/Saving
# --------------------------
def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def load_geoasn_map(path):
    m = {}
    if not os.path.exists(path):
        return m
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            m[row["ip"]] = {
                "country": row.get("country",""),
                "asn": row.get("asn",""),
                "asn_name": row.get("asn_name",""),
                "is_cloud": row.get("is_cloud","0") == "1"
            }
    return m

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

# --------------------------
# JA3 string/hash generation
# --------------------------
def ja3_string_from_tls(tls_obj: dict) -> str:
    # Expecting these keys: ssl_version, ciphers, extensions, elliptic_curves, ec_point_formats
    parts = [
        str(tls_obj.get("ssl_version", "")),
        str(tls_obj.get("ciphers", "")),
        str(tls_obj.get("extensions", "")),
        str(tls_obj.get("elliptic_curves", "")),
        str(tls_obj.get("ec_point_formats", ""))
    ]
    return ",".join(parts)

def ja3_hash_from_tls(tls_obj: dict) -> str:
    jstr = ja3_string_from_tls(tls_obj)
    return md5_hex(jstr), jstr

# --------------------------
# Small UA classifier (heuristic)
# --------------------------
def ua_family(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "python-requests" in ua or "requests" in ua and "python" in ua:
        return "python-requests"
    if "curl/" in ua:
        return "curl"
    if "headless" in ua or "puppeteer" in ua or "selenium" in ua or "playwright" in ua:
        return "headless-browser"
    if "chrome/" in ua and "safari/" in ua:
        return "chrome"
    if "firefox/" in ua:
        return "firefox"
    if "mozilla/" in ua and "windows" in ua:
        return "generic-browser"
    if ua.strip() == "":
        return "unknown"
    return "other"

# --------------------------
# JA3 family helper (from feed mappings)
# --------------------------
def ja3_family_from_feeds(jhash: str, bad_map: dict, good_map: dict) -> str:
    if jhash in bad_map:
        return bad_map[jhash]
    if jhash in good_map:
        return good_map[jhash]
    return "unknown"

# --------------------------
# Decision fusion logic
# --------------------------
def decide_action(flags: dict) -> (str, str):
    """
    flags: dictionary of booleans and contextual values:
      - is_known_bad_hash (bool)
      - spoof_mismatch (bool)
      - cloud_ip (bool)
      - ua_is_cli (bool)
      - hdr_missing_referer (bool)
      - hdr_content_type_anom (bool)
      - hdr_accept_lang_empty (bool)
    Returns: (decision, reason_str)
    """
    # Highest priority: definitive known bad JA3
    if flags.get("is_known_bad_hash"):
        return "BLOCK", "known_bad_ja3"

    # Spoofing + cloud or CLI: suspicious -> challenge
    if flags.get("spoof_mismatch") and (flags.get("cloud_ip") or flags.get("ua_is_cli")):
        return "CHALLENGE", "spoof_mismatch_and_cloud_or_cli"

    # Medium threshold: multiple anomalies -> challenge
    # sum up selected boolean flags (exclude is_known_bad_hash already handled)
    score = 0
    for k in ["spoof_mismatch", "cloud_ip", "ua_is_cli",
              "hdr_missing_referer", "hdr_content_type_anom", "hdr_accept_lang_empty"]:
        if flags.get(k):
            score += 1

    if score >= 3:
        reasons = [k for k,v in flags.items() if v and k in ["spoof_mismatch","cloud_ip","ua_is_cli","hdr_missing_referer","hdr_content_type_anom","hdr_accept_lang_empty"]]
        return "CHALLENGE", "multi_anomaly:" + ";".join(reasons)

    # default allow
    return "ALLOW", "clean"

# --------------------------
# Logging helpers
# --------------------------
def append_csv_row(path: str, fieldnames: list, row: dict):
    file_exists = os.path.exists(path)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def log_threat(event_type: str, session_id: str, ip: str, indicator: str, context: str):
    row = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": event_type,
        "session_id": session_id,
        "client_ip": ip,
        "indicator": indicator,
        "context": context
    }
    append_csv_row(THREAT_LOG_CSV, ["timestamp","type","session_id","client_ip","indicator","context"], row)

# --------------------------
# Main processing
# --------------------------
def process_sessions(sessions_path: str,
                     known_bad_path: str,
                     known_good_path: str,
                     geoasn_path: str):
    bad_map = load_json(known_bad_path)
    good_map = load_json(known_good_path)
    geo_map = load_geoasn_map(geoasn_path)

    # Track unknowns alerted
    unknown_alerted = set()

    # Prepare CSV headers (first run writes headers)
    # We'll use append_csv_row so no pre-creation needed

    with open(sessions_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                sess = json.loads(line)
            except Exception as e:
                print(f"Skipping invalid JSON line: {e}")
                continue

            sid = sess.get("session_id") or sess.get("id") or "unknown"
            ts = sess.get("timestamp") or datetime.utcnow().isoformat() + "Z"
            client_ip = sess.get("client_ip") or sess.get("ip") or ""
            http = sess.get("http", {})
            headers = http.get("headers", {}) if isinstance(http, dict) else {}
            tls = sess.get("tls", {}) or {}

            # 1) JA3 string + hash
            jstr = ja3_string_from_tls(tls)
            jhash = md5_hex(jstr)

            # 2) Feed membership checks
            is_bad = jhash in bad_map
            is_good = jhash in good_map

            # 3) UA family & ja3 family
            ua = headers.get("User-Agent","")
            fam_ua = ua_family(ua)
            fam_ja3 = ja3_family_from_feeds(jhash, bad_map, good_map)

            # 4) Spoof detection: UA says browser but JA3 indicates CLI/library, or vice versa
            spoof_mismatch = False
            if (fam_ua == "chrome" and fam_ja3 in ["python-requests","curl","headless-chrome-generic"]) or \
               (fam_ua in ["python-requests","curl","headless-browser"] and fam_ja3 in ["chrome","firefox","generic-browser"]):
                spoof_mismatch = True

            ua_cli = fam_ua in ["python-requests","curl"]

            # 5) Header anomalies heuristics
            hdr_missing_referer = headers.get("Referer","") == ""
            hdr_content_type_anom = False
            # Example heuristics: browser UA but Content-Type application/json on GET-like flow -> anomaly
            ct = headers.get("Content-Type","").lower()
            if fam_ua in ["chrome","firefox","generic-browser"] and ct in ["application/json",""]:
                hdr_content_type_anom = True
            if fam_ua in ["python-requests","curl"] and ct == "text/html":
                hdr_content_type_anom = True
            hdr_accept_lang_empty = headers.get("Accept-Language","").strip() == ""

            # 6) Geo/ASN enrichment (sample)
            geo = geo_map.get(client_ip, {})
            country = geo.get("country","")
            asn = geo.get("asn","")
            asn_name = geo.get("asn_name","")
            cloud_ip = geo.get("is_cloud", False)

            # 7) Threat feed events
            if is_bad:
                log_threat("MATCH_BAD_JA3", sid, client_ip, jhash, f"feed_label={bad_map.get(jhash,'unknown')}")
            elif not is_good:
                # first-seen unknown JA3 - alert once
                if jhash not in unknown_alerted:
                    unknown_alerted.add(jhash)
                    append_csv_row(UNKNOWN_ALERTS_CSV,
                                   ["first_seen","ja3_hash","example_session"],
                                   {"first_seen": datetime.utcnow().isoformat() + "Z",
                                    "ja3_hash": jhash,
                                    "example_session": sid})
                    log_threat("UNKNOWN_JA3", sid, client_ip, jhash, "first_seen_unknown_ja3")

            # 8) Decision fusion
            flags = {
                "is_known_bad_hash": bool(is_bad),
                "spoof_mismatch": bool(spoof_mismatch),
                "cloud_ip": bool(cloud_ip),
                "ua_is_cli": bool(ua_cli),
                "hdr_missing_referer": bool(hdr_missing_referer),
                "hdr_content_type_anom": bool(hdr_content_type_anom),
                "hdr_accept_lang_empty": bool(hdr_accept_lang_empty)
            }
            decision, reason = decide_action(flags)

            # 9) Append decision CSV
            decision_row = {
                "session_id": sid,
                "timestamp": ts,
                "client_ip": client_ip,
                "ja3": jstr,
                "ja3_hash": jhash,
                "ua": ua,
                "ua_family": fam_ua,
                "ja3_family": fam_ja3,
                "country": country,
                "asn": asn,
                "asn_name": asn_name,
                "cloud_ip": int(bool(cloud_ip)),
                "decision": decision,
                "reason": reason
            }
            append_csv_row(DECISIONS_CSV, list(decision_row.keys()), decision_row)

            # 10) Append features for ML
            features_row = {
                "session_id": sid,
                "ja3_hash": jhash,
                "ua_family": fam_ua,
                "is_known_bad_hash": int(bool(is_bad)),
                "spoof_mismatch": int(bool(spoof_mismatch)),
                "cloud_ip": int(bool(cloud_ip)),
                "country": country,
                "asn": asn,
                "hdr_missing_referer": int(bool(hdr_missing_referer)),
                "hdr_content_type_anom": int(bool(hdr_content_type_anom)),
                "hdr_accept_lang_empty": int(bool(hdr_accept_lang_empty))
            }
            append_csv_row(FEATURES_CSV, list(features_row.keys()), features_row)

    print("Processing complete.")
    print("Outputs written to:", OUT_DIR)
    print("- decisions.csv")
    print("- threat_intel_log.csv")
    print("- features_for_ml.csv")
    print("- unknown_ja3_alerts.csv")

# --------------------------
# If script run directly, provide a small guidance and optional sample generation
# --------------------------
if __name__ == "__main__":
    # If sessions.jsonl doesn't exist, create a small sample input to demonstrate usage.
    if not os.path.exists(SESSIONS_PATH):
        sample_sessions = [
            {
                "session_id": "s1",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "client_ip": "203.0.113.45",
                "http": {"headers": {"User-Agent": "python-requests/2.28.1", "Accept": "*/*", "Referer": "", "Content-Type": "application/json", "Accept-Language": "en-US,en;q=0.9"}},
                "tls": {"ssl_version":"771","ciphers":"4865-4866-4867-49195-49199-52393","extensions":"0-11-10-35-16","elliptic_curves":"23-24-25","ec_point_formats":"0"}
            },
            {
                "session_id": "s2",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "client_ip": "198.51.100.12",
                "http": {"headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36", "Accept": "text/html","Referer":"https://example.com/","Content-Type": ""}},
                "tls": {"ssl_version":"771","ciphers":"4865-4866-4867-4868-49195-49199","extensions":"0-11-10-16-35-43-45-51","elliptic_curves":"29-23-24-25","ec_point_formats":"0"}
            }
        ]
        with open(SESSIONS_PATH, "w") as f:
            for s in sample_sessions:
                f.write(json.dumps(s) + "\n")
        print(f"Sample sessions.jsonl created at: {SESSIONS_PATH}")

    # Ensure sample known_bad/known_good files exist (small placeholders)
    if not os.path.exists(KNOWN_BAD_PATH):
        sample_bad = {
            # placeholder hashes - replace with real feed hashes when available
            "b1a2f0e5f5a0c1d2e3f4a5b6c7d8e9f0": "python-requests",
            "9c1f8b0d2e3a4b5c6d7e8f9a0b1c2d3e": "curl"
        }
        with open(KNOWN_BAD_PATH, "w") as f:
            json.dump(sample_bad, f, indent=2)
        print(f"Sample known_bad_ja3.json created at: {KNOWN_BAD_PATH}")

    if not os.path.exists(KNOWN_GOOD_PATH):
        sample_good = {
            "11111111111111111111111111111111": "chrome-stable",
            "22222222222222222222222222222222": "firefox-stable"
        }
        with open(KNOWN_GOOD_PATH, "w") as f:
            json.dump(sample_good, f, indent=2)
        print(f"Sample known_good_ja3.json created at: {KNOWN_GOOD_PATH}")

    # Create sample geo/asn CSV if missing
    if not os.path.exists(IP_GEO_ASN_PATH):
        with open(IP_GEO_ASN_PATH, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip","country","asn","asn_name","is_cloud"])
            writer.writeheader()
            writer.writerow({"ip":"203.0.113.45","country":"US","asn":"AS14618","asn_name":"AMAZON-AES","is_cloud":"1"})
            writer.writerow({"ip":"198.51.100.12","country":"IN","asn":"AS24560","asn_name":"BhartiAirtel","is_cloud":"0"})
        print(f"Sample ip_geo_asn.csv created at: {IP_GEO_ASN_PATH}")

    # Initialize empty output CSVs (so append works orderly)
    for p, flds in [
        (DECISIONS_CSV, ["session_id","timestamp","client_ip","ja3","ja3_hash","ua","ua_family","ja3_family","country","asn","asn_name","cloud_ip","decision","reason"]),
        (THREAT_LOG_CSV, ["timestamp","type","session_id","client_ip","indicator","context"]),
        (FEATURES_CSV, ["session_id","ja3_hash","ua_family","is_known_bad_hash","spoof_mismatch","cloud_ip","country","asn","hdr_missing_referer","hdr_content_type_anom","hdr_accept_lang_empty"]),
        (UNKNOWN_ALERTS_CSV, ["first_seen","ja3_hash","example_session"])
    ]:
        if not os.path.exists(p):
            with open(p, "w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=flds)
                writer.writeheader()

    # Run processing
    process_sessions(SESSIONS_PATH, KNOWN_BAD_PATH, KNOWN_GOOD_PATH, IP_GEO_ASN_PATH)
