# JA3 Toolkit

**Offline JA3/TLS Analysis & Fusion Demo**

This toolkit analyzes TLS sessions using JA3 fingerprints, integrates threat intelligence feeds, enriches with geo/ASN data, and produces actionable outputs for security analysis and ML. It is designed for offline/batch analysis of session data.

---

## Features

- **JA3 Extraction**: Builds JA3 strings/hashes from session TLS fields.
- **Threat Intelligence Fusion**: Tags sessions with known malicious or trusted JA3 hashes.
- **User-Agent & Header Heuristics**: Detects anomalies and spoofing.
- **Geo/ASN Cloud Mapping**: Enriches sessions with country, ASN, cloud provider, etc.
- **Decision Automation**: Fuses multiple signals for a final decision: `BLOCK`, `CHALLENGE`, or `ALLOW`.
- **Structured Outputs**: Generates CSVs for decisions, threat events, unknown JA3s, and ML features.

---

## Inputs

Place these files in the script directory or adjust paths in the code:

- `sessions.jsonl`  
  One session per line (JSON object). Fields needed: `session_id`, `timestamp`, `client_ip`, `http.headers`, `tls`.

- `known_bad_ja3.json`  
  Mapping: `ja3_hash` → label (malicious feed).

- `known_good_ja3.json`  
  Mapping: `ja3_hash` → label (trusted browsers).

- `ip_geo_asn.csv`  
  Mapping: `ip` → `country`, `asn`, `asn_name`, `is_cloud`.

---

## Outputs (in `./ja3_toolkit_out`)

- `decisions.csv`  
  Per-session decisions, metadata, and reason.

- `threat_intel_log.csv`  
  Events: matches to known bad JA3, unknown JA3 alerts.

- `unknown_ja3_alerts.csv`  
  First-seen unknown JA3 hashes.

- `features_for_ml.csv`  
  Structured features for ML training/analysis.

---

## Usage

1. **Prepare Feeds & Data**  
   - Use your own feeds or let the toolkit auto-generate sample files on first run.
   - You can use the sample `sessions.jsonl` structure output by running the script.

2. **Run the Script**
   ```bash
   python ja3_toolkit.py
   ```

3. **Review Outputs**
   - All output CSVs will be in `./ja3_toolkit_out`.

---

## Example Session Input (`sessions.jsonl`)

```json
{"session_id": "s1", "timestamp": "...", "client_ip": "203.0.113.45", "http": {"headers": {"User-Agent": "python-requests/2.28.1", ...}}, "tls": {"ssl_version":"771", ...}}
{"session_id": "s2", "timestamp": "...", "client_ip": "198.51.100.12", "http": {"headers": {"User-Agent": "...", ...}}, "tls": {...}}
```

---

## Customization

- **Feeds**: Update `known_bad_ja3.json` and `known_good_ja3.json` with your own threat intelligence or trusted fingerprints.
- **Geo/ASN**: Enrich `ip_geo_asn.csv` with your own IP intelligence.
- **Logic**: Adjust heuristics or decision fusion as needed in the script.

---

## Dependencies

- Python 3.x (no external packages needed; uses built-in modules: `os`, `json`, `csv`, `hashlib`, `datetime`).

---

## References

- [JA3 Fingerprinting](https://github.com/salesforce/ja3)
- [TLS Client Fingerprinting](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-2e4d14c6db4a)

---

## License

MIT

---

## Author

Bhavana725 and contributors.
