#!/usr/bin/env python
"""
cert_bund_analyzer.py — CERT-Bund Django Web Application
=========================================================
Consolidated single-file Django web app: UI, routing, models, and views.
All analysis logic lives in analysis_engine.py.

Usage:
    python cert_bund_analyzer.py              # starts dev server on port 8000
    python cert_bund_analyzer.py runserver 9000
"""

import sys
import os
import json
import logging
import shutil
import csv
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# Third-party — only needed for OSINT and Word report features.
# Install via:  pip install requests beautifulsoup4 python-docx
try:
    import requests
    from bs4 import BeautifulSoup
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    from docx import Document
    _DOCX_OK = True
except ImportError:
    _DOCX_OK = False

# ── Constants ─────────────────────────────────────────────────────────────────

HEADERS = {"User-Agent": "Mozilla/5.0"}
DUCKDUCKGO_URL = "https://html.duckduckgo.com/html/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_RETRIES = 3
REQUEST_BACKOFF = 2   # seconds between retries (multiplied by attempt number)

CSV_FIELDNAMES = [
    "asn", "ip", "timestamp", "malware",
    "src_port", "dst_ip", "dst_port", "dst_host", "proto",
]

# Malware families already covered in the CERT-Bund knowledge base.
# Entries are lowercase for case-insensitive matching.
DEFAULT_KNOWN_MALWARE = {
    "m0yv", "vipersoftx", "pykspa", "android.vo1d2", "pseudo_manuscrypt",
    "andromeda", "ranbyus", "tinba", "nymaim", "prometei", "lumma",
    "ghostweaver", "zeus", "corebot", "trusteer", "urlzone", "teslacrypt",
}

# ── Row helpers ───────────────────────────────────────────────────────────────

def extract_operator_name(asn_str: str) -> str:
    """
    Strip the ASN number prefix so the dashboard shows the operator name only.
    'AS3320 Deutsche Telekom' → 'Deutsche Telekom'
    Returns the original string if no space found.
    """
    parts = asn_str.split(' ', 1)
    return parts[1].strip() if len(parts) > 1 else asn_str

def _ensure_https(url: str) -> str:
    if url.startswith('http://'):
        return 'https://' + url[7:]
    return url

def make_fingerprint(row: dict) -> str:
    """
    Create a deduplication key for a CSV row.
    Rows that share the same victim-IP -> destination-IP/port/malware tuple
    are considered duplicates and will be skipped on subsequent files.
    """
    return f"{row['ip']}|{row['dst_ip']}|{row['dst_port']}|{row['malware']}"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_post_with_retry(url: str, headers: dict, data: dict, timeout: int = 20):
    """
    POST *data* to *url* with up to REQUEST_RETRIES attempts.
    Returns the Response object or None on total failure.
    """
    if not _REQUESTS_OK:
        log.error("'requests' library not installed — HTTP POST disabled.")
        return None
    url = _ensure_https(url)
    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            resp = requests.post(url, headers=headers, data=data, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            log.warning("HTTP POST attempt %d/%d failed: %s", attempt, REQUEST_RETRIES, exc)
            if attempt < REQUEST_RETRIES:
                time.sleep(REQUEST_BACKOFF * attempt)
    return None

def http_get_with_retry(url: str, headers: dict, params: dict = None, timeout: int = 20):
    """GET with up to REQUEST_RETRIES attempts. Returns Response or None."""
    if not _REQUESTS_OK:
        log.error("'requests' not installed — HTTP GET unavailable.")
        return None
    url = _ensure_https(url)
    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            resp = requests.get(url, headers=headers, params=params or {}, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            log.warning("HTTP GET attempt %d/%d failed: %s", attempt, REQUEST_RETRIES, exc)
            if attempt < REQUEST_RETRIES:
                time.sleep(REQUEST_BACKOFF * attempt)
    return None


# ── OSINT: DuckDuckGo search ──────────────────────────────────────────────────

def search_malware_info(malware: str) -> dict | None:
    """
    Query DuckDuckGo for open-source threat-intelligence on *malware*.

    Returns a dict with keys:
        Summary, Description, References, Remediation
    or None if the query failed or returned no useful results.
    """
    query = f"{malware} malware threat analysis"
    response = http_post_with_retry(DUCKDUCKGO_URL, HEADERS, {"q": query})
    if response is None:
        return None

    try:
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("div", class_="result")[:5]

        summary = ""
        description = ""
        references = []
        seen_snippets = set()

        for r in results:
            title_tag   = r.find("a", class_="result__a")
            snippet_tag = r.find("a", class_="result__snippet")
            if not title_tag:
                continue
            title   = title_tag.get_text(strip=True)
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
            link    = title_tag.get("href", "")

            snippet_key = snippet.lower().strip()
            if not snippet_key or snippet_key in seen_snippets:
                continue
            seen_snippets.add(snippet_key)

            combined = f"{title}: {snippet}"
            if not summary:
                summary = combined
            description += combined + "\n\n"
            references.append(link)

        return {
            "Summary":     summary     or "No summary available.",
            "Description": description.strip() or "No description available.",
            "References":  "\n".join(references) if references else "No references found.",
            "Remediation": "Isolate affected systems and block all identified indicators.",
        }
    except Exception as exc:
        log.error("Failed to parse OSINT results for %s: %s", malware, exc)
        return None


# ── Word report generation ────────────────────────────────────────────────────

def create_word_report(malware: str, intel: dict, folder: str) -> str:
    """
    Write a .docx threat-intelligence report for *malware* into *folder*.
    Returns the path to the created file.
    Requires the python-docx package.
    """
    if not _DOCX_OK:
        log.error("'python-docx' not installed — Word report generation disabled.")
        return ""

    doc = Document()
    doc.add_heading(f"Malware Threat Report: {malware}", 0)
    for section, content in intel.items():
        doc.add_heading(section, level=1)
        doc.add_paragraph(content)

    safe = malware.replace("/", "_").replace("\\", "_")
    path = os.path.join(folder, f"{safe}.docx")
    doc.save(path)
    log.info("Word report created: %s", path)
    return path


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def check_ip_abuseipdb(ip: str, api_key: str) -> dict | None:
    if not api_key or not _REQUESTS_OK: return None
    resp = http_get_with_retry(
        ABUSEIPDB_URL,
        headers={'Accept': 'application/json', 'Key': api_key},
        params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True},
    )
    if resp:
        try: return resp.json().get('data')
        except: pass
    return None

def run_abuseipdb_checks(ip_list: list, api_key: str, output_dir: str) -> list:
    if not api_key or not ip_list: return []
    log.info('Running AbuseIPDB checks for %d IPs…', len(ip_list))
    results = []
    for ip in ip_list:
        data = check_ip_abuseipdb(ip, api_key)
        if data:
            results.append({
                'ip': ip, 'abuseScore': data.get('abuseConfidenceScore', 0),
                'country': data.get('countryCode', ''), 'isp': data.get('isp', ''),
                'domain': data.get('domain', ''), 'totalReports': data.get('totalReports', 0),
            })
        time.sleep(0.5)
    if results:
        path = os.path.join(output_dir, 'abuseipdb_report.csv')
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            w.writeheader()
            w.writerows(results)
    return results

# ── On-demand ZIP packaging ───────────────────────────────────────────────────

def create_results_zip(output_dir: str) -> str:
    ts = datetime.now().strftime('%Y-%m-%d_%H-%M')
    zip_path = os.path.join(output_dir, f'results_{ts}.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(output_dir):
            for fname in files:
                if fname.endswith('.zip'): continue
                full = os.path.join(root, fname)
                arcname = os.path.relpath(full, output_dir)
                zf.write(full, arcname)
    return zip_path

# ── CSV parsing ───────────────────────────────────────────────────────────────

def parse_csv_file(
    file_path: str,
    seen_combos: set,
    seen_this_run: set,
    known_malware: set,
) -> tuple[list[dict], set[str], set[str]]:
    """
    Read one CERT-Bund CSV file and return only *new* (non-duplicate) rows.
    """
    new_rows = []
    new_fingerprints = set()
    new_malware_set = set()

    try:
        with open(file_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Normalise: strip whitespace, fill missing fields with ""
                clean = {k: (row.get(k) or "").strip() for k in CSV_FIELDNAMES}
                if not clean["asn"]:
                    continue  # skip empty/header rows

                fp = make_fingerprint(clean)
                if fp in seen_combos or fp in seen_this_run:
                    continue  # duplicate — skip

                seen_this_run.add(fp)
                new_rows.append(clean)
                new_fingerprints.add(fp)

                malware_lower = clean["malware"].lower()
                if clean["malware"] and malware_lower not in known_malware:
                    new_malware_set.add(clean["malware"])

    except Exception as exc:
        log.error("Error reading %s: %s", file_path, exc)

    return new_rows, new_fingerprints, new_malware_set


# ── Core analysis pipeline ────────────────────────────────────────────────────

def run_analysis(
    uploaded_files: list[tuple[str, str]],
    output_dir: str,
    run_osint: bool = False,
    known_malware: set = None,
    abuseipdb_key: str = "",
) -> dict:
    """
    Full analysis pipeline. Does NOT create a ZIP (call create_results_zip for that).
    """
    if known_malware is None: known_malware = DEFAULT_KNOWN_MALWARE
    os.makedirs(output_dir, exist_ok=True)

    seen_combos = set()
    seen_this_run = set()
    all_rows = []

    # ── 1. Parse every uploaded file ─────────────────────────────────────────
    for orig_name, tmp_path in uploaded_files:
        new_rows, new_fps, _ = parse_csv_file(tmp_path, seen_combos, seen_this_run, known_malware)
        seen_combos.update(new_fps)
        all_rows.extend(new_rows)

    # ── 2. Return early if nothing was parsed ─────────────────────────────────
    if not all_rows:
        return {
            "total_rows":      0,
            "unique_asns":     0,
            "unique_malwares": 0,
            "unique_ips":      0,
            "asn_stats":       [],
            "malware_stats":   [],
            "ip_stats":        [],
            "output_dir":      output_dir,
        }

    # ── 3. Aggregate statistics ───────────────────────────────────────────────
    asn_counter     = Counter(r["asn"]     for r in all_rows)
    malware_counter = Counter(r["malware"] for r in all_rows if r["malware"])
    ip_counter      = Counter(r["ip"]      for r in all_rows if r["ip"])

    top_asns     = asn_counter.most_common(10)
    top_malwares = malware_counter.most_common(10)
    top_ips      = ip_counter.most_common(10)

    asn_stats     = [{"label": extract_operator_name(k), "count": v} for k, v in top_asns]
    malware_stats = [{"label": k, "count": v} for k, v in top_malwares]
    ip_stats      = [{"label": k, "count": v} for k, v in top_ips]

    # ── 4. Write per-ASN CSV files ────────────────────────────────────────────
    rows_by_asn = defaultdict(list)
    for row in all_rows:
        rows_by_asn[row["asn"]].append(row)

    for asn, rows in rows_by_asn.items():
        safe    = asn.replace("/", "_").replace("\\", "_")
        asn_dir = os.path.join(output_dir, safe)
        os.makedirs(asn_dir, exist_ok=True)

        csv_path = os.path.join(asn_dir, f"{safe}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

    # ── 5. Write combined CSV ─────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    combined_csv = os.path.join(output_dir, f"all_asns_{ts}.csv")
    with open(combined_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for asn in sorted(rows_by_asn.keys()):
            writer.writerows(rows_by_asn[asn])

    log.info("Combined CSV written: %s", combined_csv)

    # ── 6. Optional AbuseIPDB and OSINT ───────────────────────────────────────
    if abuseipdb_key:
        run_abuseipdb_checks([i["label"] for i in ip_stats], abuseipdb_key, output_dir)

    if run_osint:
        unknown_malwares = set()
        for row in all_rows:
            ml = row["malware"].lower()
            if row["malware"] and ml not in known_malware:
                unknown_malwares.add(row["malware"])

        for malware in unknown_malwares:
            log.info("Running OSINT query for: %s", malware)
            intel = search_malware_info(malware)
            if intel:
                create_word_report(malware, intel, output_dir)

    return {
        "total_rows":      len(all_rows),
        "unique_asns":     len(asn_counter),
        "unique_malwares": len(malware_counter),
        "unique_ips":      len(ip_counter),
        "asn_stats":       asn_stats,
        "malware_stats":   malware_stats,
        "ip_stats":        ip_stats,
        "output_dir":      output_dir,
    }


# ── Logging ───────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cert_bund_web")

# ─────────────────────────────────────────────────────────────────────────────
# CSS (embedded)
# ─────────────────────────────────────────────────────────────────────────────

CSS_CONTENT = """
/* =====================================================
   CERT-Bund Analyzer — Premium Dark Cyber Theme
   ===================================================== */

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

/* ── Variables ─────────────────────────────────────── */
:root {
  --bg-base:      #08090d;
  --bg-card:      rgba(15, 17, 26, 0.85);
  --bg-elevated:  rgba(20, 23, 36, 0.9);
  --border:       rgba(255,255,255,0.07);
  --border-glow:  rgba(99, 209, 159, 0.35);

  --emerald:      #10d97a;
  --emerald-dim:  #0ea862;
  --cyan:         #22d3ee;
  --violet:       #a78bfa;
  --rose:         #f43f5e;
  --amber:        #f59e0b;

  --text-primary:   #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted:     #475569;

  --radius-sm: 8px;
  --radius-md: 14px;
  --radius-lg: 20px;
  --radius-xl: 28px;

  --shadow-card: 0 4px 32px rgba(0,0,0,0.45), 0 0 0 1px var(--border);
  --shadow-glow: 0 0 40px rgba(16,217,122,0.12);
  --transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
}

/* ── Reset ─────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Inter', system-ui, sans-serif;
  background: var(--bg-base);
  color: var(--text-primary);
  min-height: 100vh;
  overflow-x: hidden;
  -webkit-font-smoothing: antialiased;
}

/* ── Animated Background Mesh ──────────────────────── */
.bg-mesh {
  position: fixed; inset: 0; z-index: 0; overflow: hidden; pointer-events: none;
}
.bg-mesh::before {
  content: ''; position: absolute; top: -20%; left: -10%;
  width: 70vw; height: 70vw;
  background: radial-gradient(circle, rgba(16,217,122,0.06) 0%, transparent 65%);
  animation: drift 18s ease-in-out infinite alternate;
}
.bg-mesh::after {
  content: ''; position: absolute; bottom: -20%; right: -10%;
  width: 60vw; height: 60vw;
  background: radial-gradient(circle, rgba(167,139,250,0.07) 0%, transparent 65%);
  animation: drift 22s ease-in-out infinite alternate-reverse;
}
@keyframes drift {
  from { transform: translate(0, 0) scale(1); }
  to   { transform: translate(3%, 5%) scale(1.05); }
}
.bg-grid {
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px);
  background-size: 48px 48px;
}
.page-content { position: relative; z-index: 1; }

/* ── Navbar ────────────────────────────────────────── */
.navbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1rem 2.5rem;
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  background: rgba(8,9,13,0.7);
  position: sticky; top: 0; z-index: 50;
}
.navbar-brand { display: flex; align-items: center; gap: 0.75rem; text-decoration: none; }
.brand-icon {
  width: 38px; height: 38px;
  background: linear-gradient(135deg, var(--emerald), var(--cyan));
  border-radius: var(--radius-sm);
  display: flex; align-items: center; justify-content: center;
  font-size: 1.1rem;
  box-shadow: 0 0 16px rgba(16,217,122,0.4);
}
.brand-name {
  font-size: 1.05rem; font-weight: 700; letter-spacing: -0.02em;
  background: linear-gradient(135deg, #fff 40%, var(--emerald));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.brand-name span { font-weight: 300; }
.navbar-actions { display: flex; align-items: center; gap: 1rem; }
.user-badge {
  display: flex; align-items: center; gap: 0.5rem;
  background: var(--bg-elevated); border: 1px solid var(--border);
  padding: 0.4rem 0.9rem; border-radius: 999px;
  font-size: 0.82rem; color: var(--text-secondary);
}
.user-badge .dot {
  width: 7px; height: 7px; background: var(--emerald);
  border-radius: 50%; box-shadow: 0 0 6px var(--emerald);
  animation: pulse-dot 2s ease infinite;
}
@keyframes pulse-dot {
  0%,100% { opacity: 1; transform: scale(1); }
  50%      { opacity: 0.6; transform: scale(1.3); }
}

/* ── Buttons ───────────────────────────────────────── */
.btn {
  display: inline-flex; align-items: center; gap: 0.5rem;
  padding: 0.6rem 1.4rem; border-radius: var(--radius-sm);
  font-size: 0.88rem; font-weight: 600; font-family: inherit;
  cursor: pointer; text-decoration: none; border: none;
  transition: var(--transition);
}
.btn-primary {
  background: linear-gradient(135deg, var(--emerald), var(--emerald-dim));
  color: #0a1a0f; box-shadow: 0 0 20px rgba(16,217,122,0.3);
}
.btn-primary:hover { transform: translateY(-2px); box-shadow: 0 0 32px rgba(16,217,122,0.5); }
.btn-primary:active { transform: translateY(0); }
.btn-ghost { background: transparent; color: var(--text-secondary); border: 1px solid var(--border); }
.btn-ghost:hover { border-color: rgba(255,255,255,0.2); color: var(--text-primary); }
.btn-danger { background: rgba(244,63,94,0.12); color: var(--rose); border: 1px solid rgba(244,63,94,0.25); }
.btn-danger:hover { background: rgba(244,63,94,0.22); }
.btn-lg { padding: 0.85rem 2rem; font-size: 0.95rem; border-radius: var(--radius-md); }
.btn-full { width: 100%; justify-content: center; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none !important; }

/* ── Cards ─────────────────────────────────────────── */
.card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px); box-shadow: var(--shadow-card);
  transition: var(--transition);
}
.card:hover { box-shadow: var(--shadow-card), var(--shadow-glow); }
.card-body { padding: 2rem; }
.card-header { padding: 1.5rem 2rem; border-bottom: 1px solid var(--border); }

/* ── Login Overlay ─────────────────────────────────── */
#login-overlay {
  position: fixed; inset: 0; z-index: 1000;
  display: flex; align-items: center; justify-content: center; padding: 1rem;
}
.login-backdrop {
  position: absolute; inset: 0; background: rgba(8,9,13,0.75);
  backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
}
.login-modal {
  position: relative; z-index: 1; width: 100%; max-width: 440px;
  background: var(--bg-elevated); border: 1px solid var(--border);
  border-radius: var(--radius-xl);
  box-shadow: 0 32px 80px rgba(0,0,0,0.6), 0 0 0 1px var(--border), 0 0 60px rgba(16,217,122,0.08);
  overflow: hidden;
  animation: modal-enter 0.4s cubic-bezier(0.34,1.56,0.64,1) forwards;
}
@keyframes modal-enter {
  from { opacity: 0; transform: scale(0.9) translateY(20px); }
  to   { opacity: 1; transform: scale(1) translateY(0); }
}
.login-header {
  padding: 2.5rem 2.5rem 1.5rem; text-align: center;
  background: linear-gradient(180deg, rgba(16,217,122,0.06) 0%, transparent 100%);
}
.login-logo {
  width: 64px; height: 64px;
  background: linear-gradient(135deg, var(--emerald), var(--cyan));
  border-radius: var(--radius-md);
  display: flex; align-items: center; justify-content: center;
  font-size: 1.8rem; margin: 0 auto 1.25rem;
  box-shadow: 0 0 32px rgba(16,217,122,0.45);
}
.login-title {
  font-size: 1.5rem; font-weight: 800; letter-spacing: -0.03em;
  background: linear-gradient(135deg, #fff 50%, var(--emerald));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  margin-bottom: 0.4rem;
}
.login-subtitle { color: var(--text-muted); font-size: 0.85rem; }
.login-body { padding: 1.5rem 2.5rem 2.5rem; }
.form-group { margin-bottom: 1.25rem; }
.form-label {
  display: block; font-size: 0.8rem; font-weight: 600;
  color: var(--text-secondary); text-transform: uppercase;
  letter-spacing: 0.08em; margin-bottom: 0.5rem;
}
.form-control {
  width: 100%; padding: 0.75rem 1rem;
  background: rgba(255,255,255,0.04); border: 1px solid var(--border);
  border-radius: var(--radius-sm); color: var(--text-primary);
  font-size: 0.92rem; font-family: inherit; outline: none;
  transition: var(--transition);
}
.form-control:focus {
  border-color: var(--emerald);
  box-shadow: 0 0 0 3px rgba(16,217,122,0.15);
  background: rgba(16,217,122,0.04);
}
.form-control::placeholder { color: var(--text-muted); }
.form-error {
  background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.3);
  color: #fda4af; border-radius: var(--radius-sm);
  padding: 0.65rem 1rem; font-size: 0.83rem;
  margin-bottom: 1.25rem; display: none;
}

/* ── Upload Zone ───────────────────────────────────── */
.upload-section { min-height: 100vh; display: flex; flex-direction: column; }
.upload-container {
  flex: 1; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  padding: 3rem 2rem; gap: 2rem;
  max-width: 720px; margin: 0 auto; width: 100%;
}
.upload-title { text-align: center; }
.upload-title h1 {
  font-size: 2.2rem; font-weight: 800; letter-spacing: -0.04em;
  background: linear-gradient(135deg, #fff 50%, var(--emerald));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  margin-bottom: 0.5rem;
}
.upload-title p { color: var(--text-secondary); font-size: 0.95rem; }
.drop-zone {
  width: 100%; border: 2px dashed rgba(16,217,122,0.25);
  border-radius: var(--radius-xl); padding: 4rem 2rem;
  text-align: center; cursor: pointer; transition: var(--transition);
  background: rgba(16,217,122,0.02); position: relative; overflow: hidden;
}
.drop-zone::before {
  content: ''; position: absolute; inset: 0;
  background: radial-gradient(ellipse at center, rgba(16,217,122,0.04) 0%, transparent 70%);
  opacity: 0; transition: opacity 0.3s;
}
.drop-zone:hover, .drop-zone.dragover {
  border-color: var(--emerald);
  box-shadow: 0 0 40px rgba(16,217,122,0.15), inset 0 0 40px rgba(16,217,122,0.04);
}
.drop-zone:hover::before, .drop-zone.dragover::before { opacity: 1; }
.drop-zone.dragover { background: rgba(16,217,122,0.05); }
.drop-icon {
  font-size: 3.5rem; margin-bottom: 1.5rem; display: block;
  filter: drop-shadow(0 0 16px rgba(16,217,122,0.5));
  animation: float 3s ease-in-out infinite;
}
@keyframes float {
  0%,100% { transform: translateY(0); }
  50%      { transform: translateY(-8px); }
}
.drop-zone h3 { font-size: 1.25rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem; }
.drop-zone p  { color: var(--text-secondary); font-size: 0.88rem; margin-bottom: 1.5rem; }
.drop-zone .hint { color: var(--text-muted); font-size: 0.78rem; margin-top: 0.75rem; }
#folder-input { display: none; }

.file-list { width: 100%; display: none; }
.file-list.visible { display: block; }
.file-list-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }
.file-list-header h3 { font-size: 0.95rem; font-weight: 600; color: var(--text-primary); }
.file-count-badge {
  background: rgba(16,217,122,0.15); color: var(--emerald);
  border-radius: 999px; padding: 0.2rem 0.65rem;
  font-size: 0.78rem; font-weight: 700; font-family: 'JetBrains Mono', monospace;
}
.file-list-items {
  background: var(--bg-elevated); border: 1px solid var(--border);
  border-radius: var(--radius-md); max-height: 220px; overflow-y: auto;
  scrollbar-width: thin; scrollbar-color: var(--border) transparent;
}
.file-item {
  display: flex; align-items: center; gap: 0.75rem;
  padding: 0.65rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.82rem;
}
.file-item:last-child { border-bottom: none; }
.file-item-icon { color: var(--emerald); font-size: 0.9rem; }
.file-item-name { color: var(--text-secondary); flex: 1; font-family: 'JetBrains Mono', monospace; }
.file-item-size { color: var(--text-muted); font-size: 0.75rem; }

.upload-options {
  width: 100%; display: flex; align-items: center; gap: 0.75rem;
  padding: 1rem 1.25rem; background: var(--bg-elevated);
  border: 1px solid var(--border); border-radius: var(--radius-md); cursor: pointer;
}
.toggle-switch { position: relative; width: 42px; height: 24px; flex-shrink: 0; }
.toggle-switch input { display: none; }
.toggle-slider {
  position: absolute; inset: 0; background: rgba(255,255,255,0.1);
  border-radius: 999px; transition: var(--transition); cursor: pointer;
}
.toggle-slider::before {
  content: ''; position: absolute; width: 18px; height: 18px;
  top: 3px; left: 3px; background: #fff; border-radius: 50%; transition: var(--transition);
}
input:checked + .toggle-slider { background: var(--emerald); }
input:checked + .toggle-slider::before { transform: translateX(18px); }
.toggle-label { font-size: 0.87rem; font-weight: 500; color: var(--text-secondary); flex: 1; }
.toggle-label small { color: var(--text-muted); font-size: 0.77rem; display: block; }

.upload-actions { width: 100%; display: flex; flex-direction: column; gap: 0.75rem; }

.error-banner {
  width: 100%; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.3);
  border-radius: var(--radius-md); padding: 1rem 1.25rem; color: #fda4af;
  font-size: 0.87rem; display: flex; gap: 0.75rem; align-items: flex-start;
}

/* ── Analyze Loading Overlay ───────────────────────── */
#analyze-overlay {
  position: fixed; inset: 0; z-index: 900;
  display: flex; align-items: center; justify-content: center;
  flex-direction: column; gap: 2rem;
  background: rgba(8,9,13,0.88); backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  opacity: 0; pointer-events: none; transition: opacity 0.35s ease;
}
#analyze-overlay.active { opacity: 1; pointer-events: all; }
.analyze-spinner { width: 80px; height: 80px; position: relative; }
.analyze-spinner::before,
.analyze-spinner::after {
  content: ''; position: absolute; border-radius: 50%; border: 3px solid transparent;
}
.analyze-spinner::before { inset: 0; border-top-color: var(--emerald); animation: spin 1s linear infinite; }
.analyze-spinner::after  { inset: 10px; border-top-color: var(--cyan); animation: spin 0.7s linear infinite reverse; }
@keyframes spin { to { transform: rotate(360deg); } }
.analyze-text { text-align: center; }
.analyze-text h2 {
  font-size: 1.6rem; font-weight: 800; letter-spacing: -0.03em;
  background: linear-gradient(135deg, #fff, var(--emerald));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.analyze-text p { color: var(--text-muted); font-size: 0.85rem; margin-top: 0.4rem; }
.analyze-dots { display: inline-flex; gap: 6px; margin-left: 4px; }
.analyze-dots span {
  width: 5px; height: 5px; border-radius: 50%;
  background: var(--emerald); animation: dot-bounce 1.2s ease infinite;
}
.analyze-dots span:nth-child(2) { animation-delay: 0.2s; }
.analyze-dots span:nth-child(3) { animation-delay: 0.4s; }
@keyframes dot-bounce {
  0%,80%,100% { transform: scale(1); opacity: 0.5; }
  40%          { transform: scale(1.3); opacity: 1; }
}
.analyze-progress { width: 280px; height: 3px; background: rgba(255,255,255,0.08); border-radius: 999px; overflow: hidden; }
.analyze-progress-bar {
  height: 100%; background: linear-gradient(90deg, var(--emerald), var(--cyan));
  border-radius: 999px; animation: progress-fill 3s ease forwards;
}
@keyframes progress-fill { from { width: 0%; } to { width: 90%; } }

/* ── Dashboard ─────────────────────────────────────── */
.dashboard-layout { max-width: 1300px; margin: 0 auto; padding: 2.5rem 2rem; }
.dashboard-header { margin-bottom: 2.5rem; }
.dashboard-breadcrumb {
  display: flex; align-items: center; gap: 0.5rem;
  font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;
}
.dashboard-breadcrumb a { color: var(--emerald); text-decoration: none; }
.dashboard-title {
  font-size: 2rem; font-weight: 800; letter-spacing: -0.04em;
  background: linear-gradient(135deg, #fff 50%, var(--emerald));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  margin-bottom: 0.4rem;
}
.dashboard-meta {
  color: var(--text-muted); font-size: 0.83rem;
  display: flex; gap: 1.25rem; flex-wrap: wrap;
}
.dashboard-meta span { display: flex; align-items: center; gap: 0.4rem; }

.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.25rem; margin-bottom: 2.5rem; }
.stat-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); padding: 1.5rem 1.75rem;
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  transition: var(--transition); position: relative; overflow: hidden;
}
.stat-card::before {
  content: ''; position: absolute; top: -50%; left: -50%;
  width: 200%; height: 200%;
  background: radial-gradient(circle, var(--accent-color, rgba(16,217,122,0.05)) 0%, transparent 60%);
  opacity: 0; transition: opacity 0.4s;
}
.stat-card:hover::before { opacity: 1; }
.stat-card:hover { border-color: rgba(255,255,255,0.12); transform: translateY(-3px); }
.stat-icon { font-size: 1.5rem; margin-bottom: 1rem; display: block; }
.stat-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 0.3rem; }
.stat-value { font-size: 2.2rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; letter-spacing: -0.04em; color: var(--text-primary); }
.stat-value.emerald { color: var(--emerald); }
.stat-value.cyan    { color: var(--cyan); }
.stat-value.violet  { color: var(--violet); }
.stat-value.amber   { color: var(--amber); }

.charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem; }
.chart-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px); padding: 1.75rem; transition: var(--transition);
}
.chart-card:hover {
  box-shadow: 0 0 40px rgba(16,217,122,0.08), 0 4px 32px rgba(0,0,0,0.4);
  border-color: rgba(255,255,255,0.1);
}
.chart-card-header { margin-bottom: 1.5rem; }
.chart-card-title { font-size: 0.95rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.25rem; }
.chart-card-subtitle { font-size: 0.78rem; color: var(--text-muted); }
.chart-container { position: relative; width: 100%; max-width: 300px; margin: 0 auto; }
.chart-center-label {
  position: absolute; inset: 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  pointer-events: none;
}
.chart-center-value { font-size: 1.6rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; color: var(--text-primary); }
.chart-center-text  { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; }
.chart-legend { margin-top: 1.25rem; display: flex; flex-direction: column; gap: 0.5rem; max-height: 180px; overflow-y: auto; scrollbar-width: thin; }
.legend-item { display: flex; align-items: center; gap: 0.6rem; font-size: 0.78rem; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.legend-label { color: var(--text-secondary); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.legend-value { color: var(--text-muted); font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; }
.no-data-state { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 3rem 1rem; gap: 0.75rem; color: var(--text-muted); font-size: 0.85rem; }
.no-data-state .icon { font-size: 2.5rem; opacity: 0.4; }

.download-section {
  display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: 1rem; padding: 1.5rem 2rem;
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: var(--radius-lg); backdrop-filter: blur(20px);
}
.download-info h3 { font-size: 1rem; font-weight: 700; margin-bottom: 0.25rem; }
.download-info p  { font-size: 0.82rem; color: var(--text-muted); }
.download-actions { display: flex; gap: 0.75rem; flex-wrap: wrap; }
.btn-download {
  background: linear-gradient(135deg, var(--violet), #7c3aed);
  color: #fff; box-shadow: 0 0 20px rgba(167,139,250,0.3);
}
.btn-download:hover { transform: translateY(-2px); box-shadow: 0 0 32px rgba(167,139,250,0.5); }

/* ── Utility ────────────────────────────────────────── */
.text-emerald { color: var(--emerald); }
.text-muted   { color: var(--text-muted); }

/* ── Responsive ────────────────────────────────────── */
@media (max-width: 768px) {
  .navbar { padding: 1rem 1.25rem; }
  .dashboard-layout { padding: 1.5rem 1rem; }
  .dashboard-title { font-size: 1.5rem; }
  .charts-grid { grid-template-columns: 1fr; }
  .stat-grid { grid-template-columns: repeat(2, 1fr); }
  .download-section { flex-direction: column; }
}
@media (max-width: 480px) {
  .stat-grid { grid-template-columns: 1fr; }
  .upload-container { padding: 2rem 1rem; }
  .drop-zone { padding: 2.5rem 1rem; }
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# HTML Templates (embedded)
# ─────────────────────────────────────────────────────────────────────────────

BASE_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{% block title %}}CERT-Bund Analyzer{{% endblock %}}</title>
  <meta name="description" content="CERT-Bund network threat intelligence analyzer — upload, process and visualize attack data.">
  <style>
  {CSS_CONTENT}
  </style>
  {{% block extra_head %}}{{% endblock %}}
</head>
<body>
  <div class="bg-mesh" aria-hidden="true"></div>
  <div class="bg-grid"  aria-hidden="true"></div>

  <div id="analyze-overlay" role="status" aria-live="polite" aria-label="Analyzing files">
    <div class="analyze-spinner"></div>
    <div class="analyze-text">
      <h2>Analyzing<span class="analyze-dots"><span></span><span></span><span></span></span></h2>
      <p>Processing your CERT-Bund CSV files. Please wait…</p>
    </div>
    <div class="analyze-progress">
      <div class="analyze-progress-bar" id="analyze-progress-bar"></div>
    </div>
  </div>

  <div class="page-content">
    <nav class="navbar">
      <a href="/" class="navbar-brand" aria-label="CERT-Bund Analyzer Home">
        <div class="brand-icon" aria-hidden="true">🛡️</div>
        <span class="brand-name">CERT-Bund <span>Analyzer</span></span>
      </a>
      <div class="navbar-actions">
        {{% if user.is_authenticated %}}
          <div class="user-badge">
            <span class="dot" aria-hidden="true"></span>
            <span>{{{{ user.username }}}}</span>
          </div>
          <a href="{{% url 'logout' %}}" class="btn btn-danger" id="logout-btn">Sign out</a>
        {{% endif %}}
        {{% block navbar_extra %}}{{% endblock %}}
      </div>
    </nav>

    <main>
      {{% block content %}}{{% endblock %}}
    </main>
  </div>

  <script>
    window.__showAnalyzeOverlay = function() {{
      const overlay = document.getElementById('analyze-overlay');
      if (overlay) {{
        overlay.classList.add('active');
        const bar = document.getElementById('analyze-progress-bar');
        if (bar) {{
          bar.style.animation = 'none';
          bar.offsetHeight;
          bar.style.animation = '';
        }}
      }}
    }};
  </script>
  {{% block extra_js %}}{{% endblock %}}
</body>
</html>
"""

INDEX_HTML = """{% extends 'analyzer/base.html' %}
{% block title %}Login — CERT-Bund Analyzer{% endblock %}

{% block content %}
<div id="login-overlay" role="dialog" aria-modal="true" aria-labelledby="login-title">
  <div class="login-backdrop" aria-hidden="true"></div>
  <div class="login-modal">
    <div class="login-header">
      <div class="login-logo" aria-hidden="true">🛡️</div>
      <h1 class="login-title" id="login-title">Secure Access</h1>
      <p class="login-subtitle">Sign in to access the CERT-Bund Analyzer</p>
    </div>
    <div class="login-body">
      <div class="form-error" id="login-error" role="alert"></div>
      <form id="login-form" novalidate>
        {% csrf_token %}
        <div class="form-group">
          <label class="form-label" for="login-username">Username</label>
          <input type="text" id="login-username" name="username" class="form-control"
                 placeholder="Enter your username" autocomplete="username" required>
        </div>
        <div class="form-group">
          <label class="form-label" for="login-password">Password</label>
          <input type="password" id="login-password" name="password" class="form-control"
                 placeholder="Enter your password" autocomplete="current-password" required>
        </div>
        <button type="submit" class="btn btn-primary btn-full btn-lg" id="login-btn">
          <span id="login-btn-text">Sign In</span>
          <span id="login-spinner" style="display:none">⟳</span>
        </button>
      </form>
      <p style="text-align:center;margin-top:1.25rem;font-size:0.78rem;color:var(--text-muted);">
        Default credentials: <code style="color:var(--emerald);">admin</code> / <code style="color:var(--emerald);">admin123</code>
      </p>
    </div>
  </div>
</div>

<div style="filter:blur(8px);opacity:0.35;min-height:100vh;display:flex;align-items:center;justify-content:center;pointer-events:none;">
  <div style="text-align:center;padding:3rem;">
    <div style="font-size:5rem;margin-bottom:1rem;opacity:0.5;">🛡️</div>
    <div style="font-size:2rem;font-weight:800;color:var(--text-primary);margin-bottom:0.5rem;">CERT-Bund Analyzer</div>
    <div style="color:var(--text-muted);font-size:1rem;">Network Threat Intelligence Platform</div>
  </div>
</div>
{% endblock %}

{% block extra_js %}
<script>
(function () {
  const form    = document.getElementById('login-form');
  const errBox  = document.getElementById('login-error');
  const btnText = document.getElementById('login-btn-text');
  const spinner = document.getElementById('login-spinner');

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    errBox.style.display = 'none';
    btnText.textContent  = 'Signing in…';
    spinner.style.display = 'inline-block';
    spinner.style.animation = 'spin 1s linear infinite';

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const csrf     = form.querySelector('[name=csrfmiddlewaretoken]').value;

    try {
      const res  = await fetch('/login/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username, password, csrfmiddlewaretoken: csrf }),
      });
      const data = await res.json();

      if (data.success) {
        window.location.href = '/';
      } else {
        errBox.textContent   = data.error || 'Login failed. Please try again.';
        errBox.style.display = 'block';
      }
    } catch (err) {
      errBox.textContent   = 'Network error. Please check your connection.';
      errBox.style.display = 'block';
    } finally {
      btnText.textContent   = 'Sign In';
      spinner.style.display = 'none';
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') form.dispatchEvent(new Event('submit', {bubbles:true,cancelable:true}));
  });
})();
</script>
{% endblock %}
"""

UPLOAD_HTML = """{% extends 'analyzer/base.html' %}
{% block title %}Upload — CERT-Bund Analyzer{% endblock %}

{% block content %}
<section class="upload-section">
  <div class="upload-container">

    <div class="upload-title">
      <h1>Analyze Threat Data</h1>
      <p>Drop a folder containing CERT-Bund CSV files to begin threat intelligence analysis.</p>
    </div>

    {% if error %}
    <div class="error-banner" role="alert">
      <span>⚠️</span>
      <span>{{ error }}</span>
    </div>
    {% endif %}

    <form id="upload-form" method="POST" action="{% url 'analyze' %}"
          enctype="multipart/form-data"
          style="width:100%;display:flex;flex-direction:column;gap:1.25rem;">
      {% csrf_token %}

      <div id="drop-zone" class="drop-zone"
           role="button" tabindex="0"
           aria-label="Drop folder here or click to browse"
           onclick="document.getElementById('folder-input').click()"
           onkeydown="if(event.key==='Enter'||event.key===' '){document.getElementById('folder-input').click()}">
        <span class="drop-icon" aria-hidden="true">📂</span>
        <h3>Drop your folder here</h3>
        <p>Drag and drop a folder containing CERT-Bund CSV files</p>
        <button type="button" class="btn btn-ghost"
                onclick="event.stopPropagation();document.getElementById('folder-input').click()">
          📁 Browse Folder
        </button>
        <p class="hint">Supports folders with multiple .csv files • Max 500 MB</p>
      </div>

      <input type="file" id="folder-input" name="files"
             multiple webkitdirectory directory accept=".csv"
             aria-label="Select folder">

      <div class="file-list" id="file-list">
        <div class="file-list-header">
          <h3>📄 Selected Files</h3>
          <span class="file-count-badge" id="file-count">0 CSV files</span>
        </div>
        <div class="file-list-items" id="file-list-items" role="list"></div>
      </div>

      <label class="upload-options" for="osint-toggle" id="osint-label">
        <div class="toggle-switch">
          <input type="checkbox" id="osint-toggle" name="run_osint">
          <span class="toggle-slider"></span>
        </div>
        <span class="toggle-label">
          🔍 Threat Intelligence Search
          <small>Run DuckDuckGo OSINT queries for unknown malware (takes longer)</small>
        </span>
      </label>

      <div class="upload-options" style="flex-direction:column; align-items:flex-start; gap:0.5rem; cursor:default; margin-bottom:1.25rem;">
        <span class="toggle-label" style="margin-left:0;">🛡️ AbuseIPDB Reputation (Optional)</span>
        <input type="password" name="abuseipdb_key" placeholder="Enter AbuseIPDB API Key (Optional)" 
               style="width:100%; padding:0.75rem; border:1px solid rgba(255,255,255,0.1); border-radius:0.5rem; background:rgba(0,0,0,0.2); color:white; font-family:inherit;">
      </div>

      <div class="upload-actions">
        <button type="submit" class="btn btn-primary btn-lg btn-full"
                id="analyze-btn" disabled>
          🔬 Analyze
        </button>
        <button type="button" class="btn btn-ghost btn-full"
                id="clear-btn" style="display:none;" onclick="clearFiles()">
          ✕ Clear Selection
        </button>
      </div>
    </form>

  </div>
</section>
{% endblock %}

{% block extra_js %}
<script>
(function () {
  const dropZone    = document.getElementById('drop-zone');
  const folderInput = document.getElementById('folder-input');
  const fileList    = document.getElementById('file-list');
  const fileItems   = document.getElementById('file-list-items');
  const fileCount   = document.getElementById('file-count');
  const analyzeBtn  = document.getElementById('analyze-btn');
  const clearBtn    = document.getElementById('clear-btn');
  const form        = document.getElementById('upload-form');
  let selectedFiles = [];

  dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault(); dropZone.classList.remove('dragover');
    const items = e.dataTransfer.items;
    if (items) {
      const files = [];
      for (let i = 0; i < items.length; i++) {
        const entry = items[i].webkitGetAsEntry ? items[i].webkitGetAsEntry() : null;
        if (entry) readEntry(entry, files);
        else if (items[i].kind === 'file') {
          const f = items[i].getAsFile();
          if (f && f.name.toLowerCase().endsWith('.csv')) files.push(f);
        }
      }
      setTimeout(() => updateFileList(files), 300);
    }
  });

  function readEntry(entry, files) {
    if (entry.isFile) {
      entry.file((f) => { if (f.name.toLowerCase().endsWith('.csv')) files.push(f); });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      reader.readEntries((entries) => entries.forEach((e) => readEntry(e, files)));
    }
  }

  folderInput.addEventListener('change', function () {
    updateFileList(Array.from(this.files).filter(f => f.name.toLowerCase().endsWith('.csv')));
  });

  function updateFileList(files) {
    if (!files || files.length === 0) return;
    selectedFiles = files;
    fileCount.textContent = `${files.length} CSV file${files.length !== 1 ? 's' : ''}`;
    fileItems.innerHTML   = '';
    files.forEach((f) => {
      const item = document.createElement('div');
      item.className = 'file-item'; item.setAttribute('role', 'listitem');
      item.innerHTML = `
        <span class="file-item-icon" aria-hidden="true">📊</span>
        <span class="file-item-name">${escHtml(f.name)}</span>
        <span class="file-item-size">${formatSize(f.size)}</span>
      `;
      fileItems.appendChild(item);
    });
    fileList.classList.add('visible');
    analyzeBtn.disabled    = false;
    clearBtn.style.display = '';
    dropZone.style.borderColor = 'var(--emerald)';
  }

  function clearFiles() {
    selectedFiles = []; folderInput.value = '';
    fileList.classList.remove('visible'); fileItems.innerHTML = '';
    analyzeBtn.disabled = true; clearBtn.style.display = 'none';
    dropZone.style.borderColor = '';
  }
  window.clearFiles = clearFiles;

  form.addEventListener('submit', function () {
    if (selectedFiles.length === 0) return;
    analyzeBtn.disabled    = true;
    analyzeBtn.textContent = '⏳ Analyzing…';
    window.__showAnalyzeOverlay();
  });

  function formatSize(b) {
    if (b < 1024)    return b + ' B';
    if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
    return (b/1048576).toFixed(1) + ' MB';
  }
  function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }
})();
</script>
{% endblock %}
"""

DASHBOARD_HTML = """{% extends 'analyzer/base.html' %}
{% block title %}Dashboard — Run #{{ run.pk }} — CERT-Bund Analyzer{% endblock %}

{% block extra_head %}
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
{% endblock %}

{% block content %}
<div class="dashboard-layout">

  <div class="dashboard-header">
    <div class="dashboard-breadcrumb" aria-label="breadcrumb">
      <a href="/">⬆ Upload</a>
      <span aria-hidden="true">›</span><span>Dashboard</span>
      <span aria-hidden="true">›</span><span>Run #{{ run.pk }}</span>
    </div>
    <h1 class="dashboard-title">Threat Analysis Report</h1>
    <div class="dashboard-meta">
      <span>📁 {{ run.folder_name }}</span>
      <span>🕐 {{ run.created_at|date:"N j, Y — H:i" }} UTC</span>
      <span>👤 {{ run.created_by.username }}</span>
    </div>
  </div>

  <div class="stat-grid" role="list" aria-label="Summary statistics">
    <div class="stat-card" role="listitem" style="--accent-color: rgba(16,217,122,0.06);">
      <span class="stat-icon" aria-hidden="true">📊</span>
      <div class="stat-label">Total Events</div>
      <div class="stat-value emerald" id="stat-total">{{ run.total_rows }}</div>
    </div>
    <div class="stat-card" role="listitem" style="--accent-color: rgba(34,211,238,0.06);">
      <span class="stat-icon" aria-hidden="true">🌐</span>
      <div class="stat-label">Unique ASNs</div>
      <div class="stat-value cyan" id="stat-asns">{{ run.unique_asns }}</div>
    </div>
    <div class="stat-card" role="listitem" style="--accent-color: rgba(167,139,250,0.06);">
      <span class="stat-icon" aria-hidden="true">🦠</span>
      <div class="stat-label">Malware Families</div>
      <div class="stat-value violet" id="stat-malwares">{{ run.unique_malwares }}</div>
    </div>
    <div class="stat-card" role="listitem" style="--accent-color: rgba(245,158,11,0.06);">
      <span class="stat-icon" aria-hidden="true">🎯</span>
      <div class="stat-label">Unique Victim IPs</div>
      <div class="stat-value amber" id="stat-ips">{{ run.unique_ips }}</div>
    </div>
  </div>

  <div class="charts-grid">

    <div class="chart-card">
      <div class="chart-card-header">
        <div class="chart-card-title">🌐 ASNs Attacked</div>
        <div class="chart-card-subtitle">Top {{ run.asn_stats|length }} autonomous systems targeted</div>
      </div>
      {% if run.asn_stats %}
        <div class="chart-container" style="height:280px;">
          <canvas id="asn-chart" aria-label="ASNs Attacked pie chart" role="img"></canvas>
          <div class="chart-center-label">
            <div class="chart-center-value">{{ run.unique_asns }}</div>
            <div class="chart-center-text">ASNs</div>
          </div>
        </div>
        <div class="chart-legend" id="asn-legend" aria-label="ASN legend"></div>
      {% else %}
        <div class="no-data-state"><div class="icon" aria-hidden="true">🌐</div><p>No ASN data available</p></div>
      {% endif %}
    </div>

    <div class="chart-card">
      <div class="chart-card-header">
        <div class="chart-card-title">🦠 Detected Malwares</div>
        <div class="chart-card-subtitle">Top {{ run.malware_stats|length }} malware families observed</div>
      </div>
      {% if run.malware_stats %}
        <div class="chart-container" style="height:280px;">
          <canvas id="malware-chart" aria-label="Malware families pie chart" role="img"></canvas>
          <div class="chart-center-label">
            <div class="chart-center-value">{{ run.unique_malwares }}</div>
            <div class="chart-center-text">Families</div>
          </div>
        </div>
        <div class="chart-legend" id="malware-legend" aria-label="Malware legend"></div>
      {% else %}
        <div class="no-data-state"><div class="icon" aria-hidden="true">🦠</div><p>No malware data available</p></div>
      {% endif %}
    </div>

    <div class="chart-card">
      <div class="chart-card-header">
        <div class="chart-card-title">🎯 Most Attacked IPs</div>
        <div class="chart-card-subtitle">Top {{ run.ip_stats|length }} victim IP addresses by event count</div>
      </div>
      {% if run.ip_stats %}
        <div class="chart-container" style="height:280px;">
          <canvas id="ip-chart" aria-label="Most attacked IPs pie chart" role="img"></canvas>
          <div class="chart-center-label">
            <div class="chart-center-value">{{ run.unique_ips }}</div>
            <div class="chart-center-text">IPs</div>
          </div>
        </div>
        <div class="chart-legend" id="ip-legend" aria-label="IP legend"></div>
      {% else %}
        <div class="no-data-state"><div class="icon" aria-hidden="true">🎯</div><p>No IP data available</p></div>
      {% endif %}
    </div>

  </div>

  <div class="download-section">
    <div class="download-info">
      <h3>📦 Download Analysis Results</h3>
      <p>Includes per-ASN CSVs, combined summary CSV{% if run.output_dir %}, and OSINT threat reports{% endif %}.</p>
    </div>
    <div class="download-actions">
      {% if run.output_dir %}
        <a href="{% url 'download_results' run.pk %}" class="btn btn-download" id="download-btn">⬇ Download ZIP</a>
      {% else %}
        <span class="btn btn-ghost" style="cursor:default;opacity:0.5;">No results file</span>
      {% endif %}
      <a href="/" class="btn btn-ghost">🔬 New Analysis</a>
    </div>
  </div>

</div>
{% endblock %}

{% block extra_js %}
<script>
(function () {
  const asnLabels     = {{ asn_labels|safe }};
  const asnValues     = {{ asn_values|safe }};
  const malwareLabels = {{ malware_labels|safe }};
  const malwareValues = {{ malware_values|safe }};
  const ipLabels      = {{ ip_labels|safe }};
  const ipValues      = {{ ip_values|safe }};

  const PALETTES = {
    emerald: ['#10d97a','#0ea862','#22d3ee','#38bdf8','#818cf8','#a78bfa','#c084fc','#e879f9','#fb923c','#facc15'],
    violet:  ['#a78bfa','#818cf8','#60a5fa','#34d399','#10d97a','#22d3ee','#f472b6','#fb923c','#facc15','#c084fc'],
    rose:    ['#f43f5e','#fb923c','#fbbf24','#a3e635','#34d399','#22d3ee','#60a5fa','#818cf8','#c084fc','#e879f9'],
  };

  Chart.defaults.color = '#94a3b8';
  Chart.defaults.font.family = "'Inter', system-ui, sans-serif";

  function buildDoughnut(canvasId, labels, values, palette) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    const colors   = PALETTES[palette] || PALETTES.emerald;
    const bgColors = labels.map((_, i) => colors[i % colors.length]);
    const totalVal = values.reduce((a, b) => a + b, 0);
    return new Chart(ctx, {
      type: 'doughnut',
      data: { labels, datasets: [{ data: values, backgroundColor: bgColors, borderColor: 'rgba(8,9,13,0.8)', borderWidth: 3, hoverOffset: 10, hoverBorderColor: '#fff' }] },
      options: {
        cutout: '68%', responsive: true, maintainAspectRatio: true,
        animation: { animateRotate: true, animateScale: false, duration: 900, easing: 'easeOutQuart' },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(15,17,26,0.95)', borderColor: 'rgba(255,255,255,0.08)',
            borderWidth: 1, padding: 12,
            titleFont: { size: 12, weight: '700' }, bodyFont: { size: 12 },
            callbacks: {
              label: function(ctx) {
                const pct = totalVal > 0 ? ((ctx.parsed / totalVal) * 100).toFixed(1) : '0.0';
                return ` ${ctx.parsed.toLocaleString()} events (${pct}%)`;
              },
            },
          },
        },
      },
    });
  }

  function buildLegend(containerId, labels, values, palette) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const colors = PALETTES[palette] || PALETTES.emerald;
    container.innerHTML = '';
    labels.forEach((label, i) => {
      const item = document.createElement('div');
      item.className = 'legend-item';
      item.innerHTML = `
        <span class="legend-dot" style="background:${colors[i % colors.length]};"></span>
        <span class="legend-label" title="${escHtml(label)}">${escHtml(label) || '(unknown)'}</span>
        <span class="legend-value">${values[i].toLocaleString()}</span>
      `;
      container.appendChild(item);
    });
  }

  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function animateCounter(el, target, duration = 1200) {
    if (!el) return;
    const step = target / (duration / 16);
    let current = 0;
    const tick = () => {
      current = Math.min(current + step, target);
      el.textContent = Math.round(current).toLocaleString();
      if (current < target) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  document.addEventListener('DOMContentLoaded', () => {
    animateCounter(document.getElementById('stat-total'),    parseInt("{{ run.total_rows }}")     || 0);
    animateCounter(document.getElementById('stat-asns'),     parseInt("{{ run.unique_asns }}")    || 0);
    animateCounter(document.getElementById('stat-malwares'), parseInt("{{ run.unique_malwares }}") || 0);
    animateCounter(document.getElementById('stat-ips'),      parseInt("{{ run.unique_ips }}")     || 0);

    if (asnLabels.length)     { buildDoughnut('asn-chart',     asnLabels,     asnValues,     'emerald'); buildLegend('asn-legend',     asnLabels,     asnValues,     'emerald'); }
    if (malwareLabels.length) { buildDoughnut('malware-chart', malwareLabels, malwareValues, 'violet');  buildLegend('malware-legend', malwareLabels, malwareValues, 'violet');  }
    if (ipLabels.length)      { buildDoughnut('ip-chart',      ipLabels,      ipValues,      'rose');    buildLegend('ip-legend',      ipLabels,      ipValues,      'rose');    }
  });
})();
</script>
{% endblock %}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Django Configuration
# ─────────────────────────────────────────────────────────────────────────────

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='django-insecure-g7c6_h)9))3i+538%f!er@74%jn4sg3z%(o%u$5uak=5^*$e4(',
        ALLOWED_HOSTS=['*'],
        INSTALLED_APPS=[
            'django.contrib.admin',
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.messages',
            '__main__',
        ],
        MIDDLEWARE=[
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ],
        ROOT_URLCONF='__main__',
        TEMPLATES=[{
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [],
            'APP_DIRS': False,
            'OPTIONS': {
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
                'loaders': [('django.template.loaders.locmem.Loader', {
                    'analyzer/base.html':      BASE_HTML,
                    'analyzer/index.html':     INDEX_HTML,
                    'analyzer/upload.html':    UPLOAD_HTML,
                    'analyzer/dashboard.html': DASHBOARD_HTML,
                })],
            },
        }],
        DATABASES={'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME':   BASE_DIR / 'db.sqlite3',
        }},
        AUTH_PASSWORD_VALIDATORS=[],
        LANGUAGE_CODE='en-us',
        TIME_ZONE='UTC',
        USE_I18N=True,
        USE_TZ=True,
        MEDIA_URL='/media/',
        MEDIA_ROOT=BASE_DIR / 'media',
        DEFAULT_AUTO_FIELD='django.db.models.BigAutoField',
        LOGIN_URL='/',
        LOGIN_REDIRECT_URL='/',
    )

django.setup()

# ─────────────────────────────────────────────────────────────────────────────
# Django imports (must come after setup)
# ─────────────────────────────────────────────────────────────────────────────

from django.db import models
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.core.management import call_command
from django.urls import path
from django.conf.urls.static import static

# ─────────────────────────────────────────────────────────────────────────────
# Database Models
# ─────────────────────────────────────────────────────────────────────────────

class KnownMalware(models.Model):
    """Malware names tracked dynamically in the database."""
    name = models.CharField(max_length=200, unique=True)
    
    class Meta:
        db_table = 'analyzer_knownmalware'
        
    def __str__(self):
        return self.name

class AnalysisRun(models.Model):
    """Tracks a single folder-analysis run."""
    created_by      = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at      = models.DateTimeField(auto_now_add=True)
    folder_name     = models.CharField(max_length=500, default='')
    total_rows      = models.IntegerField(default=0)
    unique_asns     = models.IntegerField(default=0)
    unique_malwares = models.IntegerField(default=0)
    unique_ips      = models.IntegerField(default=0)
    asn_stats       = models.JSONField(default=list)
    malware_stats   = models.JSONField(default=list)
    ip_stats        = models.JSONField(default=list)
    output_dir      = models.CharField(max_length=1000, blank=True, default='')
    status          = models.CharField(
        max_length=20,
        choices=[('pending', 'Pending'), ('done', 'Done'), ('error', 'Error')],
        default='done',
    )
    error_message   = models.TextField(blank=True, default='')

    class Meta:
        db_table = 'analyzer_analysisrun'
        ordering = ['-created_at']

    def __str__(self):
        return f"Run #{self.pk} by {self.created_by} at {self.created_at:%Y-%m-%d %H:%M}"

    def asn_chart_data(self):
        return ([i['label'] for i in self.asn_stats], [i['count'] for i in self.asn_stats])

    def malware_chart_data(self):
        return ([i['label'] for i in self.malware_stats], [i['count'] for i in self.malware_stats])

    def ip_chart_data(self):
        return ([i['label'] for i in self.ip_stats], [i['count'] for i in self.ip_stats])


# ─────────────────────────────────────────────────────────────────────────────
# Views
# ─────────────────────────────────────────────────────────────────────────────

def index(request):
    if request.user.is_authenticated:
        return render(request, 'analyzer/upload.html')
    return render(request, 'analyzer/index.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({'success': True})
        return JsonResponse({'success': False, 'error': 'Invalid username or password.'}, status=401)
    return redirect('index')


def logout_view(request):
    logout(request)
    return redirect('index')


@login_required(login_url='/')
def analyze(request):
    if request.method != 'POST':
        return redirect('index')

    uploaded  = request.FILES.getlist('files')
    run_osint = request.POST.get('run_osint') == 'on'
    abuseipdb_key = request.POST.get('abuseipdb_key', '').strip()

    if not uploaded:
        return render(request, 'analyzer/upload.html', {
            'error': 'No files were uploaded. Please drop a folder containing CSV files.'
        })

    csv_files = [f for f in uploaded if f.name.lower().endswith('.csv')]
    if not csv_files:
        return render(request, 'analyzer/upload.html', {
            'error': 'No CSV files found in the uploaded folder.'
        })

    ts          = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir     = os.path.join(settings.MEDIA_ROOT, 'runs', f'run_{ts}_{request.user.id}')
    upload_dir  = os.path.join(run_dir, 'uploads')
    output_dir  = os.path.join(run_dir, 'output')
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    file_pairs  = []
    folder_name = ''
    for f in csv_files:
        orig_name = f.name
        if not folder_name:
            parts = orig_name.replace('\\', '/').split('/')
            folder_name = parts[0] if len(parts) > 1 else 'Uploaded Files'

        safe_name = os.path.basename(orig_name.replace('\\', '/'))
        tmp_path  = os.path.join(upload_dir, safe_name)
        with open(tmp_path, 'wb') as out:
            for chunk in f.chunks():
                out.write(chunk)
        file_pairs.append((safe_name, tmp_path))

    try:
        db_malware = set(KnownMalware.objects.values_list('name', flat=True))
        stats = run_analysis(
            file_pairs, output_dir,
            run_osint=run_osint,
            known_malware=db_malware,
            abuseipdb_key=abuseipdb_key
        )
    except Exception as exc:
        log.exception("Analysis failed: %s", exc)
        shutil.rmtree(run_dir, ignore_errors=True)
        return render(request, 'analyzer/upload.html', {'error': f'Analysis failed: {exc}'})

    out_abs = stats.get('output_dir', '')
    out_rel = os.path.relpath(out_abs, settings.MEDIA_ROOT) if out_abs else ''

    run = AnalysisRun.objects.create(
        created_by      = request.user,
        folder_name     = folder_name,
        total_rows      = stats['total_rows'],
        unique_asns     = stats['unique_asns'],
        unique_malwares = stats['unique_malwares'],
        unique_ips      = stats['unique_ips'],
        asn_stats       = stats['asn_stats'],
        malware_stats   = stats['malware_stats'],
        ip_stats        = stats['ip_stats'],
        output_dir      = out_rel,
        status          = 'done',
    )
    return redirect('dashboard', run_id=run.pk)


@login_required(login_url='/')
def dashboard(request, run_id):
    run = get_object_or_404(AnalysisRun, pk=run_id, created_by=request.user)
    asn_labels,     asn_values     = run.asn_chart_data()
    malware_labels, malware_values = run.malware_chart_data()
    ip_labels,      ip_values      = run.ip_chart_data()
    return render(request, 'analyzer/dashboard.html', {
        'run':            run,
        'asn_labels':     json.dumps(asn_labels),
        'asn_values':     json.dumps(asn_values),
        'malware_labels': json.dumps(malware_labels),
        'malware_values': json.dumps(malware_values),
        'ip_labels':      json.dumps(ip_labels),
        'ip_values':      json.dumps(ip_values),
    })


@login_required(login_url='/')
def download_results(request, run_id):
    run = get_object_or_404(AnalysisRun, pk=run_id, created_by=request.user)
    if not run.output_dir:
        return HttpResponse('No output directory found.', status=404)
    
    abs_out_dir = os.path.join(settings.MEDIA_ROOT, run.output_dir)
    if not os.path.exists(abs_out_dir):
        return HttpResponse('Output directory not found on disk.', status=404)
        
    zip_path = create_results_zip(abs_out_dir)
    
    with open(zip_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="results_run_{run_id}.zip"'
        return response


# ─────────────────────────────────────────────────────────────────────────────
# URL Routing
# ─────────────────────────────────────────────────────────────────────────────

urlpatterns = [
    path('',                        index,             name='index'),
    path('login/',                  login_view,        name='login'),
    path('logout/',                 logout_view,       name='logout'),
    path('analyze/',                analyze,           name='analyze'),
    path('dashboard/<int:run_id>/', dashboard,         name='dashboard'),
    path('download/<int:run_id>/',  download_results,  name='download_results'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap & Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def bootstrap_db():
    """Run migrations and ensure the default admin user exists."""
    print("[CERT-Bund] Running migrations…")
    call_command('migrate', interactive=False)

    from django.db import connection
    for model in [KnownMalware, AnalysisRun]:
        table_name = model._meta.db_table
        if table_name not in connection.introspection.table_names():
            print(f"[CERT-Bund] Creating table '{table_name}'…")
            with connection.schema_editor() as editor:
                editor.create_model(model)
            print(f"[CERT-Bund] Table {table_name} created.")

    # Populate default malware
    if not KnownMalware.objects.exists():
        for mw in DEFAULT_KNOWN_MALWARE:
            KnownMalware.objects.create(name=mw)
        print("[CERT-Bund] Seeded KnownMalware database.")

    try:
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser(
                username='admin',
                email='admin@certbund.local',
                password='admin123',
            )
            print("[CERT-Bund] Default superuser created: admin / admin123")
    except Exception as exc:
        print(f"[CERT-Bund] Error setting up default user: {exc}")


if __name__ == '__main__':
    bootstrap_db()

    args = sys.argv
    if len(args) == 1:
        args = [args[0], 'runserver', '8000']

    print("[CERT-Bund] Starting Django dev server…")
    from django.core.management import execute_from_command_line
    execute_from_command_line(args)
