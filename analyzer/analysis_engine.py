import os
import json
import logging
import csv
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

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

log = logging.getLogger("cert_bund_web")

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

DEFAULT_KNOWN_MALWARE = set()

# ── Row helpers ───────────────────────────────────────────────────────────────
def resolve_asn(asn_str: str, db_asn_map: dict, new_asns_discovered: dict) -> str:
    """
    Resolve ASN to operator name via DB cache or API.
    Also extracts name if it is already present in the string.
    """
    if not asn_str: return ""
    
    parts = asn_str.split(' ', 1)
    if len(parts) > 1:
        operator = parts[1].strip()
        asn_num = parts[0].upper()
        if asn_num not in db_asn_map:
            db_asn_map[asn_num] = operator
            new_asns_discovered[asn_num] = operator
        return operator

    asn_num = asn_str.strip().upper()
    if not asn_num.startswith('AS'):
        asn_num = 'AS' + asn_num

    if asn_num in db_asn_map:
        return db_asn_map[asn_num]
        
    return asn_str

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
    """GET with up to REQUEST_RETRIES attempts. Returns Response or None.

    Connectivity errors (DNS failure, refused connections) are non-transient
    and will not self-heal within the retry window, so the function returns
    immediately on those rather than sleeping and retrying pointlessly.
    """
    if not _REQUESTS_OK:
        log.error("'requests' not installed — HTTP GET unavailable.")
        return None
    url = _ensure_https(url)
    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            resp = requests.get(url, headers=headers, params=params or {}, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.exceptions.ConnectionError as exc:
            log.warning("HTTP GET attempt %d/%d failed (connectivity): %s", attempt, REQUEST_RETRIES, exc)
            return None
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

# ── BGPView ASN cache & circuit breaker ──────────────────────────────────────
_asn_cache: dict[str, str] = {}
_bgpview_unavailable: bool = False

def fetch_asn_name_api(asn_num: str) -> str:
    """Resolve an ASN number to an operator name via the BGPView API."""
    global _bgpview_unavailable

    num_only = asn_num.replace('AS', '')
    if not num_only.isdigit():
        return ""

    cache_key = f"AS{num_only}"

    if cache_key in _asn_cache:
        return _asn_cache[cache_key]

    if _bgpview_unavailable:
        log.debug("BGPView unavailable — skipping lookup for %s", cache_key)
        _asn_cache[cache_key] = ""
        return ""

    resp = http_get_with_retry(f"https://api.bgpview.io/asn/{num_only}", headers=HEADERS)

    if resp is None:
        log.warning(
            "BGPView unreachable — ASN lookups disabled for this session. "
            "Check network connectivity or DNS resolution for 'api.bgpview.io'."
        )
        _bgpview_unavailable = True
        _asn_cache[cache_key] = ""
        return ""

    name = ""
    try:
        data = resp.json()
        if data.get('status') == 'ok':
            name = data['data'].get('name', '') or data['data'].get('description_short', '')
    except Exception:
        pass

    _asn_cache[cache_key] = name
    return name

# ── CSV parsing ───────────────────────────────────────────────────────────────
def parse_csv_file(
    file_path: str,
    seen_combos: set,
    seen_this_run: set,
    known_malware: set,
    db_asn_map: dict,
    new_asns_discovered: dict,
) -> tuple[list[dict], set[str], set[str], int]:
    """Read one CERT-Bund CSV file and return only *new* (non-duplicate) rows."""
    new_rows = []
    new_fingerprints = set()
    new_malware_set = set()
    duplicate_count = 0

    try:
        with open(file_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                clean = {k: (row.get(k) or "").strip() for k in CSV_FIELDNAMES}
                if not clean["asn"]:
                    continue

                fp = make_fingerprint(clean)
                if fp in seen_combos or fp in seen_this_run:
                    duplicate_count += 1
                    continue

                asn_str = clean["asn"]
                if asn_str:
                    parts = asn_str.split(' ', 1)
                    if len(parts) > 1:
                        operator = parts[1].strip()
                        asn_num = parts[0].upper()
                        if asn_num not in db_asn_map:
                            db_asn_map[asn_num] = operator
                            new_asns_discovered[asn_num] = operator
                        clean["asn"] = operator
                    else:
                        asn_num = asn_str.strip().upper()
                        if not asn_num.startswith('AS'): asn_num = 'AS' + asn_num
                        
                        if asn_num in db_asn_map:
                            clean["asn"] = db_asn_map[asn_num]
                        else:
                            fetched = fetch_asn_name_api(asn_num)
                            if fetched:
                                db_asn_map[asn_num] = fetched
                                new_asns_discovered[asn_num] = fetched
                                clean["asn"] = fetched

                seen_this_run.add(fp)
                new_rows.append(clean)
                new_fingerprints.add(fp)

                malware_lower = clean["malware"].lower()
                if clean["malware"] and malware_lower not in known_malware:
                    new_malware_set.add(clean["malware"])

    except Exception as exc:
        log.error("Error reading %s: %s", file_path, exc)

    return new_rows, new_fingerprints, new_malware_set, duplicate_count

# ── Core analysis pipeline ────────────────────────────────────────────────────
def run_analysis(
    uploaded_files: list[tuple[str, str]],
    output_dir: str,
    run_osint: bool = False,
    known_malware: set = None,
    db_asn_map: dict = None,
    abuseipdb_key: str = "",
) -> dict:
    """Full analysis pipeline."""
    if known_malware is None: known_malware = DEFAULT_KNOWN_MALWARE
    if db_asn_map is None: db_asn_map = {}
    os.makedirs(output_dir, exist_ok=True)

    seen_combos = set()
    seen_this_run = set()
    all_rows = []
    new_asns_discovered = {}
    total_duplicate_count = 0
    all_new_malware_discovered = set()

    for orig_name, tmp_path in uploaded_files:
        new_rows, new_fps, new_mw, dup_count = parse_csv_file(
            tmp_path, seen_combos, seen_this_run, known_malware, 
            db_asn_map, new_asns_discovered
        )
        seen_combos.update(new_fps)
        all_rows.extend(new_rows)
        total_duplicate_count += dup_count
        all_new_malware_discovered.update(new_mw)
        known_malware.update(new_mw)

    if not all_rows:
        return {
            "total_rows":      0,
            "duplicate_count": total_duplicate_count,
            "unique_asns":     0,
            "unique_malwares": 0,
            "unique_ips":      0,
            "asn_stats":       [],
            "malware_stats":   [],
            "ip_stats":        [],
            "output_dir":      output_dir,
            "new_asns":        new_asns_discovered,
            "new_malwares":    list(all_new_malware_discovered),
            "all_rows":        [],
        }

    asn_counter     = Counter(r["asn"]     for r in all_rows)
    malware_counter = Counter(r["malware"] for r in all_rows if r["malware"])
    ip_counter      = Counter(r["ip"]      for r in all_rows if r["ip"])

    top_asns     = asn_counter.most_common(10)
    top_malwares = malware_counter.most_common(10)
    top_ips      = ip_counter.most_common(10)

    asn_stats     = [{"label": k, "count": v} for k, v in top_asns]
    malware_stats = [{"label": k, "count": v} for k, v in top_malwares]
    ip_stats      = [{"label": k, "count": v} for k, v in top_ips]

    rows_by_asn = defaultdict(list)
    for row in all_rows:
        rows_by_asn[row["asn"]].append(row)

    for asn, rows in rows_by_asn.items():
        safe    = asn.replace("/", "_").replace("\\", "_")

        csv_path = os.path.join(output_dir, f"{safe}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    combined_csv = os.path.join(output_dir, f"all_asns_{ts}.csv")
    with open(combined_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for asn in sorted(rows_by_asn.keys()):
            writer.writerows(rows_by_asn[asn])

    log.info("Combined CSV written: %s", combined_csv)

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
        "duplicate_count": total_duplicate_count,
        "unique_asns":     len(asn_counter),
        "unique_malwares": len(malware_counter),
        "unique_ips":      len(ip_counter),
        "asn_stats":       asn_stats,
        "malware_stats":   malware_stats,
        "ip_stats":        ip_stats,
        "output_dir":      output_dir,
        "new_asns":        new_asns_discovered,
        "new_malwares":    list(all_new_malware_discovered),
        "all_rows":        all_rows,
    }
