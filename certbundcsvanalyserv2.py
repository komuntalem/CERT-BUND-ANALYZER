# =========================================================
# REQUIREMENTS
# =========================================================
# pip install python-docx requests beautifulsoup4

import subprocess
import sys

# =========================================================
# AUTO-INSTALL DEPENDENCIES
# =========================================================

REQUIRED_PACKAGES = {
    "docx":     "python-docx",
    "bs4":      "beautifulsoup4",
    "requests": "requests",
}

#def install_dependencies():
#    missing = []
#    for import_name, pip_name in REQUIRED_PACKAGES.items():
#        try:
#            __import__(import_name)
#        except ImportError:
#            missing.append(pip_name)
#    if missing:
#        print(f"[setup] Installing missing packages: {', '.join(missing)}")
#        try:
#            subprocess.check_call(
#                [sys.executable, "-m", "pip", "install", *missing],
#                stdout=subprocess.DEVNULL,
#                stderr=subprocess.DEVNULL,
#            )
#            print("[setup] Dependencies installed successfully.")
#        except subprocess.CalledProcessError as e:
#            print(f"[setup] ERROR: Failed to install packages: {e}")
#            print(f"[setup] Please run manually:  pip install {' '.join(missing)}")
#            sys.exit(1)
#    else:
#        print("[setup] All dependencies are already installed.")

#install_dependencies()

import csv
import os
import re
import glob
import logging
import time
import requests
from bs4 import BeautifulSoup
from docx import Document
from datetime import datetime

# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("analyzer.log", encoding="utf-8")
    ]
)
log = logging.getLogger(__name__)

# =========================================================
# CONFIGURATION
# =========================================================

HEADERS        = {"User-Agent": "Mozilla/5.0"}
DUCKDUCKGO_URL = "https://html.duckduckgo.com/html/"

# Single persistence file — stores ip|dst_ip|dst_port|malware fingerprints.
# On first run this file is empty/absent and every row qualifies (first scan
# becomes the baseline). After writing, all fingerprints are appended so the
# next run only processes genuinely new attack patterns.
SEEN_COMBOS_FILE  = "seen_combos.txt"
SEEN_REPORTS_FILE = "seen_malware_reports.txt"

# Name of the output subfolder created inside the scan directory.
# All ASN subfolders and reports land here, alongside the scanned files.
OUTPUT_FOLDER_NAME = "output"

# All original CSV headers — output files always use this exact order
CSV_FIELDNAMES = ["asn", "ip", "timestamp", "malware", "src_port",
                  "dst_ip", "dst_port", "dst_host", "proto"]

REQUEST_RETRIES = 3
REQUEST_BACKOFF = 2  # seconds between retries

KNOWN_MALWARE = {
    "m0yv",
    "vipersoftx",
    "pykspa",
    "android.vo1d2",
    "pseudo_manuscrypt",
    "andromeda",
    "ranbyus",
    "tinba",
    "nymaim",
    "prometei",
    "lumma",
    "ghostweaver",
    "zeus",
    "corebot",
    "trusteer",
    "urlzone",
    "teslacrypt",
}

# =========================================================
# FINGERPRINT HELPER
# =========================================================

def make_fingerprint(row):
    """
    Unique identity of an attack pattern:
      victim IP  +  attacker IP  +  port attacked  +  malware used
    src_port, timestamp, dst_host, and proto are intentionally excluded —
    src_port is ephemeral, timestamp is always new, dst_host is derived
    from dst_ip, and proto rarely varies meaningfully.
    """
    return f"{row['ip']}|{row['dst_ip']}|{row['dst_port']}|{row['malware']}"

# =========================================================
# AUTO-UPDATE KNOWN_MALWARE IN THIS SCRIPT FILE
# =========================================================

def add_to_known_malware(malware_name):
    """
    Permanently adds *malware_name* (lowercased) to the KNOWN_MALWARE set
    defined in this script file so future runs treat it as known.
    Falls back gracefully if the file cannot be patched.
    """
    malware_lower = malware_name.lower()
    if malware_lower in KNOWN_MALWARE:
        return

    script_path = os.path.abspath(__file__)
    try:
        with open(script_path, "r", encoding="utf-8") as f:
            source = f.read()

        pattern = r"(KNOWN_MALWARE\s*=\s*\{)([^}]*?)(\})"
        match = re.search(pattern, source, re.DOTALL)
        if not match:
            log.warning("Could not locate KNOWN_MALWARE block in source — skipping auto-update.")
            return

        block_open  = match.group(1)
        block_body  = match.group(2)
        block_close = match.group(3)

        if f'"{malware_lower}"' in block_body:
            KNOWN_MALWARE.add(malware_lower)
            return

        new_entry  = f'    "{malware_lower}",\n'
        new_body   = block_body.rstrip() + "\n" + new_entry
        new_source = source[:match.start()] + block_open + new_body + block_close + source[match.end():]

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(new_source)

        KNOWN_MALWARE.add(malware_lower)
        log.info("KNOWN_MALWARE updated in script: added '%s'", malware_lower)

    except Exception as exc:
        log.warning("Could not auto-update KNOWN_MALWARE in script: %s", exc)

# =========================================================
# COLLECT CSV FILES
# =========================================================

def collect_csv_files(input_path):
    if os.path.isfile(input_path):
        if not input_path.lower().endswith(".csv"):
            log.warning("File does not have a .csv extension: %s", input_path)
        return [input_path]

    if os.path.isdir(input_path):
        files = glob.glob(os.path.join(input_path, "*.csv"))
        if not files:
            log.warning("No .csv files found in directory: %s", input_path)
        return sorted(files)

    files = glob.glob(input_path)
    csv_files = [f for f in files if f.lower().endswith(".csv")]
    if not csv_files:
        log.warning("No .csv files matched pattern: %s", input_path)
    return sorted(csv_files)

# =========================================================
# PERSISTENCE HELPERS
# =========================================================

def load_set(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def append_to_file(filepath, items):
    """Append new items to a persistence file without rewriting the whole thing."""
    with open(filepath, "a", encoding="utf-8") as f:
        for item in sorted(items):
            f.write(item + "\n")

# =========================================================
# ANALYZE CSV
# =========================================================

def analyze_csv(csv_file, seen_combos, seen_reports):
    """
    Read *csv_file* and return:
      - new_rows      : list of dicts — rows with fingerprints not in seen_combos
      - new_fingerprints : set of fingerprints from new_rows (to persist after writing)
      - new_malware_set  : malware names in new_rows that need OSINT reports
    Rows are deduplicated within this run too, so the same fingerprint appearing
    multiple times in one CSV is only emitted once.
    """
    new_rows          = []
    new_fingerprints  = set()
    new_malware_set   = set()
    seen_this_run     = set()   # dedup within the current file
    skipped_rows      = 0

    with open(csv_file, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for line_num, row in enumerate(reader, start=2):

            # Normalise all fields
            clean = {k: (row.get(k) or "").strip() for k in CSV_FIELDNAMES}

            # Flag encoding issues
            if "\ufffd" in "".join(row.values()):
                log.warning("Row %d in %s had undecodable bytes — may be incomplete.",
                            line_num, csv_file)
                skipped_rows += 1

            if not clean["asn"]:
                log.debug("Row %d skipped — missing ASN.", line_num)
                continue

            fp = make_fingerprint(clean)

            # Skip if seen in a previous run OR already emitted this run
            if fp in seen_combos or fp in seen_this_run:
                continue

            seen_this_run.add(fp)
            new_rows.append(clean)
            new_fingerprints.add(fp)

            malware_lower = clean["malware"].lower()
            if (clean["malware"]
                    and malware_lower not in KNOWN_MALWARE
                    and malware_lower not in seen_reports):
                new_malware_set.add(clean["malware"])

    if skipped_rows:
        log.warning("%d row(s) with encoding issues in: %s", skipped_rows, csv_file)

    return new_rows, new_fingerprints, new_malware_set

# =========================================================
# OUTPUT FOLDER HELPERS
# =========================================================

def create_output_root(scan_dir):
    """
    Single shared output folder created inside the scan directory.
    All ASN subfolders and reports land here alongside the scanned files.
    """
    path = os.path.join(scan_dir, OUTPUT_FOLDER_NAME)
    os.makedirs(path, exist_ok=True)
    return path

def create_asn_folder(output_folder, asn):
    """Subfolder inside output_folder named after the ASN."""
    safe  = asn.replace("/", "_")
    path  = os.path.join(output_folder, safe)
    os.makedirs(path, exist_ok=True)
    return path

# =========================================================
# WRITE PER-ASN CSV
# =========================================================

def write_asn_csv(asn_folder, asn, rows):
    """
    Write (or append to) <asn>.csv inside asn_folder.
    Rows are written in the order they arrive — already sorted by ASN
    grouping at the caller level.
    """
    safe = asn.replace("/", "_")
    path = os.path.join(asn_folder, f"{safe}.csv")
    file_exists = os.path.exists(path)

    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)

    log.info("ASN CSV updated: %s (%d rows)", path, len(rows))

# =========================================================
# WRITE COMBINED ALL-ASNs CSV
# =========================================================

def write_all_asns_csv(output_folder, rows_by_asn):
    """
    Write one combined CSV inside output_folder with all new events.
    Rows are grouped by ASN — all rows for ASN-A appear before ASN-B, etc.
    File is timestamped so each run produces a fresh snapshot.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    path      = os.path.join(output_folder, f"all_asns_{timestamp}.csv")

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for asn in sorted(rows_by_asn.keys()):
            writer.writerows(rows_by_asn[asn])

    total = sum(len(v) for v in rows_by_asn.values())
    log.info("Combined CSV written: %s (%d rows across %d ASNs)",
             path, total, len(rows_by_asn))

# =========================================================
# HTTP HELPER WITH RETRY + BACKOFF
# =========================================================

def http_post_with_retry(url, headers, data, timeout=20):
    for attempt in range(1, REQUEST_RETRIES + 1):
        try:
            resp = requests.post(url, headers=headers, data=data, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            log.warning("HTTP attempt %d/%d failed: %s", attempt, REQUEST_RETRIES, exc)
            if attempt < REQUEST_RETRIES:
                time.sleep(REQUEST_BACKOFF * attempt)
    return None

# =========================================================
# OSINT SEARCH
# =========================================================

def search_malware_info(malware):
    query    = f"{malware} malware threat analysis"
    response = http_post_with_retry(DUCKDUCKGO_URL, HEADERS, {"q": query})

    if response is None:
        log.error("All retry attempts failed for OSINT query: %s", malware)
        return None

    try:
        soup    = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("div", class_="result")[:5]

        summary       = ""
        description   = ""
        references    = []
        seen_snippets = set()

        for r in results:
            title_tag   = r.find("a", class_="result__a")
            snippet_tag = r.find("a", class_="result__snippet")
            if not title_tag:
                continue

            title       = title_tag.get_text(strip=True)
            snippet     = snippet_tag.get_text(strip=True) if snippet_tag else ""
            link        = title_tag.get("href", "")
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
            "Remediation": "Isolate affected systems and block all identified malicious indicators.",
        }

    except Exception as exc:
        log.error("Failed to parse OSINT results for %s: %s", malware, exc)
        return None

# =========================================================
# WORD REPORT
# =========================================================

def create_word_report(malware, intel, folder):
    doc = Document()
    doc.add_heading(f"Malware Threat Report: {malware}", 0)
    for section, content in intel.items():
        doc.add_heading(section, level=1)
        doc.add_paragraph(content)

    safe = malware.replace("/", "_").replace("\\", "_")
    path = os.path.join(folder, f"{safe}.docx")
    doc.save(path)
    log.info("Report created: %s", path)

# =========================================================
# PROCESS A SINGLE CSV FILE
# =========================================================

def process_file(csv_file, scan_dir):
    log.info("=" * 60)
    log.info("Processing: %s", csv_file)

    seen_combos  = load_set(SEEN_COMBOS_FILE)
    seen_reports = load_set(SEEN_REPORTS_FILE)

    is_first_run = len(seen_combos) == 0
    if is_first_run:
        log.info("No baseline found — this run establishes the baseline.")

    new_rows, new_fingerprints, new_malware_set = analyze_csv(
        csv_file, seen_combos, seen_reports
    )

    if not new_rows:
        log.info("No new attack patterns found in: %s", csv_file)
        return

    # ── Group new rows by ASN (preserving natural order within each ASN) ──
    rows_by_asn = {}
    for row in new_rows:
        asn = row["asn"]
        if asn not in rows_by_asn:
            rows_by_asn[asn] = []
        rows_by_asn[asn].append(row)

    # ── Ensure shared output root exists inside the scan directory ──
    output_root = create_output_root(scan_dir)

    # ── Write per-ASN CSVs — each ASN has one folder across all event files ──
    for asn, rows in sorted(rows_by_asn.items()):
        asn_folder = create_asn_folder(output_root, asn)
        write_asn_csv(asn_folder, asn, rows)

    # ── Persist new fingerprints — these become part of the baseline ──
    append_to_file(SEEN_COMBOS_FILE, new_fingerprints)
    log.info("Baseline updated: %d new fingerprints added.", len(new_fingerprints))

    # ── Generate Word reports for new malware families ──
    if new_malware_set:
        log.info("Generating malware reports for: %s", ", ".join(new_malware_set))
        for malware in new_malware_set:
            log.info("Fetching threat intel for: %s", malware)
            intel = search_malware_info(malware)
            if intel:
                create_word_report(malware, intel, output_root)
                # Persist immediately after each success
                append_to_file(SEEN_REPORTS_FILE, {malware.lower()})
                add_to_known_malware(malware)
            else:
                log.warning("No intel retrieved for: %s — report skipped.", malware)
    else:
        log.info("No new malware families — skipping Word reports.")

    log.info("Scan complete. New rows written to: %s", output_root)

    # Return rows so main() can write one combined all_asns across all files
    return rows_by_asn

# =========================================================
# MAIN
# =========================================================

def reset_baseline():
    """
    Wipe seen_combos.txt so the next run is treated as a fresh baseline.
    seen_malware_reports.txt is intentionally kept — already-generated Word
    reports should not be regenerated just because the scan baseline changed.
    """
    if os.path.exists(SEEN_COMBOS_FILE):
        os.remove(SEEN_COMBOS_FILE)
        log.info("Baseline reset: '%s' deleted. Next run will be treated as first scan.",
                 SEEN_COMBOS_FILE)
    else:
        log.info("No baseline file found — already clean, nothing to reset.")


def main():
    # ── Baseline reset prompt ─────────────────────────────────────────────
    if os.path.exists(SEEN_COMBOS_FILE):
        answer = input(
            f"\nExisting baseline detected ('{SEEN_COMBOS_FILE}').\n"
            "Reset it so this run is treated as a fresh baseline? [y/N]: "
        ).strip().lower()
        if answer == "y":
            reset_baseline()
        else:
            log.info("Keeping existing baseline.")
    # If the file does not exist yet, no prompt needed — already a clean state.

    input_path = input(
        "\nEnter a CSV file path, a directory, or a glob pattern (e.g. /data/*.csv): "
    ).strip()

    csv_files = collect_csv_files(input_path)
    if not csv_files:
        log.error("No CSV files found for input: %s", input_path)
        return

    log.info("Found %d CSV file(s) to process.", len(csv_files))

    # Accumulate all new rows across every CSV file processed this run
    all_rows_by_asn = {}

    # Derive scan directory from the first CSV — all files share the same location
    scan_dir = os.path.dirname(os.path.abspath(csv_files[0]))
    log.info("Scan directory: %s", scan_dir)

    for csv_file in csv_files:
        if not os.path.exists(csv_file):
            log.error("File not found, skipping: %s", csv_file)
            continue
        result = process_file(csv_file, scan_dir)
        if result:
            for asn, rows in result.items():
                if asn not in all_rows_by_asn:
                    all_rows_by_asn[asn] = []
                all_rows_by_asn[asn].extend(rows)

    # Write one combined all_asns CSV in the scan directory
    if all_rows_by_asn:
        write_all_asns_csv(scan_dir, all_rows_by_asn)

    log.info("All files processed.")

if __name__ == "__main__":
    main()