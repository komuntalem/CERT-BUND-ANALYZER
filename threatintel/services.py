"""
Core intelligence service layer for the CERT-BUND Analyzer.

Provides decoupled services callable from views, API endpoints, or management
commands.  Designed for modular integration — no assumptions about the calling
UI layer.

Services:
    ASNLookupService    – Team Cymru DNS WHOIS + PeeringDB fallback + DB cache
    MalwareService      – Malware record management
    CSVImportService    – Full + minimal CSV parsing with fingerprint computation
    SeenCombosService   – Hybrid audit-log (seen_combos.txt) persistence
    AdvisoryService     – Per-pair advisory generation with ADV-YYYY-NNNN numbering
    DocumentService     – DOCX export for advisories and email drafts
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import subprocess
import urllib.request
from datetime import date
from pathlib import Path
from typing import Iterable

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from docx import Document
from docx.shared import Pt, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH

from .models import ASN, Advisory, AnalysisRun, AttackEvent, EmailDraft, Malware

log = logging.getLogger(__name__)

# In-memory cache for advisory-description DDG lookups (per process lifetime).
# Key: lower-cased malware name. Value: 15-20-word description string.
_DDG_DESC_CACHE: dict[str, str] = {}


# ---------------------------------------------------------------------------
# ASN ENRICHMENT
# ---------------------------------------------------------------------------

class ASNLookupService:
    """Resolve ASN numbers to organization names via Team Cymru + PeeringDB.

    Resolution order:
        1.  Check DB cache (ASN.organization_name already populated)
        2.  Team Cymru DNS TXT lookup  (AS<n>.asn.cymru.com)
        3.  PeeringDB REST API         (https://www.peeringdb.com/api/net?asn=<n>)

    Results are cached in the ASN model so each ASN is looked up at most once.
    """

    @staticmethod
    def _extract_asn_number(asn_string: str) -> str:
        """Extract the numeric part from an ASN string like 'AS13335' or '13335'."""
        cleaned = asn_string.strip().upper()
        if cleaned.startswith("AS"):
            return cleaned[2:]
        return cleaned

    @staticmethod
    def _normalize_asn(asn_string: str) -> str:
        """Normalize to 'AS<number>' format."""
        num = ASNLookupService._extract_asn_number(asn_string)
        return f"AS{num}" if num else asn_string.strip().upper()

    # -- Team Cymru DNS TXT --------------------------------------------------

    @staticmethod
    def _lookup_cymru(asn_num: str) -> tuple[str, str]:
        """Query Team Cymru WHOIS via nslookup TXT record.

        TXT format: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
        Returns (organization_name, country_code).
        """
        try:
            result = subprocess.run(
                ["nslookup", "-type=TXT", f"AS{asn_num}.asn.cymru.com"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in result.stdout.split("\n"):
                match = re.search(r'"([^"]+)"', line)
                if match:
                    txt = match.group(1)
                    parts = [p.strip() for p in txt.split("|")]
                    if len(parts) >= 5:
                        country = parts[1]
                        org_name = parts[4]
                        # Team Cymru often appends ", CC" to org name — keep as-is
                        return org_name, country
        except FileNotFoundError:
            log.debug("nslookup not found — skipping Team Cymru DNS lookup.")
        except subprocess.TimeoutExpired:
            log.warning("Team Cymru DNS lookup timed out for AS%s.", asn_num)
        except Exception as exc:
            log.debug("Team Cymru lookup failed for AS%s: %s", asn_num, exc)
        return "", ""

    # -- PeeringDB REST API ---------------------------------------------------

    @staticmethod
    def _lookup_peeringdb(asn_num: str) -> tuple[str, str]:
        """Query PeeringDB REST API as fallback.

        Returns (organization_name, country_code).
        """
        try:
            url = f"https://www.peeringdb.com/api/net?asn={asn_num}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "CERT-BUND-Analyzer/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("data"):
                    net = data["data"][0]
                    return net.get("name", ""), ""
        except Exception as exc:
            log.debug("PeeringDB lookup failed for AS%s: %s", asn_num, exc)
        return "", ""

    # -- RIPE Stat REST API (third fallback) ----------------------------------

    @staticmethod
    def _lookup_ripestat(asn_num: str) -> tuple[str, str]:
        """Query the RIPE Stat AS-overview endpoint as a third fallback.

        Covers all five RIRs (RIPE, ARIN, APNIC, LACNIC, AFRINIC) and returns
        the authoritative holder name registered with the routing registry.
        No API key required.  Endpoint is stable and publicly documented.

        API: https://stat.ripe.net/data/as-overview/data.json?resource=AS<n>
        Returns (organization_name, country_code).
        """
        try:
            url = (
                f"https://stat.ripe.net/data/as-overview/data.json"
                f"?resource=AS{asn_num}"
            )
            req = urllib.request.Request(
                url, headers={"User-Agent": "CERT-BUND-Analyzer/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                holder = data.get("data", {}).get("holder", "")
                if holder:
                    return holder, ""
        except Exception as exc:
            log.debug("RIPE Stat lookup failed for AS%s: %s", asn_num, exc)
        return "", ""

    # -- Name normalisation ---------------------------------------------------

    @staticmethod
    def _clean_org_name(name: str) -> str:
        """Normalise raw organisation-name strings from external sources.

        Different sources return names with different artefacts:

        * Team Cymru TXT records:  ``CLOUDFLARENET, US``
          (routing handle + comma + 2-letter country code)
        * RIPE Stat holder field:  ``CLOUDFLARENET - Cloudflare, Inc.``
          (short ASN handle + " - " + full registered name)

        Strategy:
          1. If the name contains " - ", split on the first occurrence and
             keep the **longer** side — that is always the human-readable
             registered name, never the terse routing handle.
          2. Strip a trailing ", XX" 2-letter country-code suffix.
          3. Collapse extra whitespace.
        """
        if not name:
            return name
        name = name.strip()
        # "HANDLE - Full Registered Name"  →  take the longer part
        if " - " in name:
            left, right = name.split(" - ", 1)
            name = right.strip() if len(right.strip()) >= len(left.strip()) else left.strip()
        # "ORG NAME, US"  →  strip trailing 2-letter country-code suffix
        name = re.sub(r",\s*[A-Z]{2}$", "", name).strip()
        return name

    # -- Public API -----------------------------------------------------------

    @staticmethod
    def resolve_organization(asn_number: str) -> tuple[str, str]:
        """Resolve ASN to (org_name, country).

        Resolution order:
            1. Team Cymru DNS TXT  (nslookup — fast, authoritative)
            2. PeeringDB REST API  (covers voluntarily-registered networks)
            3. RIPE Stat REST API  (covers all 5 RIRs — broadest coverage)

        The winning name is always passed through ``_clean_org_name()`` to
        strip routing-handle prefixes and country-code suffixes before storage.
        """
        asn_num = ASNLookupService._extract_asn_number(asn_number)
        if not asn_num.isdigit():
            return "", ""

        org, country = ASNLookupService._lookup_cymru(asn_num)
        if org:
            org = ASNLookupService._clean_org_name(org)
            log.info("Team Cymru resolved AS%s → %s (%s)", asn_num, org, country)
            return org, country

        org, country = ASNLookupService._lookup_peeringdb(asn_num)
        if org:
            org = ASNLookupService._clean_org_name(org)
            log.info("PeeringDB resolved AS%s → %s", asn_num, org)
            return org, country

        org, country = ASNLookupService._lookup_ripestat(asn_num)
        if org:
            org = ASNLookupService._clean_org_name(org)
            log.info("RIPE Stat resolved AS%s → %s", asn_num, org)
            return org, country

        log.warning("Could not resolve organization for AS%s.", asn_num)
        return "", ""

    @staticmethod
    def ensure_asn(asn_number: str) -> ASN:
        """Get or create an ASN record with automatic enrichment.

        If the org name is missing, triggers external lookup and caches the
        result.  Updates ``last_seen`` on every call.
        """
        normalized = ASNLookupService._normalize_asn(asn_number)

        asn, created = ASN.objects.get_or_create(
            asn_number=normalized,
            defaults={"organization_name": ""},
        )

        # Enrich if organization name is still blank
        if not asn.organization_name:
            org, country = ASNLookupService.resolve_organization(normalized)
            update_fields = []
            if org:
                asn.organization_name = org
                update_fields.append("organization_name")
            if country:
                asn.country = country
                update_fields.append("country")
            if update_fields:
                asn.save(update_fields=update_fields)

        # Always update last_seen
        asn.last_seen = timezone.now()
        asn.save(update_fields=["last_seen"])

        return asn


# ---------------------------------------------------------------------------
# MALWARE SERVICE
# ---------------------------------------------------------------------------

class MalwareService:
    """Ensure Malware records exist without duplicates."""

    @staticmethod
    def ensure_malware(
        name: str,
        description: str = "",
        risk_level: str = "Medium",
    ) -> Malware:
        malware, created = Malware.objects.get_or_create(
            malware_name=name,
            defaults={"description": description, "risk_level": risk_level},
        )
        return malware


# ---------------------------------------------------------------------------
# SEEN-COMBOS HYBRID PERSISTENCE
# ---------------------------------------------------------------------------

class SeenCombosService:
    """Manages the seen_combos.txt audit-trail file.

    This file is an append-only log of ALL fingerprints processed across every
    run — including duplicates.  It serves as an immutable forensic record
    independent of the database deduplication layer (AttackEvent).
    """

    FILENAME = "seen_combos.txt"

    @staticmethod
    def _project_base_dir() -> Path:
        base_dir = getattr(settings, "BASE_DIR", None)
        if base_dir:
            return Path(base_dir)
        return Path(__file__).resolve().parent.parent

    @staticmethod
    def _filepath() -> str:
        return os.path.join(str(SeenCombosService._project_base_dir()), SeenCombosService.FILENAME)

    @staticmethod
    def append_fingerprints(fingerprints: Iterable[str]) -> None:
        """Append only new, unique fingerprints to the audit log that are not already present."""
        path = SeenCombosService._filepath()
        existing = set()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    val = line.strip()
                    if val:
                        existing.add(val)

        new_unique = []
        for fp in fingerprints:
            fp_clean = fp.strip()
            if fp_clean and fp_clean not in existing and fp_clean not in new_unique:
                new_unique.append(fp_clean)

        if new_unique:
            with open(path, "a", encoding="utf-8") as f:
                for fp in new_unique:
                    f.write(fp + "\n")
            log.info("Appended %d new unique fingerprint(s) to %s.", len(new_unique), path)
        else:
            log.info("No new unique fingerprints to append to %s.", path)

    @staticmethod
    def load_all() -> list[str]:
        """Load all fingerprints from seen_combos.txt for dashboard analysis."""
        path = SeenCombosService._filepath()
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    @staticmethod
    def count() -> int:
        """Return the total number of fingerprint entries in the audit log."""
        path = SeenCombosService._filepath()
        if not os.path.exists(path):
            return 0
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())


# ---------------------------------------------------------------------------
# CSV IMPORT
# ---------------------------------------------------------------------------

class CSVImportService:
    """Parse CERT-Bund CSV files supporting both full and minimal formats.

    Full format columns:
        asn, ip, timestamp, malware, src_port, dst_ip, dst_port, dst_host, proto

    Minimal format columns:
        asn, malware

    Missing fields degrade gracefully — they are stored as empty strings and
    the fingerprint is still computed (empty components become empty segments).
    """

    @staticmethod
    def make_fingerprint(row: dict) -> str:
        """Compute attack-pattern fingerprint: ip|dst_ip|dst_port|malware.

        Matches the original certbundcsvanalyserv2.py fingerprint scheme.
        """
        ip = row.get("ip", "").strip()
        dst_ip = row.get("dst_ip", "").strip()
        dst_port = row.get("dst_port", "").strip()
        malware = row.get("malware", "").strip()
        return f"{ip}|{dst_ip}|{dst_port}|{malware}"

    @staticmethod
    def parse_csv(uploaded_file) -> list[dict]:
        """Parse an uploaded CSV file into normalized row dicts.

        Each dict includes all known fields (empty string for missing columns)
        plus a computed ``fingerprint`` key.
        """
        text = uploaded_file.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))

        rows: list[dict] = []
        for row in reader:
            asn = (row.get("asn") or "").strip()
            if not asn:
                continue

            raw_malware = (row.get("malware") or "").strip()
            if not raw_malware:
                if "key_hash" in row or "username" in row:
                    raw_malware = "Cowrie"
                else:
                    raw_malware = "Unknown"

            clean = {
                "asn": asn,
                "malware": raw_malware,
                "ip": (row.get("ip") or "").strip(),
                "dst_ip": (row.get("dst_ip") or "").strip(),
                "dst_port": (row.get("dst_port") or "").strip(),
                "src_port": (row.get("src_port") or "").strip(),
                "timestamp": (row.get("timestamp") or "").strip(),
                "dst_host": (row.get("dst_host") or "").strip(),
                "proto": (row.get("proto") or "").strip(),
            }
            clean["fingerprint"] = CSVImportService.make_fingerprint(clean)
            rows.append(clean)

        return rows


# ---------------------------------------------------------------------------
# ADVISORY GENERATION
# ---------------------------------------------------------------------------

class AdvisoryService:
    """Generate advisories and email drafts from processed CSV data.

    Advisories are created per unique ASN/Organization per run — one advisory
    per organization aggregating all malware families detected.
    Advisory numbers follow the ``ADV-YYYY-NNNN`` scheme with year-based
    sequential reset.
    """

    @staticmethod
    def _next_advisory_number() -> str:
        """Generate the next sequential advisory number in the format UCC-CERT-NNN."""
        prefix = "UCC-CERT-"
        last = (
            Advisory.objects.filter(advisory_number__startswith=prefix)
            .order_by("-advisory_number")
            .first()
        )
        if last and last.advisory_number:
            try:
                seq = int(last.advisory_number.split("-")[-1]) + 1
            except (ValueError, IndexError):
                seq = 1
        else:
            seq = 1
        return f"{prefix}{seq:03d}"

    @staticmethod
    def build_email_body(advisory: Advisory) -> str:  # noqa: ARG004  (advisory kept for API compat)
        """Return the fixed notification email body template.

        The body is intentionally static — sensitive advisory details are
        communicated via the attached DOCX document, not the email body.
        """
        return (
            "Hello,\n\n"
            "Please find attached a security advisory regarding detected "
            "malicious activity associated with your network.\n\n"
            "Kindly review the advisory and take the recommended actions "
            "to address the identified issue.\n\n"
            "Thank you.\n\n"
            "Regards,\n"
            "CERT Team"
        )

    # ------------------------------------------------------------------
    # Description helpers (DDG primary, DB fallback)
    # ------------------------------------------------------------------

    @staticmethod
    def _smart_summarize(text: str, min_w: int = 15, max_w: int = 20) -> str:
        """Extract a meaningful min_w–max_w word description from *text*.

        Strategy (in order):
        1. Find the first complete sentence whose word count is in [min_w, max_w].
        2. If the first sentence is longer than max_w, slice the first sentence smartly.
        3. If the first sentence is shorter than min_w, pool words across all sentences and slice smartly.
        4. Fallback: return whatever words are available, sliced smartly.
        """
        if not text:
            return ""
        # Clean up multiple dots / ellipsis (e.g. '....' or '...') to a single period
        text = re.sub(r"\.{3,}", ".", text)
        # Clean up spaces before terminal punctuation (e.g. 'can .' -> 'can.')
        text = re.sub(r"\s+([.!?])", r"\1", text)
        text = re.sub(r"\s+", " ", text).strip()

        BAD_ENDINGS = {
            'and', 'or', 'but', 'of', 'in', 'on', 'at', 'to', 'for', 'with', 'by', 'from', 'about', 'as', 'into', 
            'through', 'during', 'including', 'until', 'against', 'among', 'throughout', 'despite', 'towards', 
            'upon', 'concerning', 'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 
            'has', 'had', 'which', 'who', 'whom', 'whose', 'that', 'this', 'these', 'those', 'it', 'its', 
            'their', 'his', 'her', 'our', 'your', 'my', 'them', 'us', 'him', 'me', 'often', 'also', 'known', 
            'primarily', 'such', 'other', 'via', 'through', 'can', 'could', 'will', 'would', 'shall', 'should', 
            'may', 'might', 'must', 'has', 'have', 'had', 'is', 'are', 'was', 'were', 'be', 'been'
        }

        GOOD_BEFORE = {
            'and', 'or', 'but', 'of', 'in', 'on', 'at', 'to', 'for', 'with', 'by', 'from', 'about', 'as', 'into', 
            'through', 'which', 'who', 'that', 'such', 'especially', 'often', 'primarily', 'to', 'via'
        }

        # Split into sentences on period / excl / question mark followed by space
        sentences = re.split(r"(?<=[.!?])\s+", text)
        sentences = [s.strip() for s in sentences if len(s.split()) > 1]

        # 1. First complete in-range sentence wins (must not end in a bad word)
        for sent in sentences:
            words = sent.split()
            if min_w <= len(words) <= max_w:
                last_w = words[-1].lower().rstrip(".,;:-()[]{}'\"")
                if last_w not in BAD_ENDINGS:
                    return sent.rstrip(".,;:-") + "."

        def smart_slice(words_list: list[str]) -> str:
            if len(words_list) <= min_w:
                return " ".join(words_list)
            best_len = max_w
            best_score = -9999
            upper_bound = min(max_w, len(words_list))
            for L in range(min_w, upper_bound + 1):
                score = 0
                last_word = words_list[L-1].lower().rstrip(".,;:-()[]{}'\"")
                original_last = words_list[L-1]
                if original_last.endswith(('.', '!', '?')):
                    score += 20
                elif original_last.endswith((',', ';', ':', '-')):
                    score += 10
                if last_word in BAD_ENDINGS:
                    score -= 15
                if L < len(words_list):
                    next_word = words_list[L].lower().rstrip(".,;:-")
                    if next_word in GOOD_BEFORE:
                        score += 8
                score += L * 0.1
                if score > best_score:
                    best_score = score
                    best_len = L
            return " ".join(words_list[:best_len])

        if not sentences:
            # No sentence boundary — treat the whole text as one block
            all_words = text.split()
            return smart_slice(all_words).rstrip(".,;:-") + "."

        first_words = sentences[0].split()

        # 2. First sentence is too long — take first max_w words cleanly
        if len(first_words) > max_w:
            return smart_slice(first_words).rstrip(".,;:-") + "."

        # 3. First sentence too short — pool words from all sentences, then slice.
        all_words = " ".join(sentences).split()
        return smart_slice(all_words).rstrip(".,;:-") + "."

    @staticmethod
    def _fetch_ddg_description(malware_name: str, timeout: int = 8) -> str:
        """Query DuckDuckGo HTML search via GET and extract a 15–20 word description.

        Returns an empty string if the search fails or yields no relevant result.
        Uses *_DDG_DESC_CACHE* to avoid re-querying within the same process.
        """
        cache_key = malware_name.strip().lower()
        if cache_key in _DDG_DESC_CACHE:
            return _DDG_DESC_CACHE[cache_key]

        import urllib.parse
        import html as html_lib

        query = f"{malware_name} malware"
        ddg_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote_plus(query)}"

        try:
            req = urllib.request.Request(
                ddg_url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
                    ),
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_html = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            log.debug("DDG description fetch failed for '%s': %s", malware_name, exc)
            _DDG_DESC_CACHE[cache_key] = ""
            return ""

        # --- Extract snippets ---
        snippets: list[str] = []
        try:
            from bs4 import BeautifulSoup as _BS
            soup = _BS(raw_html, "html.parser")
            for tag in soup.find_all("a", class_="result__snippet")[:8]:
                text = tag.get_text(separator=" ", strip=True)
                if text:
                    snippets.append(html_lib.unescape(text))
        except ImportError:
            # regex fallback
            raw_snippets = re.findall(
                r'class="result__snippet"[^>]*>(.*?)</a>',
                raw_html,
                re.DOTALL | re.IGNORECASE,
            )
            for rs in raw_snippets[:8]:
                cleaned = re.sub(r"<[^>]+>", " ", rs)
                cleaned = html_lib.unescape(cleaned)
                cleaned = re.sub(r"\s+", " ", cleaned).strip()
                if cleaned:
                    snippets.append(cleaned)

        name_lower = malware_name.lower()
        # Whole-word relevance pattern (case-insensitive)
        name_pattern = re.compile(r'\b' + re.escape(name_lower) + r'\b', re.IGNORECASE)
        for snippet in snippets:
            # Clean up DDG bold-tag artifacts that leave trailing '. '
            snippet = re.sub(r'\.\s*$', '.', snippet.strip())
            snippet = re.sub(r'\s+', ' ', snippet).strip()
            # Skip if it doesn't actually mention the malware (whole-word)
            if not name_pattern.search(snippet):
                continue
            # Skip snippets that end suspiciously (looks like cut mid-sentence)
            if snippet.endswith((', ', '. ', '- ', 'also known as .')):
                continue
            summary = AdvisoryService._smart_summarize(snippet, 15, 20)
            if summary:
                _DDG_DESC_CACHE[cache_key] = summary
                log.debug(
                    "DDG description for '%s': %s", malware_name, summary
                )
                return summary

        _DDG_DESC_CACHE[cache_key] = ""
        return ""

    @staticmethod
    def _get_advisory_description(malware_name: str, db_text: str) -> str:
        """Return a 15–20 word description for *malware_name*.

        Primary source:  DuckDuckGo live search.
        Fallback source: *db_text* (from MalwareEntry.description or
                         executive_summary) — summarised meaningfully,
                         never blindly truncated.
        Last resort:     generic placeholder.
        """
        # 1. Try DDG live search
        ddg_result = AdvisoryService._fetch_ddg_description(malware_name)
        if ddg_result and len(ddg_result.split()) >= 15:
            return ddg_result

        # 2. Summarise the DB text meaningfully
        if db_text and db_text.strip():
            summary = AdvisoryService._smart_summarize(db_text.strip(), 15, 20)
            if summary and len(summary.split()) >= 15:
                return summary

        # 3. Last resort (17 words)
        return f"{malware_name} is an active malware threat detected on the network. Please generate a full malware analysis report."

    # ------------------------------------------------------------------

    @staticmethod
    def build_advisory_html(advisory: Advisory) -> str:
        """Construct the letter format HTML for an advisory, retrieving and summarizing
        details from the malware_views module database entries.
        """

        # 1. Gather all associated threatintel.Malware objects
        malware_families = list(advisory.malware_families.all())

        # 2. Look up matching malware_views.models.MalwareEntry objects
        malware_details = []
        found_malware_names = set()   # lower-case names of malware with DB entries

        try:
            from malware_views.models import MalwareEntry
        except ImportError:
            MalwareEntry = None

        for mw in malware_families:
            entry = None
            if MalwareEntry:
                entry = MalwareEntry.objects.filter(name__iexact=mw.malware_name).first()

            if entry:
                severity_val = entry.severity or "High"
                risk_val = severity_val.capitalize()
                impact_val = risk_val

                # Get a 15-20 word description: DDG primary, DB fallback
                raw_desc = entry.description or entry.executive_summary or ""
                desc_val = AdvisoryService._get_advisory_description(mw.malware_name, raw_desc)

                malware_details.append({
                    "name": entry.name,
                    "description": desc_val,
                    "risk": risk_val,
                    "impact": impact_val,
                    "is_new": False,
                })
                found_malware_names.add(mw.malware_name.lower())
            else:
                # New malware not in DB — show actual name so analyst knows which
                # report to go and generate.
                malware_details.append({
                    "name": mw.malware_name,
                    "description": "New malware detected. Please generate a malware report.",
                    "risk": "Unknown",
                    "impact": "Unknown",
                    "is_new": True,
                })

        # 3. Build a curated full-sentence recommendation list.
        #    We never rely on the short generic phrases stored in the DB —
        #    those are "Isolate affected systems", "Block network indicators" etc.
        #    Instead we always emit the full analyst-grade sentences below, selecting
        #    only those relevant to the malware families present.

        # Check if the advisory only contains "Unknown" malware.
        # If so, we do not show any recommendations as the threat is unspecified.
        only_unknown = all(mw.malware_name.lower() == "unknown" for mw in malware_families) if malware_families else True

        recommendations: list[str] = []
        if not only_unknown:
            # Start with universal actions (always included)
            recommendations = [
                "Immediately isolate the hosts/systems associated with the identified IP addresses, investigate to confirm compromise, preserve logs, and proceed with containment, eradication, and recovery.",
                "Block all identified malicious IP addresses, domains, and command-and-control communication by reviewing firewalls, proxy, DNS, and endpoint logs for suspicious outbound connections.",
                "Deploy or update advanced endpoint protection and conduct threat hunting for file-infectors, RATs, spyware, credential stealers, worms, banking trojans, and botnet activity across all endpoints.",
                "Reset credentials used on affected systems, including email, VPN, administrator, banking, and other sensitive accounts that may have been exposed or exfiltrated.",
                "Update antivirus signatures, apply all outstanding security patches, and review firewall and IDS/IPS rules to prevent re-infection and lateral movement.",
                "Preserve forensic evidence from affected hosts for incident response, including memory dumps, disk images, event logs, and network capture files.",
            ]

            # Add malware-family-specific recommendations where relevant
            seen_names_lower = {mw.malware_name.lower() for mw in malware_families}

            if any("vo1d2" in n or "void2" in n or "android" in n for n in seen_names_lower):
                recommendations.append(
                    "Review and block uncertified, unmanaged, or non-compliant Android devices "
                    "associated with Android.Vo1d2 indicators, and audit all mobile device management policies."
                )

            if any("vipersoftx" in n or "viparsoftx" in n for n in seen_names_lower):
                recommendations.append(
                    "Remove cracked software, unauthorized tools, and suspicious downloads commonly "
                    "used to deliver malware such as ViperSoftX, and enforce software whitelisting policies."
                )

            if any("prometei" in n or "mining" in n or "miner" in n for n in seen_names_lower):
                recommendations.append(
                    "Check for unauthorized cryptocurrency mining activity, including abnormal CPU/GPU "
                    "usage, unknown processes, and suspicious scheduled tasks or cron jobs."
                )

            if any("pykspa" in n or "andromeda" in n or "botnet" in n for n in seen_names_lower):
                recommendations.append(
                    "Investigate botnet command-and-control traffic, sinkhole or null-route known C2 "
                    "infrastructure, and monitor DNS requests for DGA-generated domain lookups."
                )

            if any("ghostweaver" in n or "rat" in n or "backdoor" in n for n in seen_names_lower):
                recommendations.append(
                    "Conduct a thorough hunt for persistence mechanisms including scheduled tasks, "
                    "registry run keys, and fileless PowerShell-based remote access tools (RATs)."
                )

            recommendations.append(
                "Continue monitoring all affected network segments after remediation and report "
                "further suspicious activity to the CERT team immediately."
            )

        # Deduplicate (preserve order, compare normalised)
        seen_norms: set[str] = set()
        deduped_recommendations: list[str] = []
        for rec in recommendations:
            norm = rec.lower().rstrip(". ").strip()
            if norm not in seen_norms:
                seen_norms.add(norm)
                deduped_recommendations.append(rec)

        # 4. Generate the template content
        org_name = advisory.asn.get_display_name()
        adv_num = advisory.advisory_number or "Draft"
        adv_date = advisory.advisory_date.strftime("%B %d, %Y") if advisory.advisory_date else date.today().strftime("%B %d, %Y")

        # Format rows of the table
        table_rows = ""
        for md in malware_details:
            name_style = "font-family: monospace;"
            desc_style = ""
            if md["is_new"]:
                name_style += " color: #ef4444; font-weight: bold;"
                desc_style += " color: #ef4444; font-weight: bold;"

            table_rows += f"""    <tr>
      <td style="padding: 10px; border: 1px solid #000000; {name_style}">{md['name']}</td>
      <td style="padding: 10px; border: 1px solid #000000; {desc_style}">{md['description']}</td>
      <td style="padding: 10px; border: 1px solid #000000; text-align: center;">{md['risk']}</td>
      <td style="padding: 10px; border: 1px solid #000000; text-align: center;">{md['impact']}</td>
    </tr>\n"""

        # Format recommendations
        rec_html = ""
        if deduped_recommendations:
            rec_list = ""
            for rec in deduped_recommendations:
                rec_list += f"  <li>{rec}</li>\n"
            rec_html = f"<ol>\n{rec_list}</ol>"
        else:
            rec_html = "<p>No recommendations available for unknown malware.</p>"

        # Construct final HTML
        html = f"""<p>Dear {org_name} Team,</p>

<p><strong>Advisory Number:</strong> {adv_num}<br>
<strong>Date of Issuance:</strong> {adv_date}<br>
<strong>Identified Asset:</strong> List of Identified IP addresses attached.</p>

<p>Please find attached details of IP addresses within your network that are associated with hosts most likely compromised by malware. These IP addresses should be treated as indicators of potentially affected systems and require immediate investigation, containment, and remediation.</p>

<p><strong>Description of the Identified Malware.</strong></p>

<table style="width: 100%; border-collapse: collapse; border: 1px solid #000000; margin-bottom: 20px;" border="1">
  <thead>
    <tr style="background-color: #f2f2f2;">
      <th style="padding: 10px; border: 1px solid #000000; text-align: left; width: 20%;">MALWARE</th>
      <th style="padding: 10px; border: 1px solid #000000; text-align: left; width: 50%;">DESCRIPTION</th>
      <th style="padding: 10px; border: 1px solid #000000; text-align: center; width: 15%;">RISK</th>
      <th style="padding: 10px; border: 1px solid #000000; text-align: center; width: 15%;">IMPACT</th>
    </tr>
  </thead>
  <tbody>
{table_rows}  </tbody>
</table>

<p><strong>Recommended Actions:</strong></p>
{rec_html}

<p>You are required to submit an initial status update within 48 hours from receipt of this advisory via the feedback form below.</p>

<p><a href="https://forms.office.com/pages/responsepage.aspx?id=Xs3_98BEhkaEUnjqV0Mt51BLmTH0Iw5ApxjklnxERGdUOFRFTkYzQ0dTTTJFSUhaUVY2VUVVRlc5My4u&amp;route=shorturl" target="_blank" style="color: #0563C1; text-decoration: underline;"><strong>UCC-CERT CYBERSECURITY ADVISORY FEEDBACK FORM &#8211; Fill out form</strong></a></p>

<p>Kind regards,</p>
"""
        return html

    @staticmethod
    def process_csv_upload(
        source_file_name: str, rows: list[dict]
    ) -> AnalysisRun:
        """Complete CSV-to-advisory processing workflow.

        Execution order (per requirements):
            1.  Create AnalysisRun
            2.  Pre-enrich unique ASNs   (outside transaction — HTTP calls)
            3.  Process rows in transaction:
                a.  Compute fingerprint
                b.  Check AttackEvent table for dedup
                c.  If new → create AttackEvent, group for advisory
            4.  ALWAYS append ALL fingerprints to seen_combos.txt
            5.  Generate one advisory per ASN/Organization
            6.  Generate one email draft per advisory
            7.  Update AnalysisRun with final counts
        """
        # -- Phase 0: Create the run ----------------------------------------
        run = AnalysisRun.objects.create(
            source_file_name=source_file_name,
            row_count=len(rows),
            status="processing",
        )

        try:
            # -- Phase 1: Pre-enrich ASNs (HTTP — outside transaction) ------
            unique_asn_numbers = {row["asn"] for row in rows}
            asn_cache: dict[str, ASN] = {}
            for asn_num in unique_asn_numbers:
                asn_cache[asn_num] = ASNLookupService.ensure_asn(asn_num)

            # -- Phase 2: Collect all fingerprints for audit log -------------
            all_fingerprints = [row["fingerprint"] for row in rows]

            # -- Phase 3: Process events in transaction ----------------------
            new_events_by_asn: dict[int, dict] = {}
            new_event_count = 0

            with transaction.atomic():
                for row in rows:
                    fp = row["fingerprint"]

                    # Dedup against AttackEvent table
                    if AttackEvent.objects.filter(fingerprint=fp).exists():
                        continue

                    asn = asn_cache.get(row["asn"]) or ASNLookupService.ensure_asn(
                        row["asn"]
                    )
                    malware = MalwareService.ensure_malware(row["malware"])

                    AttackEvent.objects.create(
                        analysis_run=run,
                        asn=asn,
                        malware=malware,
                        fingerprint=fp,
                        ip=row.get("ip", ""),
                        dst_ip=row.get("dst_ip", ""),
                        dst_port=row.get("dst_port", ""),
                        src_port=row.get("src_port", ""),
                        event_timestamp=row.get("timestamp", ""),
                        dst_host=row.get("dst_host", ""),
                        proto=row.get("proto", ""),
                    )
                    new_event_count += 1

                    # Group by ASN for org-level advisory generation
                    asn_key = asn.pk
                    if asn_key not in new_events_by_asn:
                        new_events_by_asn[asn_key] = {
                            "asn": asn,
                            "malware_set": set(),
                            "malware_objects": {},
                            "count": 0,
                        }
                    new_events_by_asn[asn_key]["malware_set"].add(malware.pk)
                    new_events_by_asn[asn_key]["malware_objects"][malware.pk] = malware
                    new_events_by_asn[asn_key]["count"] += 1

            # -- Phase 4: Audit log (always, independent of dedup) ----------
            SeenCombosService.append_fingerprints(all_fingerprints)

            # -- Phase 5+6: Generate advisories + email drafts ---------------
            advisory_count = 0
            with transaction.atomic():
                for asn_data in new_events_by_asn.values():
                    asn = asn_data["asn"]
                    malware_objects = list(asn_data["malware_objects"].values())
                    event_count = asn_data["count"]

                    advisory_number = AdvisoryService._next_advisory_number()
                    malware_names = ", ".join(
                        mw.malware_name for mw in malware_objects
                    )
                    summary = (
                        f"Detected {event_count} unique attack event(s) involving "
                        f"malware: {malware_names} — targeting network assets "
                        f"associated with {asn.get_display_name()} ({asn.asn_number})."
                    )
                    mitigation = (
                        "1. Isolate affected systems immediately.\n"
                        "2. Block all identified malicious IP addresses and domains.\n"
                        "3. Update antivirus signatures and scan all endpoints.\n"
                        "4. Review firewall and IDS/IPS rules.\n"
                        "5. Escalate to security operations for further investigation.\n"
                        "6. Preserve forensic evidence for incident response."
                    )

                    advisory = Advisory.objects.create(
                        advisory_number=advisory_number,
                        advisory_date=date.today(),
                        asn=asn,
                        summary=summary,
                        recommended_mitigation=mitigation,
                        content=f"{summary}\n\n{mitigation}",
                        status="draft",
                        source_run=run,
                    )
                    advisory.malware_families.set(malware_objects)
                    advisory.html_content = AdvisoryService.build_advisory_html(advisory)
                    advisory.save()

                    EmailDraft.objects.create(
                        advisory=advisory,
                        subject=(
                            f"Cybersecurity Advisory Notification – "
                            f"{asn.get_display_name()}"
                        ),
                        body=AdvisoryService.build_email_body(advisory),
                    )
                    advisory_count += 1

            # -- Phase 7: Finalize run --------------------------------------
            run.new_event_count = new_event_count
            run.advisory_count = advisory_count
            run.status = "completed"
            run.save(update_fields=["new_event_count", "advisory_count", "status"])

            log.info(
                "CSV processing complete: %s — %d rows, %d new events, "
                "%d advisories generated.",
                source_file_name,
                len(rows),
                new_event_count,
                advisory_count,
            )

        except Exception:
            run.status = "failed"
            run.save(update_fields=["status"])
            log.exception("CSV processing failed for %s.", source_file_name)
            raise

        return run


# ---------------------------------------------------------------------------
# DOCUMENT GENERATION
# ---------------------------------------------------------------------------

class DocumentService:
    """Generate DOCX documents for advisories and email drafts.

    All generation is done in memory (returns bytes) without creating disk files.
    """

    @staticmethod
    def html_to_docx_bytes(html_content: str) -> bytes:
        import io
        from bs4 import BeautifulSoup, NavigableString
        from docx.shared import RGBColor
        
        doc = Document()
        
        # Configure standard margins (1 inch)
        for section in doc.sections:
            section.top_margin = Inches(1)
            section.bottom_margin = Inches(1)
            section.left_margin = Inches(1)
            section.right_margin = Inches(1)
            
        soup = BeautifulSoup(html_content, "html.parser")
        
        def process_element(element, paragraph=None):
            if isinstance(element, NavigableString):
                if paragraph and element.strip():
                    paragraph.add_run(element)
                return
                
            tag = element.name
            if tag in ["p", "div"]:
                p = doc.add_paragraph()
                for child in element.children:
                    process_run(child, p)
            elif tag in ["h1", "h2", "h3", "h4", "h5", "h6"]:
                level = int(tag[1])
                p = doc.add_heading("", level=level)
                for child in element.children:
                    process_run(child, p)
            elif tag == "ol":
                for i, li in enumerate(element.find_all("li", recursive=False), 1):
                    p = doc.add_paragraph()
                    p.paragraph_format.left_indent = Inches(0.25)
                    r = p.add_run(f"{i}. ")
                    r.bold = True
                    for child in li.children:
                        process_run(child, p)
            elif tag == "ul":
                for li in element.find_all("li", recursive=False):
                    p = doc.add_paragraph(style="List Bullet")
                    for child in li.children:
                        process_run(child, p)
            elif tag == "table":
                rows = element.find_all("tr")
                if not rows:
                    return
                
                col_count = 0
                for tr in rows:
                    cols = tr.find_all(["td", "th"])
                    col_count = max(col_count, len(cols))
                    
                table = doc.add_table(rows=0, cols=col_count)
                table.style = "Table Grid"
                
                for tr in rows:
                    row_cells = table.add_row().cells
                    cols = tr.find_all(["td", "th"])
                    for i, col in enumerate(cols):
                        if i >= col_count:
                            break
                        cell = row_cells[i]
                        
                        if len(cell.paragraphs) > 0:
                            p = cell.paragraphs[0]
                        else:
                            p = cell.add_paragraph()
                            
                        is_header = (col.name == "th" or tr.parent.name == "thead")
                        
                        for child in col.children:
                            if child.name in ["p", "div"]:
                                p_cell = cell.add_paragraph()
                                for gc in child.children:
                                    process_run(gc, p_cell, force_bold=is_header)
                            else:
                                process_run(child, p, force_bold=is_header)
            else:
                for child in element.children:
                    process_element(child)

        def process_run(element, paragraph, force_bold=False, force_italic=False, force_underline=False):
            if isinstance(element, NavigableString):
                val = str(element)
                if val:
                    run = paragraph.add_run(val)
                    if force_bold:
                        run.bold = True
                    if force_italic:
                        run.italic = True
                    if force_underline:
                        run.underline = True
                return

            tag = element.name
            bold = force_bold or (tag in ["strong", "b"])
            italic = force_italic or (tag in ["em", "i"])
            underline = force_underline or (tag in ["u"])
            
            if tag == "a":
                link_runs_start = len(paragraph.runs)
                for child in element.children:
                    process_run(child, paragraph, force_bold=bold, force_italic=italic, force_underline=True)
                for r in paragraph.runs[link_runs_start:]:
                    r.font.color.rgb = RGBColor(5, 99, 193)
            else:
                for child in element.children:
                    process_run(child, paragraph, force_bold=bold, force_italic=italic, force_underline=underline)

        for child in soup.children:
            process_element(child)
            
        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()

    @staticmethod
    def generate_advisory_docx(advisory: Advisory) -> bytes:
        """Generate the advisory DOCX document from html_content in memory."""
        html_content = advisory.html_content
        if not html_content:
            html_content = AdvisoryService.build_advisory_html(advisory)
        return DocumentService.html_to_docx_bytes(html_content)

    @staticmethod
    def generate_email_docx(advisory: Advisory) -> bytes:
        """Generate an email draft DOCX document in memory and return bytes."""
        import io
        doc = Document()
        
        for section in doc.sections:
            section.top_margin = Inches(1)
            section.bottom_margin = Inches(1)
            section.left_margin = Inches(1)
            section.right_margin = Inches(1)

        try:
            email = advisory.email_draft
        except EmailDraft.DoesNotExist:
            email = EmailDraft(
                advisory=advisory,
                subject=f"Cybersecurity Advisory Notification – {advisory.asn.get_display_name()}",
                body=AdvisoryService.build_email_body(advisory),
            )

        title = doc.add_heading("Email Draft", level=0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        doc.add_paragraph("")  # spacer

        p = doc.add_paragraph()
        runner = p.add_run("Subject: ")
        runner.bold = True
        p.add_run(email.subject)

        doc.add_paragraph("")  # spacer

        doc.add_heading("Body", level=1)
        for line in email.body.split("\n"):
            doc.add_paragraph(line)

        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()

