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
    AdvisoryService     – Per-pair advisory generation with UCC-CERT-NNN numbering
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

            clean = {
                "asn": asn,
                "malware": (row.get("malware") or "Unknown").strip(),
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

    Advisories are created per unique ASN/Organisation per run — one advisory
    per organisation regardless of how many malware families are detected.
    Advisory numbers follow the ``UCC-CERT-NNN`` scheme.
    """

    @staticmethod
    def _next_advisory_number() -> str:
        """Generate the next sequential advisory number following UCC-CERT-SA-YY-NNN format."""
        year_short = date.today().year % 100
        prefix = f"UCC-CERT-SA-{year_short:02d}-"
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
    def format_issuance_date(d: date) -> str:
        """Format a date like '11th June 2026'."""
        day = d.day
        if 11 <= day <= 13:
            suffix = 'th'
        else:
            suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
        month_name = d.strftime('%B')
        year = d.year
        return f"{day}{suffix} {month_name} {year}"

    @staticmethod
    def get_malware_info_ddg_first(malware_name: str) -> tuple[str, list[str]]:
        """
        Get malware description and recommendations, querying DuckDuckGo first with OpenRouter summarization/generation,
        and falling back to the Malware module.
        """
        import os
        import json
        import re
        import requests
        from ddgs import DDGS
        from malware_views.models import MalwareEntry

        api_key = os.getenv("OPENROUTER_API_KEY", "")
        
        # 1. Try DuckDuckGo primary path
        snippets = []
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(f"{malware_name} malware", max_results=3))
                for r in results:
                    body = r.get("body", "")
                    if body:
                        snippets.append(body)
        except Exception as e:
            log.warning(f"DuckDuckGo search failed for {malware_name}: {e}")

        # If search worked, try to get description and mitigation from DDG results using OpenRouter
        if snippets and api_key:
            context_text = " ".join(snippets)
            prompt = f"""
Analyze the following threat intelligence context about the malware family '{malware_name}':
Context: {context_text}

Task 1: Generate a concise description of '{malware_name}' explaining what the malware is, its primary purpose, and its main impact on affected systems.
Constraints for Task 1:
- Must be a single complete and meaningful sentence.
- Must contain a minimum of 15 words and a maximum of 20 words.
- Do NOT simply truncate or copy existing text; synthesize it.

Task 2: Generate 3 realistic incident response recommended mitigation actions for '{malware_name}'.
Constraints for Task 2:
- Write each recommendation as a complete, professional, CERT-advisory style sentence.
- Do NOT use short bullet fragments like "Scan systems" or "Change passwords". Under any circumstances, write long, well-composed, full sentences.
- Example of acceptable recommendations:
  * "Affected systems should be immediately isolated from the network to prevent further propagation or data exfiltration."
  * "Organizations should perform a full endpoint scan using updated security tools to identify additional indicators of compromise."
  * "Credentials used on affected systems should be reset and reviewed for unauthorized access activity."

Respond with a JSON object in this exact format:
{{
  "description": "...",
  "recommendations": [
    "...",
    "...",
    "..."
  ]
}}
"""
            try:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:8000",
                    "X-Title": "CERT-Bund Threat Intelligence Platform"
                }
                payload = {
                    "model": "google/gemini-2.5-flash",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.5,
                    "max_tokens": 500,
                    "response_format": {"type": "json_object"}
                }
                res = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=8
                )
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    result = json.loads(content)
                    desc = result.get("description", "").strip()
                    recs = [r.strip() for r in result.get("recommendations", []) if r.strip()]
                    
                    # Validate description constraints
                    words = desc.split()
                    if 15 <= len(words) <= 20 and recs:
                        log.info(f"Successfully generated custom description and mitigation for {malware_name} from DDG via AI.")
                        return desc, recs
            except Exception as e:
                log.warning(f"Failed to query/parse OpenRouter for DDG summary: {e}")

        # 2. Fallback to Malware module database
        db_desc = ""
        db_recs = ""
        try:
            entry = MalwareEntry.objects.filter(name__iexact=malware_name).first()
            if entry:
                db_desc = entry.description or entry.executive_summary
                db_recs = entry.recommendations or entry.remediation
        except Exception as e:
            log.warning(f"Error fetching fallback from MalwareEntry: {e}")

        # If database records are available, try to summarize them using OpenRouter
        if db_desc and api_key:
            prompt = f"""
Summarize the following malware description and recommendations for '{malware_name}'.
Description: {db_desc}
Recommendations: {db_recs}

Task 1: Generate a concise description of '{malware_name}' explaining what the malware is, its primary purpose, and its main impact.
Constraints for Task 1:
- Must be a single complete and meaningful sentence.
- Must contain a minimum of 15 words and a maximum of 20 words.
- Do NOT simply truncate the existing text; write a proper summary.

Task 2: Format the recommendations as realistic incident response mitigation actions.
Constraints for Task 2:
- Write each recommendation as a complete, professional, CERT-advisory style sentence.
- Do NOT use short bullet fragments under any circumstances. Write long, well-composed, full sentences.
- Example of acceptable recommendations:
  * "Affected systems should be immediately isolated from the network to prevent further propagation or data exfiltration."
  * "Organizations should perform a full endpoint scan using updated security tools to identify additional indicators of compromise."
  * "Credentials used on affected systems should be reset and reviewed for unauthorized access activity."

Respond with a JSON object in this exact format:
{{
  "description": "...",
  "recommendations": [
    "...",
    "...",
    "..."
  ]
}}
"""
            try:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:8000",
                    "X-Title": "CERT-Bund Threat Intelligence Platform"
                }
                payload = {
                    "model": "google/gemini-2.5-flash",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.5,
                    "max_tokens": 500,
                    "response_format": {"type": "json_object"}
                }
                res = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=8
                )
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    result = json.loads(content)
                    desc = result.get("description", "").strip()
                    recs = [r.strip() for r in result.get("recommendations", []) if r.strip()]
                    
                    # Validate description constraints
                    words = desc.split()
                    if 15 <= len(words) <= 20 and recs:
                        log.info(f"Successfully generated custom description and mitigation for {malware_name} from MalwareEntry fallback via AI.")
                        return desc, recs
            except Exception as e:
                log.warning(f"Failed to query/parse OpenRouter for MalwareEntry summary fallback: {e}")

        # 3. Local deterministic fallbacks & template synthesizers if OpenRouter is offline/402
        REMEDIAS_MAP = {
            "isolate affected systems": "Affected systems should be immediately isolated from the network to prevent further propagation or data exfiltration.",
            "isolate affected systems immediately": "Affected systems should be immediately isolated from the network to prevent further propagation or data exfiltration.",
            "block network indicators": "Organizations should block all identified network and host-based indicators of compromise at the perimeter firewalls and DNS level.",
            "block identified network indicators": "Organizations should block all identified network and host-based indicators of compromise at the perimeter firewalls and DNS level.",
            "conduct forensic investigation": "A comprehensive forensic investigation should be conducted on affected host systems to identify the entry vector and scope of compromise.",
            "update security controls": "Organizations should update their security controls and host-based signatures, and implement enhanced monitoring for anomalous network activity.",
            "update security controls and implement enhanced monitoring": "Organizations should update their security controls and host-based signatures, and implement enhanced monitoring for anomalous network activity.",
            "change passwords": "Credentials used on affected systems should be reset and reviewed for unauthorized access activity.",
            "scan systems": "Organizations should perform a full endpoint scan using updated security tools to identify additional indicators of compromise."
        }

        # Parse local list of recommendations from db_recs
        recs_list = []
        if db_recs:
            for line in db_recs.split("\n"):
                line = line.strip()
                if not line:
                    continue
                line_clean = re.sub(r'^\d+[\.\s\-)]+', '', line).strip()
                line_lower = line_clean.lower().rstrip('.')
                if line_lower in REMEDIAS_MAP:
                    recs_list.append(REMEDIAS_MAP[line_lower])
                elif line_clean:
                    # Formatting custom fallback recommendation as a full sentence
                    sentence = line_clean[0].upper() + line_clean[1:]
                    if not sentence.endswith('.'):
                        sentence += '.'
                    recs_list.append(sentence)

        # Fallback to defaults if list is empty or too short
        if len(recs_list) < 2:
            recs_list = [
                "Affected systems should be immediately isolated from the network to prevent further propagation or data exfiltration.",
                "Organizations should perform a full endpoint scan using updated security tools to identify additional indicators of compromise.",
                "Credentials used on affected systems should be reset and reviewed for unauthorized access activity."
            ]

        # Generate a grammatically correct description between 15-20 words based on db_desc
        desc = ""
        if db_desc:
            text_lower = db_desc.lower()
            purpose = "compromise systems and steal sensitive user information"
            if "miner" in text_lower or "mining" in text_lower:
                purpose = "perform unauthorized cryptocurrency mining and harvest user credentials"
            elif "stealer" in text_lower or "theft" in text_lower:
                purpose = "steal sensitive user information and harvest credentials from web browsers"
            elif "trojan" in text_lower:
                purpose = "establish remote access and deliver additional malicious payloads to host systems"
            elif "botnet" in text_lower:
                purpose = "enlist compromised host devices into a botnet for command and control activities"

            desc = f"{malware_name} is a sophisticated malware family designed to {purpose}."
            words = desc.split()
            if not (15 <= len(words) <= 20):
                desc = ""

        if not desc:
            desc = f"{malware_name} is an active threat vector designed to compromise host systems, steal sensitive data, and exploit network assets."

        log.info(f"Using local static fallback configuration for {malware_name} (description length: {len(desc.split())} words).")
        return desc, recs_list

    @staticmethod
    def build_advisory_html(advisory: Advisory) -> str:
        """Generate structured HTML content for the advisory page/TinyMCE editor."""
        date_str = AdvisoryService.format_issuance_date(advisory.advisory_date)
        org_name = advisory.asn.get_display_name()
        
        from django.utils.html import strip_tags
        from malware_views.models import MalwareEntry

        # 1. Self-heal missing malware descriptions
        for mw in advisory.malware_families.all():
            if not mw.description:
                desc, recs = AdvisoryService.get_malware_info_ddg_first(mw.malware_name)
                mw.description = desc
                mw.save(update_fields=["description"])

        # 2. Self-heal missing recommended mitigation actions
        if not advisory.recommended_mitigation:
            combined_recs = []
            for mw in advisory.malware_families.all():
                desc, recs = AdvisoryService.get_malware_info_ddg_first(mw.malware_name)
                for r in recs:
                    r_clean = r.strip()
                    if r_clean and r_clean not in combined_recs:
                        combined_recs.append(r_clean)
            if combined_recs:
                advisory.recommended_mitigation = "\n".join(f"{i}. {r}" for i, r in enumerate(combined_recs, 1))
                advisory.save(update_fields=["recommended_mitigation"])
        
        # 3. Construct malware table rows
        malware_rows = ""
        for mw in advisory.malware_families.all():
            try:
                entry = MalwareEntry.objects.filter(name__iexact=mw.malware_name).first()
            except Exception:
                entry = None
            if entry:
                risk = entry.risk or entry.get_severity_display() or mw.risk_level
                imp = entry.impact
            else:
                risk = mw.risk_level
                imp = "Potential compromise of affected systems."
                
            desc = strip_tags(mw.description or "No description available.").strip()
            risk = strip_tags(risk or "Medium").strip()
            imp = strip_tags(imp or "High").strip()
            
            malware_rows += f"""
            <tr>
                <td style="border: 1px solid #000000; padding: 6px; font-weight: bold;">{mw.malware_name}</td>
                <td style="border: 1px solid #000000; padding: 6px;">{desc}</td>
                <td style="border: 1px solid #000000; padding: 6px;">{risk}</td>
                <td style="border: 1px solid #000000; padding: 6px;">{imp}</td>
            </tr>
            """
            
        mitigation_list = ""
        mitigation = advisory.recommended_mitigation or ""
        for line in mitigation.split("\n"):
            line = line.strip()
            if not line:
                continue
            match = re.match(r'^(\d+\.\s+)(.*)$', line)
            if match:
                num = match.group(1)
                text = match.group(2)
                mitigation_list += f'<li><strong>{num}</strong>{text}</li>'
            else:
                mitigation_list += f'<li>{line}</li>'
                
        html = f"""
        <p>Dear {org_name} Team,</p>
        <p><strong>Advisory Number:</strong> {advisory.advisory_number or "TBD"}<br>
        <strong>Date of Issuance:</strong> {date_str}<br>
        <strong>Identified Asset:</strong> List of identified IP addresses attached.</p>
        <p>Please find attached details of IP addresses within your network that are associated with hosts most likely compromised by malware. These IP addresses should be treated as indicators of potentially affected systems and require immediate investigation, containment, and remediation.</p>
        <p><strong>Description of the Identified Malware:</strong></p>
        <table style="border-collapse: collapse; width: 100%; border: 1px solid #000000;" border="1">
            <thead>
                <tr style="background-color: #f2f2f2;">
                    <th style="border: 1px solid #000000; padding: 6px; text-align: left;">MALWARE</th>
                    <th style="border: 1px solid #000000; padding: 6px; text-align: left;">DESCRIPTION</th>
                    <th style="border: 1px solid #000000; padding: 6px; text-align: left;">RISK</th>
                    <th style="border: 1px solid #000000; padding: 6px; text-align: left;">IMPACT</th>
                </tr>
            </thead>
            <tbody>
                {malware_rows}
            </tbody>
        </table>
        <p>&nbsp;</p>
        <p><strong>Recommended Actions:</strong></p>
        <ol style="list-style-type: decimal; margin-left: 20px;">
            {mitigation_list}
        </ol>
        <p>&nbsp;</p>
        <p>You are required to submit an initial status update within 48 hours from receipt of this advisory via the feedback form, below.</p>
        <p><strong>UCC-CERT CYBERSECURITY ADVISORY FEEDBACK FORM</strong> – <a href="https://forms.office.com/pages/responsepage.aspx?id=Xs3_98BEhkaEUnjqV0Mt51BLmTH0Iw5ApxjklnxERGdUOFRFTkYzQ0dTTTJFSUhaUVY2VUVVRlc5My4u&amp;route=shorturl" target="_blank" rel="noopener">Fill out form</a></p>
        <p>Kind regards,</p>
        """
        return html

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
            4.  Append only NEW unique fingerprints to seen_combos.txt
            5.  Generate advisories per unique (ASN, Malware) pair
            6.  Generate email drafts for each advisory
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
            new_events_by_pair: dict[tuple, dict] = {}
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
                    if asn_key not in new_events_by_pair:
                        new_events_by_pair[asn_key] = {
                            "asn": asn,
                            "malware_set": set(),
                            "count": 0,
                        }
                    new_events_by_pair[asn_key]["malware_set"].add(malware)
                    new_events_by_pair[asn_key]["count"] += 1

            # -- Phase 4: Audit log (always, independent of dedup) ----------
            SeenCombosService.append_fingerprints(all_fingerprints)

            # -- Phase 5+6: Generate/update org-level advisories + email drafts
            advisory_count = 0
            with transaction.atomic():
                for asn_data in new_events_by_pair.values():
                    asn = asn_data["asn"]
                    malware_set = asn_data["malware_set"]
                    event_count = asn_data["count"]

                    malware_names = ", ".join(
                        sorted(m.malware_name for m in malware_set)
                    )

                    # Upsert: one advisory per ASN per run
                    existing = Advisory.objects.filter(
                        asn=asn, source_run=run
                    ).first()

                    if existing:
                        # Update existing advisory to add newly detected malware
                        existing.malware_families.add(*malware_set)
                        malware_names = ", ".join(
                            sorted(
                                m.malware_name
                                for m in existing.malware_families.all()
                            )
                        )
                        existing.summary = (
                            f"Detected {event_count} unique attack event(s) involving "
                            f"malware: {malware_names} — "
                            f"{asn.get_display_name()} ({asn.asn_number})."
                        )
                        existing.recommended_mitigation = "" # Reset to regenerate mitigations with new malware family
                        existing.content = AdvisoryService.build_advisory_html(existing)
                        existing.save(update_fields=["summary", "recommended_mitigation", "content"])
                        advisory = existing
                    else:
                        advisory_number = AdvisoryService._next_advisory_number()
                        summary = (
                            f"Detected {event_count} unique attack event(s) involving "
                            f"malware: {malware_names} — "
                            f"{asn.get_display_name()} ({asn.asn_number})."
                        )
                        advisory = Advisory.objects.create(
                            advisory_number=advisory_number,
                            advisory_date=date.today(),
                            asn=asn,
                            summary=summary,
                            recommended_mitigation="",
                            content="",
                            status="draft",
                            source_run=run,
                        )
                        advisory.malware_families.set(malware_set)
                        advisory.content = AdvisoryService.build_advisory_html(advisory)
                        advisory.save(update_fields=["content"])
                        advisory_count += 1

                    # Upsert email draft (one per org advisory)
                    EmailDraft.objects.update_or_create(
                        advisory=advisory,
                        defaults={
                            "subject": (
                                f"Cybersecurity Advisory Notification – "
                                f"{asn.get_display_name()}"
                            ),
                            "body": AdvisoryService.build_email_body(advisory),
                        },
                    )

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

    Files are saved under MEDIA_ROOT/{advisories,email_drafts}/.
    """

    @staticmethod
    def _media_dir(subdir: str) -> str:
        media_root = getattr(settings, "MEDIA_ROOT", None)
        if not media_root:
            media_root = os.path.join(str(SeenCombosService._project_base_dir()), "media")
        path = os.path.join(str(media_root), subdir)
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def generate_advisory_docx(advisory: Advisory) -> str:
        """Generate a professionally formatted advisory DOCX document from HTML content."""
        # Ensure HTML content is populated
        if not advisory.content or "<table" not in advisory.content:
            advisory.content = AdvisoryService.build_advisory_html(advisory)
            advisory.save(update_fields=["content"])

        doc = Document()
        
        # Set margins to 1 inch
        for section in doc.sections:
            section.top_margin = Inches(1)
            section.bottom_margin = Inches(1)
            section.left_margin = Inches(1)
            section.right_margin = Inches(1)
            
        # Configure Normal style default font to match the template (Bookman Old Style 12pt)
        style = doc.styles['Normal']
        style.font.name = 'Bookman Old Style'
        style.font.size = Pt(12)
        style.paragraph_format.line_spacing = 1.15
        style.paragraph_format.space_after = Pt(6)
        style.paragraph_format.space_before = Pt(0)
        
        # Convert HTML to Word using HtmlToDocx
        from htmldocx import HtmlToDocx
        html_parser = HtmlToDocx()
        html_parser.add_html_to_document(advisory.content, doc)
        
        # Save to media/advisories/
        outdir = DocumentService._media_dir("advisories")
        path = os.path.join(outdir, f"advisory_{advisory.pk}.docx")
        doc.save(path)
        log.info("Advisory DOCX generated from HTML content: %s", path)
        return path

    @staticmethod
    def generate_email_docx(advisory: Advisory) -> str:
        """Generate an email draft DOCX document."""
        doc = Document()

        try:
            email = advisory.email_draft
        except EmailDraft.DoesNotExist:
            # Safety fallback — create a minimal draft
            email = EmailDraft(
                advisory=advisory,
                subject=f"Cybersecurity Advisory Notification – {advisory.asn.get_display_name()}",
                body=AdvisoryService.build_email_body(advisory),
            )

        # -- Title --
        title = doc.add_heading("Email Draft", level=0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        doc.add_paragraph("")  # spacer

        # -- Subject --
        p = doc.add_paragraph()
        runner = p.add_run("Subject: ")
        runner.bold = True
        p.add_run(email.subject)

        doc.add_paragraph("")  # spacer

        # -- Body --
        doc.add_heading("Body", level=1)
        for line in email.body.split("\n"):
            doc.add_paragraph(line)

        # -- Save --
        outdir = DocumentService._media_dir("email_drafts")
        path = os.path.join(outdir, f"email_draft_{advisory.pk}.docx")
        doc.save(path)
        log.info("Email draft DOCX generated: %s", path)
        return path
