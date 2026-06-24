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
import concurrent.futures
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

# Circuit breaker: set to True after the first nslookup failure so all
# subsequent ASNs in the same process skip the 15-second timeout entirely.
_cymru_unavailable: bool = False
# Empty-result streak counter: trip the circuit breaker after this many
# consecutive lookups that return no TXT record (nslookup ran fine but
# Cymru returned nothing — not a timeout, not a FileNotFoundError).
_cymru_empty_streak: int = 0
_CYMRU_EMPTY_STREAK_LIMIT: int = 3


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
        """Extract only the numeric part from an ASN string.

        Handles both bare numbers and strings with a trailing org name:
            'AS13335'              → '13335'
            'AS13335 CLOUDFLARE'  → '13335'   (org name discarded)
            '13335'               → '13335'
            '13335 CLOUDFLARE'    → '13335'
        """
        cleaned = asn_string.strip().upper()
        if cleaned.startswith("AS"):
            cleaned = cleaned[2:]
        # Take only the leading digit sequence — discard anything after the
        # first space or non-digit character (e.g. " CLOUDFLARE").
        m = re.match(r'(\d+)', cleaned)
        return m.group(1) if m else cleaned

    @staticmethod
    def _normalize_asn(asn_string: str) -> str:
        """Normalize to 'AS<number>' format."""
        num = ASNLookupService._extract_asn_number(asn_string)
        return f"AS{num}" if num else asn_string.strip().upper()

    # -- Team Cymru DNS TXT --------------------------------------------------

    @staticmethod
    def _lookup_cymru(asn_num: str) -> tuple[str, str]:
        """Query Team Cymru WHOIS via dnspython TXT record.

        TXT format: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
        Returns (organization_name, country_code).

        A module-level circuit breaker (_cymru_unavailable) is tripped on the
        first Timeout so that subsequent ASNs in the same process return immediately.
        """
        global _cymru_unavailable, _cymru_empty_streak
        if _cymru_unavailable:
            return "", ""

        try:
            import dns.resolver
            import dns.exception
            
            # Using dnspython
            answers = dns.resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT", lifetime=10)
            for rdata in answers:
                # Extract text from TXT record
                txt = b"".join(rdata.strings).decode("utf-8")
                parts = [p.strip() for p in txt.split("|")]
                if len(parts) >= 5:
                    country = parts[1]
                    org_name = parts[4]
                    # Successful result — reset the empty-streak counter.
                    _cymru_empty_streak = 0
                    return org_name, country
                    
            # Ran but returned no usable TXT record — count the miss.
            _cymru_empty_streak += 1
            if _cymru_empty_streak >= _CYMRU_EMPTY_STREAK_LIMIT:
                _cymru_unavailable = True
                log.warning(
                    "Team Cymru returned empty results %d times consecutively — "
                    "disabling for this session.", _CYMRU_EMPTY_STREAK_LIMIT
                )
        except ImportError:
            log.error("dnspython not installed. Cannot perform Team Cymru lookup.")
            _cymru_unavailable = True
        except dns.resolver.NXDOMAIN:
            _cymru_empty_streak += 1
            if _cymru_empty_streak >= _CYMRU_EMPTY_STREAK_LIMIT:
                _cymru_unavailable = True
                log.warning("Team Cymru returned NXDOMAIN multiple times — disabling.")
        except dns.exception.Timeout:
            _cymru_unavailable = True
            log.warning(
                "Team Cymru DNS lookup timed out for AS%s — disabling for this session.",
                asn_num,
            )
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

    # -- Public API -----------------------------------------------------------

    @staticmethod
    def resolve_organization(asn_number: str) -> tuple[str, str]:
        """Resolve ASN to (org_name, country). Tries Cymru then PeeringDB."""
        asn_num = ASNLookupService._extract_asn_number(asn_number)
        if not asn_num.isdigit():
            return "", ""

        org, country = ASNLookupService._lookup_cymru(asn_num)
        if org:
            log.info("Team Cymru resolved AS%s → %s (%s)", asn_num, org, country)
            return org, country

        org, country = ASNLookupService._lookup_peeringdb(asn_num)
        if org:
            log.info("PeeringDB resolved AS%s → %s", asn_num, org)
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
        update_fields = []
        if not asn.organization_name:
            org, country = ASNLookupService.resolve_organization(normalized)
            if org:
                asn.organization_name = org
                update_fields.append("organization_name")
            if country:
                asn.country = country
                update_fields.append("country")

        # Only write last_seen when the record was just created or when we
        # are already saving enrichment fields — avoids a redundant write-lock
        # acquisition on every call for already-known ASNs.
        if created or update_fields:
            asn.last_seen = timezone.now()
            update_fields.append("last_seen")
            asn.save(update_fields=update_fields)

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
        """Append fingerprints to the audit log.  Always called — independent
        of whether the fingerprint was a duplicate."""
        path = SeenCombosService._filepath()
        with open(path, "a", encoding="utf-8") as f:
            for fp in fingerprints:
                f.write(fp + "\n")
        log.info("Appended %d fingerprint(s) to %s.", len(list(fingerprints)), path)

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

    Advisories are created per unique (ASN, Malware) pair per run — not per
    individual row.  Advisory numbers follow the ``ADV-YYYY-NNNN`` scheme
    with year-based sequential reset.
    """

    @staticmethod
    def _next_advisory_number() -> str:
        """Generate the next sequential advisory number for the current year."""
        year = date.today().year
        prefix = f"ADV-{year}-"
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
        return f"{prefix}{seq:04d}"

    @staticmethod
    def build_email_body(advisory: Advisory) -> str:
        """Build a simple notification email body — details are in the attached advisory."""
        title = advisory.advisory_number or advisory.asn.get_display_name()
        return (
            f"Hello,\n\n"
            f"find attached an advisory about {title}.\n\n"
            f"Regards,"
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
            4.  ALWAYS append ALL fingerprints to seen_combos.txt
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
            # -- Phase 1: Pre-enrich ASNs & Malware (HTTP/DB — outside transaction) ------
            unique_asn_numbers = {row["asn"] for row in rows}
            asn_cache: dict[str, ASN] = {}
            
            # Step 1A: Fetch from DB / Create empty placeholders
            for asn_num in unique_asn_numbers:
                normalized = ASNLookupService._normalize_asn(asn_num)
                asn, _ = ASN.objects.get_or_create(asn_number=normalized, defaults={"organization_name": ""})
                asn_cache[asn_num] = asn
                
            # Step 1B: Find ASNs that still need org name enrichment
            asns_to_enrich = {asn_num: asn_cache[asn_num] for asn_num in unique_asn_numbers if not asn_cache[asn_num].organization_name}
            
            if asns_to_enrich:
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    future_to_asn = {
                        executor.submit(ASNLookupService.resolve_organization, asn_num): asn_num
                        for asn_num in asns_to_enrich
                    }
                    for future in concurrent.futures.as_completed(future_to_asn):
                        asn_num = future_to_asn[future]
                        try:
                            org, country = future.result()
                            if org or country:
                                asn = asn_cache[asn_num]
                                if org: asn.organization_name = org
                                if country: asn.country = country
                                asn.last_seen = timezone.now()
                                asn.save(update_fields=["organization_name", "country", "last_seen"])
                        except Exception as exc:
                            log.error("Concurrent ASN lookup failed for %s: %s", asn_num, exc)
            
            # Update last_seen for all ASNs found in this batch (that didn't just get updated)
            ASN.objects.filter(id__in=[asn.id for asn in asn_cache.values()]).update(last_seen=timezone.now())

            unique_malware_names = {row["malware"] for row in rows if row.get("malware")}
            existing_malwares = {m.malware_name: m for m in Malware.objects.filter(malware_name__in=unique_malware_names)}
            new_malwares_to_create = []
            for m_name in unique_malware_names:
                if m_name not in existing_malwares:
                    new_malwares_to_create.append(Malware(malware_name=m_name, description="", risk_level="Medium"))
            if new_malwares_to_create:
                Malware.objects.bulk_create(new_malwares_to_create)
                # Ensure the cache is updated with the newly created IDs
                existing_malwares.update({m.malware_name: m for m in Malware.objects.filter(malware_name__in=[m.malware_name for m in new_malwares_to_create])})
            malware_cache = existing_malwares

            # -- Phase 2: Bulk-prefetch existing fingerprints for dedup ------
            batch_fingerprints = {row["fingerprint"] for row in rows}
            existing_fingerprints = set(
                AttackEvent.objects
                .filter(fingerprint__in=batch_fingerprints)
                .values_list('fingerprint', flat=True)
            )

            # -- Phase 3: Prepare events ----------------------
            new_events_by_pair: dict[tuple, dict] = {}
            new_attack_events = []
            new_fingerprints_for_audit = []

            for row in rows:
                fp = row["fingerprint"]

                if fp in existing_fingerprints:   # Python set — no DB query
                    continue

                asn = asn_cache.get(row["asn"]) or ASNLookupService.ensure_asn(row["asn"])
                malware = malware_cache.get(row["malware"]) or MalwareService.ensure_malware(row["malware"])

                new_attack_events.append(AttackEvent(
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
                ))
                new_fingerprints_for_audit.append(fp)

                # Group by (ASN, Malware) for advisory generation
                pair_key = (asn.pk, malware.pk)
                if pair_key not in new_events_by_pair:
                    new_events_by_pair[pair_key] = {
                        "asn": asn,
                        "malware": malware,
                        "count": 0,
                    }
                new_events_by_pair[pair_key]["count"] += 1

            new_event_count = len(new_attack_events)

            with transaction.atomic():
                if new_attack_events:
                    AttackEvent.objects.bulk_create(new_attack_events, batch_size=1000)

            # -- Phase 4: Audit log (Only append new combos) ----------------
            if new_fingerprints_for_audit:
                SeenCombosService.append_fingerprints(new_fingerprints_for_audit)

            # -- Phase 5+6: Generate advisories + email drafts ---------------
            advisory_count = 0
            new_advisories = []
            
            # Fetch the base sequence number once so bulk creation doesn't duplicate them
            base_advisory_number = AdvisoryService._next_advisory_number()
            prefix_parts = base_advisory_number.split("-")
            if len(prefix_parts) >= 3:
                prefix = f"{prefix_parts[0]}-{prefix_parts[1]}-"
                try:
                    current_seq = int(prefix_parts[2])
                except ValueError:
                    current_seq = 1
            else:
                prefix = f"ADV-{date.today().year}-"
                current_seq = 1
            
            for pair_data in new_events_by_pair.values():
                asn = pair_data["asn"]
                malware = pair_data["malware"]
                event_count = pair_data["count"]

                advisory_number = f"{prefix}{current_seq:04d}"
                current_seq += 1

                summary = (
                    f"Detected {event_count} unique attack event(s) involving "
                    f"malware '{malware.malware_name}' targeting network assets "
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

                new_advisories.append(Advisory(
                    advisory_number=advisory_number,
                    advisory_date=date.today(),
                    asn=asn,
                    malware=malware,
                    summary=summary,
                    recommended_mitigation=mitigation,
                    content=f"{summary}\n\n{mitigation}",
                    status="draft",
                    source_run=run,
                ))

            with transaction.atomic():
                if new_advisories:
                    created_advisories = Advisory.objects.bulk_create(new_advisories)
                    advisory_count = len(created_advisories)
                    
                    new_emails = []
                    for advisory in created_advisories:
                        new_emails.append(EmailDraft(
                            advisory=advisory,
                            subject=(
                                f"Cybersecurity Advisory Notification – "
                                f"{advisory.asn.get_display_name()}"
                            ),
                            body=AdvisoryService.build_email_body(advisory),
                        ))
                    
                    if new_emails:
                        EmailDraft.objects.bulk_create(new_emails)

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
        """Generate a professionally formatted advisory DOCX document.

        Formatting: Bookman Old Style, 12pt, 1.5 line spacing, justified, black/white.
        """
        from docx.shared import RGBColor
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement

        FONT_NAME = "Bookman Old Style"
        FONT_SIZE = Pt(12)
        LINE_SPACING = Pt(18)  # 1.5 × 12pt

        def _fmt(paragraph, bold=False, center=False):
            """Apply standard formatting to every run in a paragraph."""
            paragraph.paragraph_format.line_spacing = LINE_SPACING
            if center:
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            else:
                paragraph.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            for run in paragraph.runs:
                run.font.name = FONT_NAME
                run.font.size = FONT_SIZE
                run.font.color.rgb = RGBColor(0, 0, 0)
                if bold:
                    run.bold = True

        def _add_paragraph(doc, text, bold=False, center=False):
            p = doc.add_paragraph(text)
            _fmt(p, bold=bold, center=center)
            return p

        doc = Document()

        # -- Greeting --
        org_name = advisory.asn.get_display_name() or "Team"
        _add_paragraph(doc, f"Dear {org_name},")
        
        # -- Metadata --
        _add_paragraph(doc, f"Advisory Number: {advisory.advisory_number or 'TBD'}")
        
        # Format date as something like "11th June 2026"
        def ordinal(n):
            if 11 <= (n % 100) <= 13:
                return str(n) + 'th'
            return str(n) + {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
            
        advisory_date = advisory.advisory_date
        formatted_date = f"{ordinal(advisory_date.day)} {advisory_date.strftime('%B %Y')}"
        
        _add_paragraph(doc, f"Date of Issuance: {formatted_date}")
        _add_paragraph(doc, "Identified Asset: List of Identified IP addresses attached.")
        
        doc.add_paragraph("")  # spacer

        # -- Intro text --
        intro = (
            "Please find attached details of IP addresses within your network that are associated with hosts "
            "most likely compromised by malware. These IP addresses should be treated as indicators of "
            "potentially affected systems and require immediate investigation, containment, and remediation."
        )
        _add_paragraph(doc, intro)

        doc.add_paragraph("")  # spacer
        
        _add_paragraph(doc, "Description of the Identified Malware.")
        
        # -- Malware table --
        table = doc.add_table(rows=2, cols=4)
        table.style = "Table Grid"
        
        # Header row
        headers = ["MALWARE", "DESCRIPTION", "RISK", "IMPACT"]
        for i, header in enumerate(headers):
            cell = table.rows[0].cells[i]
            cell.text = header
            _fmt(cell.paragraphs[0], bold=True)
            
        # Data row
        data = [
            advisory.malware.malware_name,
            advisory.summary or advisory.content or "No description available.",
            advisory.malware.risk_level,
            "High" if advisory.malware.risk_level in ("High", "Critical") else advisory.malware.risk_level
        ]
        
        for i, val in enumerate(data):
            cell = table.rows[1].cells[i]
            cell.text = str(val)
            _fmt(cell.paragraphs[0])
            
        doc.add_paragraph("")  # spacer

        # -- Recommended Actions --
        _add_paragraph(doc, "Recommended Actions:")
        
        mitigation = advisory.recommended_mitigation or "No specific mitigation provided."
        for line in mitigation.split("\n"):
            line = line.strip()
            if line:
                # remove any leading numbers since the source might have them, or keep them.
                # Assuming the mitigation field contains the numbered items.
                _add_paragraph(doc, line)
                
        doc.add_paragraph("")  # spacer
        
        # -- Conclusion --
        conclusion = (
            "You are required to submit an initial status update within 48 hours from receipt of this "
            "advisory via the feedback form below."
        )
        _add_paragraph(doc, conclusion)
        
        _add_paragraph(doc, "UCC-CERT CYBERSECURITY ADVISORY FEEDBACK FORM  – Fill out form")
        
        doc.add_paragraph("")  # spacer
        _add_paragraph(doc, "Kind regards,")

        # -- Save --
        outdir = DocumentService._media_dir("advisories")
        path = os.path.join(outdir, f"advisory_{advisory.pk}.docx")
        doc.save(path)
        log.info("Advisory DOCX generated: %s", path)
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
