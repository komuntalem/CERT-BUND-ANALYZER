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
        """Build a structured email body for an advisory notification."""
        return (
            f"Advisory Number: {advisory.advisory_number}\n"
            f"Date: {advisory.advisory_date}\n"
            f"Organization Name: {advisory.asn.get_display_name()}\n"
            f"ASN: {advisory.asn.asn_number}\n"
            f"Malware Detected: {advisory.malware.malware_name}\n"
            f"Risk Level: {advisory.malware.risk_level}\n\n"
            f"Summary:\n{advisory.summary}\n\n"
            f"Recommended Mitigation Actions:\n{advisory.recommended_mitigation}\n"
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

                    # Group by (ASN, Malware) for advisory generation
                    pair_key = (asn.pk, malware.pk)
                    if pair_key not in new_events_by_pair:
                        new_events_by_pair[pair_key] = {
                            "asn": asn,
                            "malware": malware,
                            "count": 0,
                        }
                    new_events_by_pair[pair_key]["count"] += 1

            # -- Phase 4: Audit log (always, independent of dedup) ----------
            SeenCombosService.append_fingerprints(all_fingerprints)

            # -- Phase 5+6: Generate advisories + email drafts ---------------
            advisory_count = 0
            with transaction.atomic():
                for pair_data in new_events_by_pair.values():
                    asn = pair_data["asn"]
                    malware = pair_data["malware"]
                    event_count = pair_data["count"]

                    advisory_number = AdvisoryService._next_advisory_number()

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

                    advisory = Advisory.objects.create(
                        advisory_number=advisory_number,
                        advisory_date=date.today(),
                        asn=asn,
                        malware=malware,
                        summary=summary,
                        recommended_mitigation=mitigation,
                        content=f"{summary}\n\n{mitigation}",
                        status="draft",
                        source_run=run,
                    )

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
        """Generate a professionally formatted advisory DOCX document."""
        doc = Document()

        # -- Title --
        title = doc.add_heading("Cybersecurity Advisory", level=0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        subtitle = doc.add_heading(
            advisory.advisory_number or "Draft Advisory", level=1
        )
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER

        doc.add_paragraph("")  # spacer

        # -- Metadata table --
        table = doc.add_table(rows=6, cols=2)
        table.style = "Table Grid"

        metadata = [
            ("Advisory Number", advisory.advisory_number or "TBD"),
            ("Date", str(advisory.advisory_date)),
            ("Organization", advisory.asn.get_display_name()),
            ("ASN", advisory.asn.asn_number),
            ("Malware", advisory.malware.malware_name),
            ("Risk Level", advisory.malware.risk_level),
        ]
        for i, (label, value) in enumerate(metadata):
            row = table.rows[i]
            row.cells[0].text = label
            row.cells[1].text = value
            # Bold the label column
            for paragraph in row.cells[0].paragraphs:
                for run in paragraph.runs:
                    run.bold = True

        doc.add_paragraph("")  # spacer

        # -- Summary --
        doc.add_heading("Summary", level=1)
        doc.add_paragraph(advisory.summary or advisory.content or "No summary available.")

        # -- Recommended Mitigation --
        doc.add_heading("Recommended Mitigation", level=1)
        mitigation = advisory.recommended_mitigation or "No specific mitigation provided."
        for line in mitigation.split("\n"):
            line = line.strip()
            if line:
                doc.add_paragraph(line, style="List Bullet")

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
