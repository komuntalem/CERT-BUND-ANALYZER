#!/usr/bin/env python
"""
cert_bund_analyzer.py — Legacy compatibility wrapper for CERT-Bund Analyzer.
Delegates to the modularized analyzer application and runs the development server
or e2e tests using the threatintelligence project configuration.
"""

import sys
import os
import csv
import logging
from pathlib import Path

# Set default settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatintelligence.settings')

import django
django.setup()

from django.core.management import call_command
from django.contrib.auth.models import User
from django.conf import settings
from analyzer.models import KnownMalware, KnownASN, AnalysisRun

log = logging.getLogger("cert_bund_web")


def create_malware_entries_from_run(run):
    """
    Create MalwareEntry records for all malware found in an AnalysisRun.
    Reads the combined CSV file to get ALL malware.
    """
    try:
        from malware_views.models import MalwareEntry
        from malware_views.report_generator import generate_malware_report
    except ImportError as e:
        log.warning(f"Malware views not available: {e}")
        return

    all_malware = set()
    
    # 1. Get malware from malware_stats (top 10)
    for item in run.malware_stats:
        malware_name = item.get('label', '').strip()
        if malware_name:
            all_malware.add(malware_name)
    
    # 2. Get malware from the combined CSV file (ALL malware)
    try:
        output_dir = os.path.join(settings.MEDIA_ROOT, run.output_dir)
        combined_csv = None
        
        if os.path.exists(output_dir):
            for f in os.listdir(output_dir):
                if f.startswith('all_asns_') and f.endswith('.csv'):
                    combined_csv = os.path.join(output_dir, f)
                    break
        
        if combined_csv and os.path.exists(combined_csv):
            log.info(f"Reading malware from: {combined_csv}")
            with open(combined_csv, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    malware_name = row.get('malware', '').strip()
                    if malware_name:
                        all_malware.add(malware_name)
    except Exception as e:
        log.warning(f"Could not read combined CSV for malware extraction: {e}")
    
    log.info(f"Total unique malware detected: {len(all_malware)}")
    log.info(f"Malware names: {', '.join(sorted(all_malware))}")
    
    # 3. Create entries for each malware
    created_count = 0
    existing_count = 0
    
    for malware_name in all_malware:
        if not malware_name:
            continue
            
        try:
            entry, created = MalwareEntry.objects.get_or_create(
                name=malware_name,
                defaults={
                    'first_seen_run_id': run.pk,
                    'severity': 'unknown',
                    'status': 'new',
                    'source': 'OpenRouter AI',
                    'family': malware_name,
                    'confidence': 'MODERATE'
                }
            )
            
            if created:
                created_count += 1
                log.info(f"New malware detected: {malware_name} - generating report...")
                try:
                    generate_malware_report(malware_name, entry, None)
                    log.info(f"Auto-generated malware report for: {malware_name}")
                except Exception as e:
                    log.error(f"Error generating report for {malware_name}: {e}")
            else:
                existing_count += 1
                
        except Exception as e:
            log.error(f"Error creating entry for {malware_name}: {e}")
    
    log.info(f"Malware entries created: {created_count}, existing: {existing_count}")
    return created_count


def process_malware_after_analysis(response, request):
    """
    Process malware after analysis completes.
    Called from the patched analyze view.
    """
    if response.status_code == 302 and '/dashboard/' in response.url:
        try:
            # Get the run ID from the redirect URL
            run_id = response.url.split('/')[-2]
            run = AnalysisRun.objects.get(pk=run_id)
            
            log.info(f"Processing malware for run #{run_id}")
            created_count = create_malware_entries_from_run(run)
            log.info(f"Malware processing complete. Created {created_count} new entries.")
            
        except Exception as e:
            log.error(f"Error processing malware after analysis: {e}")
    
    return response


def patch_analyze_view():
    """
    Patch the analyze view to process ALL malware after analysis.
    """
    try:
        from analyzer import views
        original_analyze = views.analyze
        
        def patched_analyze(request):
            """Enhanced analyze that captures ALL malware from all rows."""
            response = original_analyze(request)
            return process_malware_after_analysis(response, request)
        
        # Replace the analyze view with our patched version
        views.analyze = patched_analyze
        print("[CERT-Bund] Successfully patched analyze view.")
        
    except Exception as e:
        print(f"[CERT-Bund] Error patching analyze view: {e}")


def bootstrap_db():
    """Run migrations and ensure the default admin user exists."""
    print("[CERT-Bund] Running migrations…")
    call_command('migrate', interactive=False)

    from django.db import connection
    for model in [KnownMalware, KnownASN]:
        table_name = model._meta.db_table
        if table_name not in connection.introspection.table_names():
            print(f"[CERT-Bund] Creating table '{table_name}'…")
            with connection.schema_editor() as editor:
                editor.create_model(model)
            print(f"[CERT-Bund] Table {table_name} created.")

    # Create malware_views tables
    try:
        from malware_views.models import MalwareEntry, MalwareReport
        for model in [MalwareEntry, MalwareReport]:
            table_name = model._meta.db_table
            if table_name not in connection.introspection.table_names():
                print(f"[CERT-Bund] Creating table '{table_name}'…")
                with connection.schema_editor() as editor:
                    editor.create_model(model)
                print(f"[CERT-Bund] Table {table_name} created.")
    except ImportError as e:
        print(f"[CERT-Bund] Malware views not available: {e}")

    # Ensure AnalysisRun table has the new fields
    with connection.cursor() as cursor:
        cursor.execute("PRAGMA table_info(analyzer_analysisrun)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        
        if 'seen_combos_count' not in existing_cols:
            print("[CERT-Bund] Adding column 'seen_combos_count' to 'analyzer_analysisrun'…")
            cursor.execute("ALTER TABLE analyzer_analysisrun ADD COLUMN seen_combos_count INTEGER DEFAULT 0")
            
        if 'new_malwares' not in existing_cols:
            print("[CERT-Bund] Adding column 'new_malwares' to 'analyzer_analysisrun'…")
            cursor.execute("ALTER TABLE analyzer_analysisrun ADD COLUMN new_malwares TEXT DEFAULT '[]'")

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
    
    # Patch the analyze view to capture ALL malware
    try:
        patch_analyze_view()
    except Exception as e:
        print(f"[CERT-Bund] Warning: Could not patch analyze view: {e}")


def run_e2e_test():
    """Run end-to-end verification test."""
    print("=== Running End-to-End Test ===")
    from django.test import Client
    from django.conf import settings

    # Truncate tables for a clean slate
    KnownMalware.objects.all().delete()
    KnownASN.objects.all().delete()
    AnalysisRun.objects.all().delete()

    print("Initial database counts:")
    print("  KnownMalware:", KnownMalware.objects.count())
    print("  KnownASN:", KnownASN.objects.count())
    print("  AnalysisRun:", AnalysisRun.objects.count())

    # Get admin user
    try:
        admin = User.objects.get(username='CERT-Bund Admin')
    except User.DoesNotExist:
        admin = User.objects.create_superuser('admin', 'admin@certbund.local', 'admin123')

    client = Client()
    client.force_login(admin)

    # Locate sample files
    sample_dir = Path(r"c:\Users\Administrator\Desktop\INTERNSHIP\CERT-BUND-ANALYZER\sample_data")
    csv_paths = sorted(list(sample_dir.glob("*.csv")))
    print(f"Found {len(csv_paths)} sample CSV files for testing.")

    # Prepare files for upload
    files = []
    opened_files = []
    for p in csv_paths:
        f = open(p, 'rb')
        opened_files.append(f)
        files.append(f)

    # POST request
    print("Sending POST request to /analyze/...")
    response = client.post('/analyze/', {'files': files, 'run_osint': 'off'}, follow=True)

    # Close files
    for f in opened_files:
        f.close()

    print("Response status code:", response.status_code)
    print("Redirect chain:", response.redirect_chain)

    print("\nAfter run database counts:")
    print("  KnownMalware count:", KnownMalware.objects.count())
    print("  KnownMalware list:", list(KnownMalware.objects.values_list('name', flat=True)))
    print("  KnownASN count:", KnownASN.objects.count())
    print("  KnownASN list:", list(KnownASN.objects.values_list('asn_number', 'operator_name')))
    print("  AnalysisRun count:", AnalysisRun.objects.count())

    if AnalysisRun.objects.exists():
        run = AnalysisRun.objects.first()
        print("\nLast AnalysisRun stats:")
        print("  Folder name:", run.folder_name)
        print("  Total rows:", run.total_rows)
        print("  Seen combos count (duplicates):", run.seen_combos_count)
        print("  Unique ASNs:", run.unique_asns)
        print("  Unique malwares:", run.unique_malwares)
        print("  Unique IPs:", run.unique_ips)
        print("  New malwares:", run.new_malwares)
        print("  ASN Stats:", run.asn_stats)
        print("  Output directory:", run.output_dir)
        
        # Check output files
        media_root = settings.MEDIA_ROOT
        out_dir = os.path.join(media_root, run.output_dir)
        print("\nGenerated files in output directory:")
        if os.path.exists(out_dir):
            subdirs_found = []
            for f in os.listdir(out_dir):
                print("  -", f)
                full_f = os.path.join(out_dir, f)
                if os.path.isdir(full_f):
                    subdirs_found.append(f)
            if subdirs_found:
                print("  [ERROR] Subdirectories found in output folder (not flat!):", subdirs_found)
                sys.exit(1)
            else:
                print("  [SUCCESS] All files written flat in the output folder.")
        else:
            print("  [ERROR] Output directory does not exist on disk!")
            sys.exit(1)
    else:
        print("  [ERROR] No AnalysisRun was created!")
        sys.exit(1)

    # Check malware entries
    from malware_views.models import MalwareEntry
    malware_count = MalwareEntry.objects.count()
    print(f"\nMalware entries in database: {malware_count}")
    if malware_count > 0:
        print("  Malware list:", list(MalwareEntry.objects.values_list('name', flat=True)))
    else:
        print("  [WARNING] No malware entries created!")

    print("\n=== End-to-End Test Passed Successfully! ===")


if __name__ == '__main__':
    bootstrap_db()

    args = sys.argv
    if len(args) > 1 and args[1] == 'test_e2e':
        run_e2e_test()
        sys.exit(0)

    if len(args) == 1:
        args = [args[0], 'runserver', '8000']

    print("[CERT-Bund] Starting Django dev server…")
    from django.core.management import execute_from_command_line
    execute_from_command_line(args)