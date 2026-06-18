#!/usr/bin/env python
"""
cert_bund_analyzer.py — Legacy compatibility wrapper for CERT-Bund Analyzer.
Delegates to the modularized analyzer application and runs the development server
or e2e tests using the threatintelligence project configuration.
"""

import sys
import os
from pathlib import Path

# Set default settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threatintelligence.settings')

import django
django.setup()

from django.core.management import call_command
from django.contrib.auth.models import User
from analyzer.models import KnownMalware, KnownASN, AnalysisRun

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
