import glob
import os
import json
import logging
import shutil
from datetime import datetime

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .models import KnownMalware, KnownASN, AnalysisRun
from .analysis_engine import run_analysis, create_results_zip

log = logging.getLogger("cert_bund_web")


def index(request):
    # Always show the login page for unauthenticated users.
    # SESSION_EXPIRE_AT_BROWSER_CLOSE=True ensures the session cookie
    # is discarded when the browser closes, so this branch is always
    # reached on a fresh browser open.
    if not request.user.is_authenticated:
        return render(request, 'analyzer/index.html')
    return render(request, 'analyzer/upload.html')


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

    uploaded = request.FILES.getlist('files')
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

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir = os.path.join(settings.MEDIA_ROOT, 'runs', f'run_{ts}_{request.user.id}')
    upload_dir = os.path.join(run_dir, 'uploads')
    output_dir = os.path.join(run_dir, 'output')
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    file_pairs = []
    folder_name = ''
    for f in csv_files:
        orig_name = f.name
        if not folder_name:
            parts = orig_name.replace('\\', '/').split('/')
            folder_name = parts[0] if len(parts) > 1 else 'Uploaded Files'

        safe_name = os.path.basename(orig_name.replace('\\', '/'))
        tmp_path = os.path.join(upload_dir, safe_name)
        with open(tmp_path, 'wb') as out:
            for chunk in f.chunks():
                out.write(chunk)
        file_pairs.append((safe_name, tmp_path))

    try:
        db_malware = set(KnownMalware.objects.values_list('name', flat=True))
        db_asn_map = dict(KnownASN.objects.values_list('asn_number', 'operator_name'))

        stats = run_analysis(
            file_pairs, output_dir,
            run_osint=run_osint,
            known_malware=db_malware,
            db_asn_map=db_asn_map,
            abuseipdb_key=abuseipdb_key
        )

        # Save newly discovered ASNs
        for asn_num, op_name in stats.get('new_asns', {}).items():
            KnownASN.objects.get_or_create(asn_number=asn_num, defaults={'operator_name': op_name})

        # Pre-seed threatintel.ASN so the advisory pipeline finds records
        # already populated and skips external lookups (Team Cymru / PeeringDB).
        # Uses the same already-resolved data — no additional network calls.
        try:
            from threatintel.models import ASN as ThreatASN
            for asn_num, op_name in stats.get('new_asns', {}).items():
                obj, created = ThreatASN.objects.get_or_create(
                    asn_number=asn_num,
                    defaults={'organization_name': op_name},
                )
                if not created and not obj.organization_name and op_name:
                    obj.organization_name = op_name
                    obj.save(update_fields=['organization_name'])
        except Exception as e:
            log.warning("Could not pre-seed threatintel ASN table: %s", e)

        # Save newly discovered malware - handle as list
        new_malwares = stats.get('new_malwares', [])
        if isinstance(new_malwares, list):
            for mw in new_malwares:
                if mw:
                    KnownMalware.objects.get_or_create(name=mw)
        else:
            log.warning(f"new_malwares is not a list: {type(new_malwares)}")

    except Exception as exc:
        log.exception("Analysis failed: %s", exc)
        shutil.rmtree(run_dir, ignore_errors=True)
        return render(request, 'analyzer/upload.html', {'error': f'Analysis failed: {exc}'})

    out_abs = stats.get('output_dir', '')
    out_rel = os.path.relpath(out_abs, settings.MEDIA_ROOT) if out_abs else ''

    # Ensure new_malwares is a list before storing
    new_malwares = stats.get('new_malwares', [])
    if not isinstance(new_malwares, list):
        new_malwares = []
        log.warning("new_malwares was not a list, defaulting to empty list")

    run = AnalysisRun.objects.create(
        created_by=request.user,
        folder_name=folder_name,
        total_rows=stats['total_rows'],
        seen_combos_count=stats.get('duplicate_count', 0),
        unique_asns=stats['unique_asns'],
        unique_malwares=stats['unique_malwares'],
        unique_ips=stats['unique_ips'],
        asn_stats=stats['asn_stats'],
        malware_stats=stats['malware_stats'],
        ip_stats=stats['ip_stats'],
        new_malwares=new_malwares,
        output_dir=out_rel,
        status='done',
    )

    # ── Auto-create MalwareEntry records with severity ────────────────────
    try:
        from malware_views.models import MalwareEntry
        from malware_views.report_generator import generate_malware_report
        # Import the helper function from malware_views.views
        from malware_views.views import create_malware_entries_with_severity, safe_str

        all_malware = set()

        # Get malware from all_rows
        for row in stats.get('all_rows', []):
            malware_name = row.get('malware', '').strip()
            if malware_name:
                all_malware.add(malware_name)

        # Also get from malware_stats (top 10)
        for item in stats.get('malware_stats', []):
            malware_name = item.get('label', '').strip()
            if malware_name:
                all_malware.add(malware_name)

        log.info(f"Total unique malware detected: {len(all_malware)}")
        if all_malware:
            log.info(f"Malware names: {', '.join(sorted(all_malware))}")

        # Create entries with severity using the helper function
        try:
            created_count = create_malware_entries_with_severity(all_malware, run.pk)
            log.info(f"Created/updated {created_count} malware entries with severity")
        except Exception as e:
            log.error(f"Error in create_malware_entries_with_severity: {e}")
            # Fallback to original method if helper fails
            for malware_name in all_malware:
                if malware_name:
                    try:
                        entry, created = MalwareEntry.objects.get_or_create(
                            name=malware_name,
                            defaults={
                                'first_seen_run_id': run.pk,
                                'severity': 'unknown',
                                'status': 'new'
                            }
                        )
                        if created:
                            log.info(f"New malware detected (fallback): {malware_name}")
                            # Generate report for fallback created entries
                            try:
                                generate_malware_report(malware_name, entry, request.user)
                                log.info(f"Auto-generated malware report for: {malware_name}")
                            except Exception as report_error:
                                log.error(f"Error generating report for {malware_name}: {report_error}")
                    except Exception as e2:
                        log.error(f"Error creating entry for {malware_name}: {e2}")

        # Generate reports for each malware (only if not already generated)
        for malware_name in all_malware:
            if malware_name:
                try:
                    # Check if entry exists and is newly created
                    entry = MalwareEntry.objects.get(name=malware_name)
                    # Only generate report if entry was just created in this run
                    if entry.first_seen_run_id == run.pk or entry.status == 'new':
                        generate_malware_report(malware_name, entry, request.user)
                        log.info(f"Auto-generated malware report for: {malware_name}")
                    else:
                        log.info(f"Malware already exists with report: {malware_name}")
                except MalwareEntry.DoesNotExist:
                    # If entry doesn't exist, create it
                    try:
                        entry, created = MalwareEntry.objects.get_or_create(
                            name=malware_name,
                            defaults={
                                'first_seen_run_id': run.pk,
                                'severity': 'unknown',
                                'status': 'new'
                            }
                        )
                        if created:
                            generate_malware_report(malware_name, entry, request.user)
                            log.info(f"Auto-generated malware report for: {malware_name}")
                    except Exception as e:
                        log.error(f"Error creating entry for {malware_name}: {e}")
                except Exception as e:
                    log.error(f"Error generating report for {malware_name}: {e}")

    except ImportError as e:
        log.warning(f"Malware module not available: {e}")
    except Exception as e:
        log.error(f"Error creating malware entries: {e}")

    # ── Auto-generate threatintel advisories from the uploaded CSVs ──────
    # Mirrors generate_from_run() in threatintel/views.py but called as a
    # service directly so no HTTP round-trip is needed. Non-fatal: if this
    # fails the analysis result and dashboard are unaffected. The manual
    # "Generate Advisories" button on the dashboard remains as a fallback.
    try:
        from threatintel.services import CSVImportService, AdvisoryService

        csv_paths = sorted(glob.glob(os.path.join(upload_dir, '*.csv')))
        for csv_path in csv_paths:
            with open(csv_path, 'rb') as f:
                rows = CSVImportService.parse_csv(f)
                if rows:
                    AdvisoryService.process_csv_upload(os.path.basename(csv_path), rows)
                    log.info(f"Auto-generated advisories from: {os.path.basename(csv_path)}")
    except ImportError as e:
        log.warning(f"Threatintel module not available for advisory auto-generation: {e}")
    except Exception as e:
        log.error(f"Advisory auto-generation failed (non-fatal): {e}")
    # ── end advisory auto-generation ─────────────────────────────────────

    return redirect('dashboard', run_id=run.pk)


@login_required(login_url='/')
def dashboard(request, run_id):
    run = get_object_or_404(AnalysisRun, pk=run_id, created_by=request.user)

    asn_labels, asn_values = run.asn_chart_data()
    malware_labels, malware_values = run.malware_chart_data()
    ip_labels, ip_values = run.ip_chart_data()

    # ── ASN legend enrichment ─────────────────────────────────────────────
    # asn_labels contains whatever asn_chart_data() returns — operator names
    # (e.g. "CLOUDFLARE") if analysis_engine resolved them, or raw ASN numbers
    # (e.g. "AS13335") if BGPView was offline. Both cases are handled below.
    #
    # Step 1: build reverse map  operator_name → asn_number  from KnownASN.
    #   KnownASN holds both columns and is populated during analyze().
    #   This gives us the ASN number needed to query threatintel.Advisory.
    reverse_map = dict(
        KnownASN.objects
        .filter(operator_name__in=asn_labels)
        .values_list('operator_name', 'asn_number')
    )
    # Also build forward map  asn_number → operator_name  for the fallback
    # case where asn_labels already contains raw ASN numbers (BGPView offline).
    forward_map = dict(
        KnownASN.objects
        .filter(asn_number__in=asn_labels)
        .values_list('asn_number', 'operator_name')
    )

    # Step 2: resolve the true ASN numbers we'll use to query Advisory.
    #   Priority: reverse_map (label is an operator name already in KnownASN)
    #           → label itself if it starts with 'AS' (e.g. "AS13335")
    #           → 'AS' + label if it is a bare integer (e.g. "37075")
    #           → None (no advisory lookup possible)
    resolved_asn_numbers = []
    for label in asn_labels:
        asn_num = (
            reverse_map.get(label)
            or (label if label.startswith('AS') else None)
            or (f'AS{label}' if label.isdigit() else None)
        )
        resolved_asn_numbers.append(asn_num)

    # Step 3: latest advisory pk per ASN number — one query, no N+1.
    try:
        from threatintel.models import Advisory as ThreatAdvisory, ASN as ThreatASN

        advisory_pk_map = dict(
            ThreatAdvisory.objects
            .filter(asn__asn_number__in=[n for n in resolved_asn_numbers if n])
            .values('asn__asn_number')
            .annotate(latest_pk=Max('pk'))
            .values_list('asn__asn_number', 'latest_pk')
        )  # {"AS13335": 12, "AS3320": 7}

        # Bulk fetch org names from threatintel.ASN — used when labels are bare
        # integers (BGPView offline). One query; keyed by 'AS'-prefixed number.
        ti_asn_org_map = dict(
            ThreatASN.objects
            .filter(asn_number__in=[n for n in resolved_asn_numbers if n])
            .values_list('asn_number', 'organization_name')
        )

        # Step 4: build legend items and org-label list for the chart tooltips.
        asn_legend_items = []
        asn_org_labels = []

        for label, asn_num in zip(asn_labels, resolved_asn_numbers):
            # Display name resolution:
            #   'AS13335'   → forward_map lookup (KnownASN operator_name) or label
            #   '37075'     → ti_asn_org_map lookup (threatintel.ASN.organization_name)
            #   'CLOUDFLARE'→ already an operator name, use directly
            if label.startswith('AS'):
                org_name = forward_map.get(label) or label
            elif label.isdigit():
                org_name = ti_asn_org_map.get(f'AS{label}') or label
            else:
                org_name = label  # already an operator name

            advisory_pk = advisory_pk_map.get(asn_num) if asn_num else None
            advisory_url = f"/intel/advisories/{advisory_pk}/" if advisory_pk else None

            asn_org_labels.append(org_name)
            asn_legend_items.append({
                'org_name': org_name,
                'asn': asn_num or label,
                'advisory_url': advisory_url,
            })
    except ImportError as e:
        log.warning(f"Threatintel module not available for ASN enrichment: {e}")
        asn_org_labels = asn_labels
        asn_legend_items = []
    except Exception as e:
        log.warning(f"ASN enrichment failed (non-fatal): {e}")
        asn_org_labels = asn_labels
        asn_legend_items = []
    # ── end ASN legend enrichment ─────────────────────────────────────────

    return render(request, 'analyzer/dashboard.html', {
        'run': run,
        'asn_labels': json.dumps(asn_org_labels),  # org names for chart tooltips
        'asn_values': json.dumps(asn_values),      # counts unchanged
        'asn_legend_items': asn_legend_items,      # server-rendered legend
        'malware_labels': json.dumps(malware_labels),
        'malware_values': json.dumps(malware_values),
        'ip_labels': json.dumps(ip_labels),
        'ip_values': json.dumps(ip_values),
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


# ── API endpoint for getting the most recent run ──────────────────────────────
def get_recent_run(request):
    """
    Get the most recent analysis run for the current user.
    Used by the malware list page to navigate back to the dashboard.
    """
    if request.user.is_authenticated:
        run = AnalysisRun.objects.filter(created_by=request.user).order_by('-created_at').first()
        if run:
            return JsonResponse({'run_id': run.pk})
    return JsonResponse({'run_id': None})