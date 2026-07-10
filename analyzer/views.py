import glob
import os
import json
import logging
import shutil
from collections import defaultdict
from datetime import datetime

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.db.models import Max
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .models import KnownMalware, KnownASN, AnalysisRun
from .analysis_engine import run_analysis, create_results_zip, _seen_combos_path

log = logging.getLogger("cert_bund_web")


def index(request):
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

    ts         = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir    = os.path.join(settings.MEDIA_ROOT, 'runs', f'run_{ts}_{request.user.id}')
    upload_dir = os.path.join(run_dir, 'uploads')
    output_dir = os.path.join(run_dir, 'output')
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

        # Pre-seed threatintel.ASN so advisory pipeline finds records
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

        # Save newly discovered malware
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

    run = AnalysisRun.objects.create(
        created_by        = request.user,
        folder_name       = folder_name,
        total_rows        = stats['total_rows'],
        seen_combos_count = stats.get('duplicate_count', 0),
        unique_asns       = stats['unique_asns'],
        unique_malwares   = stats['unique_malwares'],
        unique_ips        = stats['unique_ips'],
        asn_stats         = stats['asn_stats'],
        malware_stats     = stats['malware_stats'],
        ip_stats          = stats['ip_stats'],
        new_malwares      = stats.get('new_malwares', []),
        malware_asn_stats = stats.get('malware_asn_stats', {}),
        output_dir        = out_rel,
        status            = 'done',
        is_first_run      = stats.get('is_first_run', False),
    )

    # ── Auto-create MalwareEntry records with AI severity (no docx generation) ──
    try:
        from malware_views.views import create_malware_entries_with_severity

        all_malware = set()
        for row in stats.get('all_rows', []):
            malware_name = row.get('malware', '').strip()
            if malware_name:
                all_malware.add(malware_name)

        if all_malware:
            created_count = create_malware_entries_with_severity(all_malware, run.pk)
            log.info(f"Created {created_count} new malware entries with AI severity")

    except ImportError as e:
        log.warning(f"Malware module not available: {e}")
    except Exception as e:
        log.error(f"Error creating malware entries: {e}")

    # ── Auto-generate threatintel advisories from uploaded CSVs ──────────────
    try:
        from threatintel.services import CSVImportService, AdvisoryService

        csv_paths = sorted(glob.glob(os.path.join(upload_dir, '*.csv')))
        all_rows = []
        for csv_path in csv_paths:
            with open(csv_path, 'rb') as f:
                rows = CSVImportService.parse_csv(f)
                if rows:
                    all_rows.extend(rows)
        if all_rows:
            AdvisoryService.process_csv_upload(folder_name, all_rows)
            log.info(f"Auto-generated advisories for folder: {folder_name}")
    except ImportError as e:
        log.warning(f"Threatintel module not available for advisory auto-generation: {e}")
    except Exception as e:
        log.error(f"Advisory auto-generation failed (non-fatal): {e}")
    # ── end advisory auto-generation ─────────────────────────────────────────

    return redirect('dashboard', run_id=run.pk)


@login_required(login_url='/')
def dashboard(request, run_id):
    run = get_object_or_404(AnalysisRun, pk=run_id, created_by=request.user)
    asn_labels,     asn_values     = run.asn_chart_data()
    malware_labels, malware_values = run.malware_chart_data()
    ip_labels,      ip_values      = run.ip_chart_data()
    new_events_count = run.total_rows - run.seen_combos_count

    total_baseline_events = 0
    try:
        with open(_seen_combos_path(), 'r', encoding='utf-8') as f:
            total_baseline_events = sum(1 for line in f if line.strip())
    except Exception:
        pass

    # ── ASN legend enrichment — map labels to advisory links ─────────────────
    reverse_map = dict(
        KnownASN.objects
        .filter(operator_name__in=asn_labels)
        .values_list('operator_name', 'asn_number')
    )
    forward_map = dict(
        KnownASN.objects
        .filter(asn_number__in=asn_labels)
        .values_list('asn_number', 'operator_name')
    )

    resolved_asn_numbers = []
    for label in asn_labels:
        asn_num = (
            reverse_map.get(label)
            or (label if label.startswith('AS') else None)
            or (f'AS{label}' if label.isdigit() else None)
        )
        resolved_asn_numbers.append(asn_num)

    try:
        from threatintel.models import Advisory as ThreatAdvisory, ASN as ThreatASN

        advisory_pk_map = dict(
            ThreatAdvisory.objects
            .filter(asn__asn_number__in=[n for n in resolved_asn_numbers if n])
            .values('asn__asn_number')
            .annotate(latest_pk=Max('pk'))
            .values_list('asn__asn_number', 'latest_pk')
        )

        ti_asn_org_map = dict(
            ThreatASN.objects
            .filter(asn_number__in=[n for n in resolved_asn_numbers if n])
            .values_list('asn_number', 'organization_name')
        )

        asn_legend_items = []
        asn_org_labels   = []

        for label, asn_num in zip(asn_labels, resolved_asn_numbers):
            if label.startswith('AS'):
                org_name = forward_map.get(label) or label
            elif label.isdigit():
                org_name = ti_asn_org_map.get(f'AS{label}') or label
            else:
                org_name = label

            advisory_pk  = advisory_pk_map.get(asn_num) if asn_num else None
            advisory_url = f"/intel/advisories/{advisory_pk}/" if advisory_pk else None

            asn_org_labels.append(org_name)
            asn_legend_items.append({
                'org_name':    org_name,
                'asn':         asn_num or label,
                'advisory_url': advisory_url,
            })

    except ImportError as e:
        log.warning(f"Threatintel module not available for ASN enrichment: {e}")
        asn_org_labels   = asn_labels
        asn_legend_items = []
    except Exception as e:
        log.warning(f"ASN enrichment failed (non-fatal): {e}")
        asn_org_labels   = asn_labels
        asn_legend_items = []
    # ── end ASN legend enrichment ─────────────────────────────────────────────

    # ── Trend Graphs Logic ────────────────────────────────────────────────────
    all_runs = AnalysisRun.objects.filter(created_by=request.user, status='done').order_by('created_at')

    trend_dates      = []
    trend_volume     = []
    trend_duplicates = []
    trend_asns       = []
    trend_malwares   = []
    all_time_malware = defaultdict(int)

    for r in all_runs:
        trend_dates.append(r.folder_name or f"Run {r.id}")
        trend_volume.append(r.total_rows)
        trend_duplicates.append(r.seen_combos_count)
        trend_asns.append(r.unique_asns)
        trend_malwares.append(r.unique_malwares)

    try:
        with open(_seen_combos_path(), 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) >= 4 and parts[3]:
                    all_time_malware[parts[3]] += 1
    except Exception as e:
        log.error(f"Failed to read seen_combos.txt for malware trends: {e}")

    sorted_all_time = sorted(all_time_malware.items(), key=lambda x: x[1], reverse=True)[:10]
    trend_top_malware_labels = [k for k, v in sorted_all_time]
    trend_top_malware_values = [v for k, v in sorted_all_time]
    show_trends = len(all_runs) >= 2

    return render(request, 'analyzer/dashboard.html', {
        'run':            run,
        'raw_asn_labels': json.dumps(asn_labels),
        'asn_labels':     json.dumps(asn_org_labels),
        'asn_values':     json.dumps(asn_values),
        'asn_legend_items': asn_legend_items,
        'malware_labels': json.dumps(malware_labels),
        'malware_values': json.dumps(malware_values),
        'ip_labels':      json.dumps(ip_labels),
        'ip_values':      json.dumps(ip_values),
        'is_first_run':   run.is_first_run,
        'new_events_count': new_events_count,
        'total_baseline_events': total_baseline_events,
        'trend_dates':    json.dumps(trend_dates),
        'trend_volume':   json.dumps(trend_volume),
        'trend_duplicates': json.dumps(trend_duplicates),
        'trend_asns':     json.dumps(trend_asns),
        'trend_malwares': json.dumps(trend_malwares),
        'trend_top_malware_labels': json.dumps(trend_top_malware_labels),
        'trend_top_malware_values': json.dumps(trend_top_malware_values),
        'show_trends':    show_trends,
        'malware_asn_stats': json.dumps(run.malware_asn_stats),
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


def get_recent_run(request):
    """API: return the most recent run_id for the authenticated user.
    Used by the malware list 'Back' button to navigate to the last dashboard."""
    if request.user.is_authenticated:
        run = AnalysisRun.objects.filter(created_by=request.user).order_by('-created_at').first()
        if run:
            return JsonResponse({'run_id': run.pk})
    return JsonResponse({'run_id': None})
