import os
import json
import logging
import shutil
from datetime import datetime

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .models import KnownMalware, KnownASN, AnalysisRun
from .analysis_engine import run_analysis, create_results_zip

log = logging.getLogger("cert_bund_web")

def index(request):
    if request.user.is_authenticated:
        return render(request, 'analyzer/upload.html')
    return render(request, 'analyzer/index.html')


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

    ts          = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir     = os.path.join(settings.MEDIA_ROOT, 'runs', f'run_{ts}_{request.user.id}')
    upload_dir  = os.path.join(run_dir, 'uploads')
    output_dir  = os.path.join(run_dir, 'output')
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
            
        # Save newly discovered malware
        for mw in stats.get('new_malwares', []):
            KnownMalware.objects.get_or_create(name=mw)
            
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
        output_dir        = out_rel,
        status            = 'done',
    )

    # ── Auto-create MalwareEntry records for malware found in this run ──
    try:
        from malware_views.models import MalwareEntry
        from malware_views.report_generator import generate_malware_report

        all_malware = set()
        for row in stats.get('all_rows', []):
            malware_name = row.get('malware', '').strip()
            if malware_name:
                all_malware.add(malware_name)

        # Create entries for each malware
        for malware_name in all_malware:
            if malware_name:
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
    except ImportError as e:
        log.warning(f"Malware module not available: {e}")
    except Exception as e:
        log.error(f"Error creating malware entries: {e}")

    return redirect('dashboard', run_id=run.pk)


@login_required(login_url='/')
def dashboard(request, run_id):
    run = get_object_or_404(AnalysisRun, pk=run_id, created_by=request.user)
    asn_labels,     asn_values     = run.asn_chart_data()
    malware_labels, malware_values = run.malware_chart_data()
    ip_labels,      ip_values      = run.ip_chart_data()
    return render(request, 'analyzer/dashboard.html', {
        'run':            run,
        'asn_labels':     json.dumps(asn_labels),
        'asn_values':     json.dumps(asn_values),
        'malware_labels': json.dumps(malware_labels),
        'malware_values': json.dumps(malware_values),
        'ip_labels':      json.dumps(ip_labels),
        'ip_values':      json.dumps(ip_values),
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
