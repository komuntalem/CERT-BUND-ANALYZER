import glob
import os
from urllib.parse import quote

from django.conf import settings
from django.contrib import messages
from django.db import connection
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import DetailView, ListView

from .forms import AdvisoryForm, CSVUploadForm
from .models import Advisory, ASN, AnalysisRun, EmailDraft
from .services import AdvisoryService, CSVImportService, DocumentService





class UploadCSVView(View):
    template_name = "threatintel/upload_csv.html"

    def get(self, request):
        return render(request, self.template_name, {"form": CSVUploadForm()})

    def post(self, request):
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES["csv_file"]
            rows = CSVImportService.parse_csv(uploaded_file)
            if not rows:
                messages.error(
                    request, "No valid rows were found in the uploaded file."
                )
                return redirect("threatintel:generate-advisories")

            run = AdvisoryService.process_csv_upload(uploaded_file.name, rows)

            messages.success(
                request,
                f"Processing complete — {run.row_count} rows ingested, "
                f"{run.new_event_count} new events detected, "
                f"{run.advisory_count} advisories generated.",
            )
            return redirect("threatintel:advisory-list")
        return render(request, self.template_name, {"form": form})


def generate_from_run(request, run_id):
    """Generate advisories from an analysis run's uploaded CSV files.

    Reads CSV files saved by Developer A's analyze view, then processes
    them through the advisory pipeline to create ASN, Advisory, and
    EmailDraft records.  No re-upload required.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT output_dir FROM analyzer_analysisrun WHERE id = %s",
            [run_id],
        )
        row = cursor.fetchone()

    if not row or not row[0]:
        messages.error(request, "Analysis run not found.")
        return redirect("/")

    # Derive upload directory from output directory
    # output_dir is like "runs/run_20260618_050000_1/output"
    # uploads live at   "runs/run_20260618_050000_1/uploads"
    run_base = os.path.dirname(row[0])
    upload_dir = os.path.join(settings.MEDIA_ROOT, run_base, "uploads")

    if not os.path.isdir(str(upload_dir)):
        messages.error(request, "Upload directory not found on disk.")
        return redirect("/")

    csv_files = sorted(glob.glob(os.path.join(str(upload_dir), "*.csv")))
    if not csv_files:
        messages.error(request, "No CSV files found in the analysis run.")
        return redirect("/")

    total_advisories = 0
    total_events = 0
    for csv_path in csv_files:
        with open(csv_path, "rb") as f:
            rows = CSVImportService.parse_csv(f)
            if rows:
                run = AdvisoryService.process_csv_upload(
                    os.path.basename(csv_path), rows
                )
                total_advisories += run.advisory_count
                total_events += run.new_event_count

    messages.success(
        request,
        f"Advisory generation complete — {total_events} new events, "
        f"{total_advisories} advisories generated.",
    )
    return redirect("threatintel:advisory-list")


class ASNListView(ListView):
    model = ASN
    template_name = "threatintel/asn_list.html"
    context_object_name = "asns"


class ASNDetailView(DetailView):
    model = ASN
    template_name = "threatintel/asn_detail.html"
    context_object_name = "asn"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        asn = self.object
        
        # Get the latest run ID
        latest_run = AnalysisRun.objects.order_by("-uploaded_at").first()
        
        # Get all advisories associated with this ASN in the latest run
        if latest_run:
            advisories = list(asn.advisories.filter(source_run=latest_run).prefetch_related("malware_families").order_by("-advisory_date", "-id"))
        else:
            advisories = list(asn.advisories.prefetch_related("malware_families").order_by("-advisory_date", "-id"))
        
        if advisories:
            latest_advisory = advisories[0]
            
            # Since we filter by the current run, malware families are exactly the ones from this run's advisory
            all_malware_families = list(latest_advisory.malware_families.all())
            
            context["latest_advisory"] = latest_advisory
            context["all_malware_families"] = all_malware_families
            context["has_advisories"] = True
        else:
            context["has_advisories"] = False
            context["all_malware_families"] = []
            
        # Find the latest analyzer run ID for the back button
        try:
            from analyzer.models import AnalysisRun as AnalyzerRun
            latest_analyzer_run = AnalyzerRun.objects.order_by('-created_at').first()
            if latest_analyzer_run:
                context["dashboard_run_id"] = latest_analyzer_run.pk
        except Exception:
            pass

        return context



class AdvisoryListView(ListView):
    model = Advisory
    template_name = "threatintel/advisory_list.html"
    context_object_name = "advisories"

    def get_queryset(self):
        # We only show advisories from the latest/current run!
        latest_run = AnalysisRun.objects.order_by("-uploaded_at").first()
        if latest_run:
            qs = Advisory.objects.filter(source_run=latest_run).select_related("asn").prefetch_related(
                "malware_families"
            ).order_by("-advisory_date", "-id")
        else:
            qs = Advisory.objects.none()

        asn_filter = self.request.GET.get("asn", "").strip()
        malware_filter = self.request.GET.get("malware", "").strip()
        if asn_filter:
            qs = qs.filter(asn__asn_number__icontains=asn_filter)
        if malware_filter:
            qs = qs.filter(
                malware_families__malware_name__icontains=malware_filter
            ).distinct()
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["filter_asn"] = self.request.GET.get("asn", "")
        ctx["filter_malware"] = self.request.GET.get("malware", "")

        # Annotate each advisory with its malware list for the template
        for adv in ctx["advisories"]:
            adv.malware_list = list(adv.malware_families.all())
            
        # Find the latest analyzer run ID for the back button
        try:
            from analyzer.models import AnalysisRun as AnalyzerRun
            latest_analyzer_run = AnalyzerRun.objects.order_by('-created_at').first()
            if latest_analyzer_run:
                ctx["dashboard_run_id"] = latest_analyzer_run.pk
        except Exception:
            pass
            
        return ctx


class AdvisoryDetailView(View):
    template_name = "threatintel/advisory_detail.html"

    def get(self, request, pk):
        advisory = get_object_or_404(
            Advisory.objects.select_related("asn").prefetch_related(
                "malware_families"
            ),
            pk=pk,
        )
        # Ensure html_content is populated
        if not advisory.html_content:
            advisory.html_content = AdvisoryService.build_advisory_html(advisory)
            advisory.save(update_fields=["html_content"])

        form = AdvisoryForm(instance=advisory)

        try:
            email_draft = advisory.email_draft
        except Advisory.email_draft.RelatedObjectDoesNotExist:
            email_draft = None

        return render(
            request,
            self.template_name,
            {
                "advisory": advisory,
                "form": form,
                "advisory_html": advisory.html_content,
                "malware_list": list(advisory.malware_families.all()),
                "has_email_draft": email_draft is not None,
            },
        )

    def post(self, request, pk):
        advisory = get_object_or_404(Advisory, pk=pk)
        form = AdvisoryForm(request.POST, instance=advisory)

        if form.is_valid():
            saved = form.save(commit=False)
            saved.status = "draft"
            saved.save()

            # Save html_content if passed in the form (fallback/non-ajax POST)
            if "html_content" in request.POST:
                saved.html_content = request.POST["html_content"]
                saved.save(update_fields=["html_content"])

            subject = (
                f"Cybersecurity Advisory Notification – "
                f"{advisory.asn.get_display_name()}"
            )
            body = AdvisoryService.build_email_body(advisory)
            EmailDraft.objects.update_or_create(
                advisory=advisory,
                defaults={"subject": subject, "body": body},
            )

            messages.success(request, "Advisory saved and email draft updated.")
            return redirect("threatintel:advisory-detail", pk=advisory.pk)

        try:
            email_draft = advisory.email_draft
        except Advisory.email_draft.RelatedObjectDoesNotExist:
            email_draft = None

        return render(
            request,
            self.template_name,
            {
                "advisory": advisory,
                "form": form,
                "advisory_html": advisory.html_content,
                "malware_list": list(advisory.malware_families.all()),
                "has_email_draft": email_draft is not None,
            },
        )




# ---------------------------------------------------------------------------
# DOCX DOWNLOADS
# ---------------------------------------------------------------------------


def download_advisory_docx(request, pk):
    """Download an advisory as a professionally formatted DOCX document."""
    advisory = get_object_or_404(Advisory, pk=pk)
    docx_bytes = DocumentService.generate_advisory_docx(advisory)
    response = HttpResponse(
        docx_bytes,
        content_type=(
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document"
        ),
    )
    safe_name = (advisory.advisory_number or f"advisory_{pk}").replace(" ", "_")
    response["Content-Disposition"] = (
        f'attachment; filename="{safe_name}.docx"'
    )
    return response


def download_email_docx(request, pk):
    """Download an email draft as a DOCX document."""
    advisory = get_object_or_404(Advisory, pk=pk)
    docx_bytes = DocumentService.generate_email_docx(advisory)
    response = HttpResponse(
        docx_bytes,
        content_type=(
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document"
        ),
    )
    safe_name = f"email_draft_{advisory.advisory_number or pk}".replace(" ", "_")
    response["Content-Disposition"] = (
        f'attachment; filename="{safe_name}.docx"'
    )
    return response


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json

def save_advisory_html(request, pk):
    """Save edited advisory HTML content via AJAX and update email draft metadata."""
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    advisory = get_object_or_404(Advisory, pk=pk)
    try:
        data = json.loads(request.body)
        html_content = data.get("html_content", "")
        advisory.html_content = html_content
        advisory.save(update_fields=["html_content"])
        
        # Keep EmailDraft synchronized with the main advisory update
        subject = f"Cybersecurity Advisory Notification – {advisory.asn.get_display_name()}"
        body = AdvisoryService.build_email_body(advisory)
        EmailDraft.objects.update_or_create(
            advisory=advisory,
            defaults={"subject": subject, "body": body},
        )
        return JsonResponse({"success": True})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


def regenerate_advisory_html(request, pk):
    """Regenerate default advisory HTML content from malware entries via AJAX."""
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    advisory = get_object_or_404(Advisory, pk=pk)
    try:
        html_content = AdvisoryService.build_advisory_html(advisory)
        advisory.html_content = html_content
        advisory.save(update_fields=["html_content"])
        return JsonResponse({"success": True, "html_content": html_content})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)



# ---------------------------------------------------------------------------
# GMAIL INTEGRATION
# ---------------------------------------------------------------------------


def open_gmail_draft(request, pk):
    """Open Gmail compose with pre-populated subject and body.

    Does NOT send automatically — the analyst enters recipients and reviews
    the content before sending.  Marks the advisory as "sent" upon opening.
    """
    advisory = get_object_or_404(Advisory, pk=pk)
    try:
        email_draft = advisory.email_draft
    except Advisory.email_draft.RelatedObjectDoesNotExist:
        messages.error(request, "No email draft exists for this advisory.")
        return redirect("threatintel:advisory-detail", pk=pk)

    subject = quote(email_draft.subject)
    body = quote(email_draft.body)
    gmail_url = f"https://mail.google.com/mail/?view=cm&fs=1&su={subject}&body={body}"

    # Transition advisory status: Draft → Sent
    if advisory.status != "sent":
        advisory.status = "sent"
        advisory.save(update_fields=["status"])

    return HttpResponseRedirect(gmail_url)
