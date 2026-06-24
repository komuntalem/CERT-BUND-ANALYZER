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

from .forms import AdvisoryForm, CSVUploadForm, EmailDraftForm
from .models import Advisory, ASN, AnalysisRun
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


class AdvisoryListView(ListView):
    model = Advisory
    template_name = "threatintel/advisory_list.html"
    context_object_name = "advisories"


class AdvisoryDetailView(View):
    template_name = "threatintel/advisory_detail.html"

    def get(self, request, pk):
        advisory = get_object_or_404(Advisory, pk=pk)
        form = AdvisoryForm(instance=advisory)

        # Safely access the OneToOne — avoid RelatedObjectDoesNotExist
        email_draft = getattr(advisory, "email_draft", None)
        try:
            email_draft = advisory.email_draft
        except Advisory.email_draft.RelatedObjectDoesNotExist:
            email_draft = None

        email_form = EmailDraftForm(instance=email_draft) if email_draft else None

        return render(
            request,
            self.template_name,
            {
                "advisory": advisory,
                "form": form,
                "email_form": email_form,
                "has_email_draft": email_draft is not None,
            },
        )

    def post(self, request, pk):
        advisory = get_object_or_404(Advisory, pk=pk)
        form = AdvisoryForm(request.POST, instance=advisory)

        try:
            email_draft = advisory.email_draft
        except Advisory.email_draft.RelatedObjectDoesNotExist:
            email_draft = None

        email_form = (
            EmailDraftForm(request.POST, instance=email_draft)
            if email_draft
            else None
        )

        advisory_valid = form.is_valid()
        email_valid = email_form.is_valid() if email_form else True

        if advisory_valid and email_valid:
            form.save()
            if email_form:
                email_form.save()
            messages.success(request, "Advisory updated successfully.")
            return redirect("threatintel:advisory-detail", pk=advisory.pk)

        return render(
            request,
            self.template_name,
            {
                "advisory": advisory,
                "form": form,
                "email_form": email_form,
                "has_email_draft": email_draft is not None,
            },
        )


# ---------------------------------------------------------------------------
# DOCX DOWNLOADS
# ---------------------------------------------------------------------------


def download_advisory_docx(request, pk):
    """Download an advisory as a professionally formatted DOCX document."""
    advisory = get_object_or_404(Advisory, pk=pk)
    path = DocumentService.generate_advisory_docx(advisory)
    with open(path, "rb") as f:
        response = HttpResponse(
            f.read(),
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
    path = DocumentService.generate_email_docx(advisory)
    with open(path, "rb") as f:
        response = HttpResponse(
            f.read(),
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


# ---------------------------------------------------------------------------
# GMAIL INTEGRATION
# ---------------------------------------------------------------------------


def open_gmail_draft(request, pk):
    """Open Gmail compose with pre-populated subject and body.

    Does NOT send automatically — the analyst enters recipients and reviews
    the content before sending.
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
    return HttpResponseRedirect(gmail_url)
