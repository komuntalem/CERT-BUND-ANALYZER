from django.urls import path

from . import views

app_name = "threatintel"

urlpatterns = [
    path("", views.DashboardView.as_view(), name="dashboard"),
    path("upload/", views.UploadCSVView.as_view(), name="upload-csv"),
    path("asns/", views.ASNListView.as_view(), name="asn-list"),
    path("asns/<int:pk>/", views.ASNDetailView.as_view(), name="asn-detail"),
    path("advisories/", views.AdvisoryListView.as_view(), name="advisory-list"),
    path("advisories/<int:pk>/", views.AdvisoryDetailView.as_view(), name="advisory-detail"),
    path("advisories/<int:pk>/download/", views.download_advisory_docx, name="download-advisory-docx"),
    path("advisories/<int:pk>/download-email/", views.download_email_docx, name="download-email-docx"),
    path("advisories/<int:pk>/gmail/", views.open_gmail_draft, name="gmail-draft"),
]