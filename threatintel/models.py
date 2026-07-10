from django.db import models
from django.urls import reverse
from django.utils import timezone


class ASN(models.Model):
    """Autonomous System Number with enrichment data from Team Cymru / PeeringDB."""

    asn_number = models.CharField(max_length=32, unique=True)
    organization_name = models.CharField(max_length=255, blank=True)
    contact_email = models.EmailField(blank=True)
    country = models.CharField(max_length=100, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["asn_number"]

    def __str__(self):
        if self.organization_name:
            return f"{self.asn_number} ({self.organization_name})"
        return self.asn_number

    def get_display_name(self):
        return self.organization_name or self.asn_number


class Malware(models.Model):
    malware_name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    risk_level = models.CharField(
        max_length=50,
        choices=[
            ("Critical", "Critical"),
            ("High", "High"),
            ("Medium", "Medium"),
            ("Low", "Low"),
        ],
        default="Medium",
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["malware_name"]

    def __str__(self):
        return self.malware_name


class AnalysisRun(models.Model):
    uploaded_at = models.DateTimeField(default=timezone.now)
    source_file_name = models.CharField(max_length=255)
    row_count = models.PositiveIntegerField(default=0)
    new_event_count = models.PositiveIntegerField(default=0)
    advisory_count = models.PositiveIntegerField(default=0)
    status = models.CharField(
        max_length=50,
        choices=[
            ("processing", "Processing"),
            ("completed", "Completed"),
            ("failed", "Failed"),
        ],
        default="processing",
    )

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"Run {self.pk} - {self.source_file_name}"


class AttackEvent(models.Model):
    """Stores each unique attack event fingerprint from CSV imports.

    Works alongside seen_combos.txt (audit log) for hybrid persistence.
    Database layer handles deduplication; file layer provides audit trail.
    Fingerprint format: ip|dst_ip|dst_port|malware
    """

    analysis_run = models.ForeignKey(
        AnalysisRun, on_delete=models.CASCADE, related_name="events"
    )
    asn = models.ForeignKey("ASN", on_delete=models.CASCADE, related_name="events")
    malware = models.ForeignKey(
        "Malware", on_delete=models.CASCADE, related_name="events"
    )
    fingerprint = models.CharField(max_length=512, unique=True, db_index=True)
    ip = models.CharField(max_length=45, blank=True)
    dst_ip = models.CharField(max_length=45, blank=True)
    dst_port = models.CharField(max_length=10, blank=True)
    src_port = models.CharField(max_length=10, blank=True)
    event_timestamp = models.CharField(max_length=64, blank=True)
    dst_host = models.CharField(max_length=255, blank=True)
    proto = models.CharField(max_length=20, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.fingerprint


class Advisory(models.Model):
    STATUS_CHOICES = [
        ("draft", "Draft"),
        ("sent", "Sent"),
    ]

    advisory_number = models.CharField(max_length=100, blank=True)
    advisory_date = models.DateField(default=timezone.now)
    asn = models.ForeignKey(ASN, on_delete=models.CASCADE, related_name="advisories")
    malware_families = models.ManyToManyField(
        Malware, blank=True, related_name="advisories"
    )
    content = models.TextField(blank=True)
    summary = models.TextField(blank=True)
    recommended_mitigation = models.TextField(blank=True)
    html_content = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    created_at = models.DateTimeField(default=timezone.now)
    source_run = models.ForeignKey(
        AnalysisRun,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="advisories",
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.advisory_number or 'Advisory'} - {self.asn}"

    def get_absolute_url(self):
        return reverse("threatintel:advisory-detail", kwargs={"pk": self.pk})


class EmailDraft(models.Model):
    advisory = models.OneToOneField(
        Advisory, on_delete=models.CASCADE, related_name="email_draft"
    )
    subject = models.CharField(max_length=255)
    body = models.TextField()
    generated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self):
        return self.subject

