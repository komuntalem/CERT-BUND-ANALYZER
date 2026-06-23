from django.db import models
from django.contrib.auth.models import User

class KnownMalware(models.Model):
    """Malware names tracked dynamically in the database."""
    name = models.CharField(max_length=200, unique=True)
    
    class Meta:
        db_table = 'analyzer_knownmalware'
        
    def __str__(self):
        return self.name


class KnownASN(models.Model):
    """Cache for ASN operator names resolved via BGPView API."""
    asn_number    = models.CharField(max_length=50, unique=True)
    operator_name = models.CharField(max_length=255)

    class Meta:
        db_table = 'analyzer_knownasn'

    def __str__(self):
        return f"{self.asn_number} - {self.operator_name}"


class AnalysisRun(models.Model):
    """Tracks a single folder-analysis run."""
    created_by        = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at        = models.DateTimeField(auto_now_add=True)
    folder_name       = models.CharField(max_length=500, default='')
    total_rows        = models.IntegerField(default=0)
    seen_combos_count = models.IntegerField(default=0)
    unique_asns       = models.IntegerField(default=0)
    unique_malwares   = models.IntegerField(default=0)
    unique_ips        = models.IntegerField(default=0)
    asn_stats         = models.JSONField(default=list)
    malware_stats     = models.JSONField(default=list)
    ip_stats          = models.JSONField(default=list)
    new_malwares      = models.JSONField(default=list)
    output_dir        = models.CharField(max_length=1000, blank=True, default='')
    status            = models.CharField(
        max_length=20,
        choices=[('pending', 'Pending'), ('done', 'Done'), ('error', 'Error')],
        default='done',
    )
    error_message   = models.TextField(blank=True, default='')

    class Meta:
        db_table = 'analyzer_analysisrun'
        ordering = ['-created_at']

    def __str__(self):
        return f"Run by {self.created_by} at {self.created_at:%Y-%m-%d %H:%M}"

    def asn_chart_data(self):
        return ([i['label'] for i in self.asn_stats], [i['count'] for i in self.asn_stats])

    def malware_chart_data(self):
        return ([i['label'] for i in self.malware_stats], [i['count'] for i in self.malware_stats])

    def ip_chart_data(self):
        return ([i['label'] for i in self.ip_stats], [i['count'] for i in self.ip_stats])
