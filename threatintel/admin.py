from django.contrib import admin

from .models import Advisory, ASN, AnalysisRun, AttackEvent, EmailDraft, Malware

admin.site.register(ASN)
admin.site.register(Malware)
admin.site.register(AnalysisRun)
admin.site.register(AttackEvent)
admin.site.register(Advisory)
admin.site.register(EmailDraft)
