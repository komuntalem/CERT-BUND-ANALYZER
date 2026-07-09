"""
Three-step migration: Advisory FK→M2M for malware.

Step 1: Add the new ``malware_families`` M2M field.
Step 2: Data migration — copy FK data into M2M, merge duplicate advisories
        that share the same ASN into a single org-level advisory.
Step 3: Remove the old ``malware`` FK column.
"""

from django.db import migrations, models


def merge_advisories_to_org_level(apps, schema_editor):
    """Deduplicate advisories: merge (ASN, Malware) rows into one per ASN.

    For each ASN that has multiple advisories, keep the one with the lowest PK
    (earliest advisory number), aggregate all malware families onto it, and
    reassign email drafts.  Delete the duplicates.
    """
    Advisory = apps.get_model("threatintel", "Advisory")
    EmailDraft = apps.get_model("threatintel", "EmailDraft")

    # Phase 2: Merge advisories that share the same ASN.
    #   Group by asn_id, keep the canonical (lowest PK), collect all malware IDs,
    #   then bulk-set them (avoiding UNIQUE constraint violations from add() loops).
    from collections import defaultdict

    by_asn = defaultdict(list)
    for adv in Advisory.objects.order_by("pk"):
        by_asn[adv.asn_id].append(adv)

    for asn_id, advisories in by_asn.items():
        canonical = advisories[0]  # lowest PK

        # Collect all malware IDs across all advisories for this ASN (including canonical's own)
        all_malware_ids = set()
        if canonical.malware_id:
            all_malware_ids.add(canonical.malware_id)

        for dup in advisories[1:]:
            if dup.malware_id:
                all_malware_ids.add(dup.malware_id)

        # Use set() which is idempotent and avoids unique-constraint violations
        canonical.malware_families.set(all_malware_ids)

        # Process duplicates: reassign email drafts, then delete
        for dup in advisories[1:]:
            try:
                dup_draft = EmailDraft.objects.get(advisory_id=dup.pk)
                # If canonical already has a draft, delete the duplicate draft
                if EmailDraft.objects.filter(advisory_id=canonical.pk).exists():
                    dup_draft.delete()
                else:
                    dup_draft.advisory_id = canonical.pk
                    dup_draft.save()
            except EmailDraft.DoesNotExist:
                pass

            dup.delete()

    # Phase 1 (now last): for any remaining single-ASN advisories, copy their FK into M2M
    for adv in Advisory.objects.all():
        if adv.malware_id and not adv.malware_families.exists():
            adv.malware_families.add(adv.malware_id)


def reverse_merge(apps, schema_editor):
    """Reverse is a no-op — we cannot un-merge advisories."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("threatintel", "0003_remove_ready_status"),
    ]

    operations = [
        # Step 1: Add the M2M field (coexists with old FK temporarily)
        migrations.AddField(
            model_name="advisory",
            name="malware_families",
            field=models.ManyToManyField(
                blank=True, related_name="+", to="threatintel.malware"
            ),
        ),
        # Step 2: Data migration — copy FK → M2M, merge duplicates
        migrations.RunPython(merge_advisories_to_org_level, reverse_merge),
        # Step 3: Remove old FK column
        migrations.RemoveField(
            model_name="advisory",
            name="malware",
        ),
        # Step 4: Fix the related_name on the M2M now that FK is gone
        migrations.AlterField(
            model_name="advisory",
            name="malware_families",
            field=models.ManyToManyField(
                blank=True, related_name="advisories", to="threatintel.malware"
            ),
        ),
    ]
