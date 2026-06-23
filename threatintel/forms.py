from django import forms

from .models import Advisory, EmailDraft


class CSVUploadForm(forms.Form):
    csv_file = forms.FileField(
        label="Upload CSV",
        help_text="Upload a CERT-Bund CSV file for analysis.",
        widget=forms.ClearableFileInput(attrs={"class": "form-control"}),
    )


class AdvisoryForm(forms.ModelForm):
    class Meta:
        model = Advisory
        fields = [
            "advisory_number",
            "advisory_date",
            "status",
            "summary",
            "recommended_mitigation",
            "content",
        ]
        widgets = {
            "advisory_number": forms.TextInput(attrs={"class": "form-control"}),
            "advisory_date": forms.DateInput(
                attrs={"type": "date", "class": "form-control"}
            ),
            "status": forms.Select(attrs={"class": "form-select"}),
            "summary": forms.Textarea(attrs={"rows": 4, "class": "form-control"}),
            "recommended_mitigation": forms.Textarea(
                attrs={"rows": 6, "class": "form-control"}
            ),
            "content": forms.Textarea(attrs={"rows": 8, "class": "form-control"}),
        }


class EmailDraftForm(forms.ModelForm):
    class Meta:
        model = EmailDraft
        fields = ["subject", "body"]
        widgets = {
            "subject": forms.TextInput(attrs={"class": "form-control"}),
            "body": forms.Textarea(attrs={"rows": 14, "class": "form-control"}),
        }
