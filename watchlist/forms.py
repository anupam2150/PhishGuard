import re
from django import forms
from .models import WatchlistEntry

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class WatchlistEntryForm(forms.ModelForm):
    class Meta:
        model  = WatchlistEntry
        fields = ("indicator", "indicator_type", "alert_on_change", "notes")
        widgets = {
            "indicator": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "e.g. evil.com, 1.2.3.4, https://phish.example/login",
                "autocomplete": "off",
            }),
            "indicator_type": forms.Select(attrs={"class": "form-select"}),
            "alert_on_change": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "notes": forms.Textarea(attrs={
                "class": "form-control",
                "rows": 2,
                "placeholder": "Optional notes about this indicator…",
            }),
        }
        labels = {
            "indicator":      "Indicator",
            "indicator_type": "Type",
            "alert_on_change": "Alert me when risk level changes",
            "notes":          "Notes",
        }

    def clean(self):
        cleaned = super().clean()
        indicator = (cleaned.get("indicator") or "").strip()
        itype     = cleaned.get("indicator_type")

        if indicator and not itype:
            # Auto-detect if user left type blank
            if _IP_RE.match(indicator):
                cleaned["indicator_type"] = "IP"
            elif indicator.startswith("http://") or indicator.startswith("https://"):
                cleaned["indicator_type"] = "URL"
            else:
                cleaned["indicator_type"] = "DOMAIN"

        cleaned["indicator"] = indicator
        return cleaned
