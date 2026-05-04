import re
from django import forms

HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class IntelForm(forms.Form):
    indicator = forms.CharField(
        label="Indicator (IP / Domain / URL / Hash)",
        max_length=2048,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "e.g. 8.8.8.8 | evil.com | https://... | md5/sha256",
        }),
    )
