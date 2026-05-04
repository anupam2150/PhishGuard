from django import forms


class ScanForm(forms.Form):
    url = forms.URLField(
        label="URL to Scan",
        max_length=2048,
        widget=forms.URLInput(attrs={"class": "form-control", "placeholder": "https://example.com"}),
    )
