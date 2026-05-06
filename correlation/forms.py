from django import forms


class CampaignScanForm(forms.Form):
    scan_label = forms.CharField(
        required=False,
        max_length=100,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "e.g. PayPal phishing batch — Oct 2024",
        }),
    )
    url_input = forms.CharField(
        max_length=5000,
        widget=forms.Textarea(attrs={
            "class": "form-control font-monospace",
            "rows": 12,
            "placeholder": "Paste URLs here, one per line\nhttps://example.com/login\nhttps://paypal-verify.xyz/secure",
        }),
    )

    def clean_url_input(self):
        raw = self.cleaned_data.get("url_input", "")
        lines = [line.strip() for line in raw.splitlines()]
        urls = [l for l in lines if l]

        invalid = [u for u in urls if not (u.startswith("http://") or u.startswith("https://"))]
        if invalid:
            raise forms.ValidationError(f"Invalid URLs (must start with http:// or https://): {', '.join(invalid[:3])}")

        if len(urls) < 2:
            raise forms.ValidationError("Enter at least 2 URLs to correlate.")
        if len(urls) > 100:
            raise forms.ValidationError("Maximum 100 URLs per scan.")

        return urls
