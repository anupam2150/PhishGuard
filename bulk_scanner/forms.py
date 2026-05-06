import csv
import io
from django import forms

MAX_URLS = 500


class BulkScanForm(forms.Form):
    file = forms.FileField(
        label="URL list (.txt or .csv)",
        help_text=f"One URL per line. Max {MAX_URLS} URLs. Accepted: .txt, .csv",
        widget=forms.ClearableFileInput(attrs={"accept": ".txt,.csv", "class": "form-control"}),
    )

    def clean_file(self):
        f = self.cleaned_data["file"]
        name = f.name.lower()

        if not (name.endswith(".txt") or name.endswith(".csv")):
            raise forms.ValidationError("Only .txt and .csv files are accepted.")

        raw = f.read().decode("utf-8", errors="ignore")
        f.seek(0)

        if name.endswith(".csv"):
            reader = csv.reader(io.StringIO(raw))
            urls = [row[0].strip() for row in reader if row and row[0].strip()]
        else:
            urls = [line.strip() for line in raw.splitlines() if line.strip()]

        # Filter to lines that look like URLs
        urls = [u for u in urls if u.startswith("http://") or u.startswith("https://")]

        if not urls:
            raise forms.ValidationError("No valid URLs found. Each URL must start with http:// or https://.")

        if len(urls) > MAX_URLS:
            raise forms.ValidationError(f"Too many URLs ({len(urls)}). Maximum is {MAX_URLS}.")

        self.cleaned_data["parsed_urls"] = urls
        return f
