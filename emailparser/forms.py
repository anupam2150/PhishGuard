from django import forms


class EmailHeaderForm(forms.Form):
    raw_headers = forms.CharField(
        label="Raw Email Headers",
        widget=forms.Textarea(attrs={
            "class": "form-control font-monospace",
            "rows": 4,
            "placeholder": "Paste raw email headers here...",
            "style": "resize:vertical; min-height:90px;",
        }),
    )
