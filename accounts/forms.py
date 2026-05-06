from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class ProfileAPIKeyForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ("vt_api_key", "abuseipdb_key", "gsb_api_key", "news_api_key")
        widgets = {
            "vt_api_key":     forms.TextInput(attrs={"class": "form-control", "placeholder": "VirusTotal API key"}),
            "abuseipdb_key":  forms.TextInput(attrs={"class": "form-control", "placeholder": "AbuseIPDB API key"}),
            "gsb_api_key":    forms.TextInput(attrs={"class": "form-control", "placeholder": "Google Safe Browsing API key"}),
            "news_api_key":   forms.TextInput(attrs={"class": "form-control", "placeholder": "NewsAPI key"}),
        }
        labels = {
            "vt_api_key":    "VirusTotal API Key",
            "abuseipdb_key": "AbuseIPDB API Key",
            "gsb_api_key":   "Google Safe Browsing API Key",
            "news_api_key":  "NewsAPI Key",
        }
