import uuid
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from cryptography.fernet import Fernet
from django.conf import settings


def _fernet():
    return Fernet(settings.FIELD_ENCRYPTION_KEY.encode())


class EncryptedCharField(models.TextField):
    """Transparent encrypt-on-save / decrypt-on-load field."""

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return _fernet().decrypt(value.encode()).decode()
        except Exception:
            return value

    def to_python(self, value):
        return value

    def get_prep_value(self, value):
        if not value:
            return value
        try:
            _fernet().decrypt(value.encode())
            return value          # already encrypted
        except Exception:
            return _fernet().encrypt(value.encode()).decode()


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    vt_api_key = EncryptedCharField(blank=True, default="")
    abuseipdb_key = EncryptedCharField(blank=True, default="")
    gsb_api_key = EncryptedCharField(blank=True, default="")
    news_api_key = EncryptedCharField(blank=True, default="")
    personal_api_key = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} profile"

    def save(self, *args, **kwargs):
        if not self.personal_api_key:
            self.personal_api_key = uuid.uuid4().hex
        super().save(*args, **kwargs)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
