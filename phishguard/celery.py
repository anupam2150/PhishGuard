import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phishguard.settings")

app = Celery("phishguard")

# Pull all CELERY_* settings from Django settings
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks.py in every INSTALLED_APP
app.autodiscover_tasks()
