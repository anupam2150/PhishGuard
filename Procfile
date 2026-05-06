release: python manage.py migrate
web: gunicorn phishguard.wsgi:application --workers 2 --timeout 120
worker: celery -A phishguard worker --loglevel=info --concurrency=2 --max-tasks-per-child=50
