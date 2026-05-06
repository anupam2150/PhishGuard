release: python manage.py migrate && python manage.py collectstatic --noinput
web: gunicorn phishguard.wsgi --workers 2 --timeout 120
worker: celery -A phishguard worker --loglevel=info --concurrency=2 --max-tasks-per-child=50
