import logging
import os

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class WatchlistConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "watchlist"

    def ready(self):
        # Guard: only start the scheduler in the main process.
        # - RUN_MAIN is set by Django's auto-reloader for the child process.
        # - We only want ONE scheduler instance, so we start it in the parent
        #   (when RUN_MAIN is not set) or when the reloader is disabled entirely.
        # - Also skip during management commands like migrate, makemigrations, etc.
        import sys
        if "runserver" in sys.argv and os.environ.get("RUN_MAIN") == "true":
            return
        if any(cmd in sys.argv for cmd in ("migrate", "makemigrations", "collectstatic", "shell")):
            return

        self._start_scheduler()

    def _start_scheduler(self):
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.interval import IntervalTrigger
            from django_apscheduler.jobstores import DjangoJobStore
            from django_apscheduler.models import DjangoJobExecution

            from .scheduler import rescan_watchlist

            scheduler = BackgroundScheduler(timezone="UTC")
            scheduler.add_jobstore(DjangoJobStore(), "default")

            scheduler.add_job(
                rescan_watchlist,
                trigger=IntervalTrigger(hours=6),
                id="watchlist_rescan",
                name="Watchlist periodic re-scan",
                jobstore="default",
                replace_existing=True,
                max_instances=1,
                misfire_grace_time=300,  # allow up to 5 min late start
            )

            scheduler.start()
            logger.info("APScheduler started — watchlist_rescan every 6 hours")

        except Exception as exc:
            logger.exception("Failed to start APScheduler: %s", exc)
