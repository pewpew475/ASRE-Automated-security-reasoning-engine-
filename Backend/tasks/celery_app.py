import logging

from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

from config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "asre",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "tasks.scan_tasks",
        "tasks.report_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    result_expires=86400,
    result_extended=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=3600,
    task_time_limit=3900,
    task_max_retries=3,
    task_default_retry_delay=60,
    task_queues=(
        Queue("scans", Exchange("scans"), routing_key="scan.#"),
        Queue("reports", Exchange("reports"), routing_key="report.#"),
        Queue("default", Exchange("default"), routing_key="default"),
    ),
    task_default_queue="default",
    task_default_exchange="default",
    task_default_routing_key="default",
    broker_connection_retry_on_startup=True,
    task_routes={
        "tasks.scan_tasks.*": {"queue": "scans"},
        "tasks.report_tasks.*": {"queue": "reports"},
    },
    worker_max_tasks_per_child=10,
    worker_cancel_long_running_tasks_on_connection_loss=True,
    beat_schedule={
        "cleanup-stale-scans": {
            "task": "tasks.scan_tasks.cleanup_stale_scans",
            "schedule": crontab(minute=0, hour="*/6"),
            "args": (),
        },
    },
    worker_log_format="[%(asctime)s: %(levelname)s/%(processName)s] %(message)s",
    worker_task_log_format=(
        "[%(asctime)s: %(levelname)s/%(processName)s]"
        "[%(task_name)s(%(task_id)s)] %(message)s"
    ),
)
