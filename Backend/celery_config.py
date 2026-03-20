import multiprocessing
multiprocessing.set_start_method("spawn", force=True)

CELERY_TASK_SOFT_TIME_LIMIT = None
CELERY_TASK_TIME_LIMIT = 300  # Set a hard timeout in seconds
broker_connection_retry_on_startup = True  # Retain retry behavior on startup