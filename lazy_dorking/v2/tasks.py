"""Celery dispatches bounded jobs; Redis is never the source of scan state."""
import asyncio
import os

from celery import Celery

from .store import Store
from .worker import run_one

app = Celery("blh", broker=os.getenv("BLH_REDIS_URL", "redis://localhost:6379/0"))
app.conf.update(task_acks_late=True, task_reject_on_worker_lost=True, worker_prefetch_multiplier=1,
    task_ignore_result=True, task_soft_time_limit=110, task_time_limit=115,
    beat_schedule={"dispatch": {"task": "blh.step", "schedule": 1.0, "options": {"expires": 5}}})


@app.task(name="blh.step")
def step():
    store = Store()
    try:
        asyncio.run(run_one(store))
    finally:
        store.engine.dispose()
