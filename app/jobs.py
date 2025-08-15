from concurrent.futures import ThreadPoolExecutor
import os, threading
from apscheduler.schedulers.background import BackgroundScheduler

class JobManager:
    def __init__(self, max_workers=None):
        max_workers = max_workers or int(os.environ.get("PARALLELISM", "4"))
        self.pool = ThreadPoolExecutor(max_workers=max_workers)
        self.lock = threading.Lock()
        self.bulk_futures = {}
        self.scheduler = BackgroundScheduler(timezone=os.environ.get("TZ","UTC"))
        self.scheduler.start()

    def submit(self, fn, *args, **kwargs):
        return self.pool.submit(fn, *args, **kwargs)

    def submit_bulk(self, bulk_job_id, futures):
        with self.lock:
            self.bulk_futures[bulk_job_id] = futures

    def progress(self, bulk_job_id):
        with self.lock:
            futs = self.bulk_futures.get(bulk_job_id, [])
        total = len(futs)
        done = sum(1 for f in futs if f.done())
        percent = (done*100 // total) if total else 0
        return {"total": total, "done": done, "percent": percent}

    def schedule_cron(self, job_id, func, **cron):
        self.scheduler.add_job(func, "cron", id=job_id, replace_existing=True, **cron)

    def schedule_interval(self, job_id, func, seconds:int):
        self.scheduler.add_job(func, "interval", id=job_id, seconds=seconds, replace_existing=True)

    def start(self):
        return self

job_manager = JobManager()
