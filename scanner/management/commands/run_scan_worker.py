import time

from django.conf import settings
from django.core.management.base import BaseCommand

from scanner.tasks import process_pending_scan_jobs


class Command(BaseCommand):
    help = "Process queued scan jobs from the database-backed worker queue."

    def add_arguments(self, parser):
        parser.add_argument(
            "--once",
            action="store_true",
            help="Process queued jobs once and then exit.",
        )
        parser.add_argument(
            "--poll-interval",
            type=float,
            default=settings.SCAN_WORKER_POLL_INTERVAL,
            help="Seconds to wait before polling for more queued jobs.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=settings.SCAN_WORKER_BATCH_SIZE,
            help="Maximum number of jobs to process per polling cycle.",
        )

    def handle(self, *args, **options):
        once = options["once"]
        poll_interval = max(options["poll_interval"], 0.1)
        batch_size = max(options["batch_size"], 1)

        self.stdout.write(self.style.SUCCESS("Scan worker started."))

        while True:
            processed_jobs = process_pending_scan_jobs(limit=batch_size)
            if processed_jobs:
                self.stdout.write(f"Processed {processed_jobs} queued scan job(s).")

            if once:
                break

            if processed_jobs == 0:
                time.sleep(poll_interval)

        self.stdout.write(self.style.SUCCESS("Scan worker stopped."))
