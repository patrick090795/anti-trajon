from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.db import close_old_connections
from django.utils import timezone

from scanner.models import ScanJob
from scanner.services.analysis_pipeline import run_scan_for_scan_file

executor = ThreadPoolExecutor(max_workers=2)


def schedule_scan_job(scan_job_id):
    if getattr(settings, "SCAN_EAGER_JOBS", False):
        process_scan_job(scan_job_id)
        return

    executor.submit(process_scan_job, scan_job_id)


def process_scan_job(scan_job_id):
    close_old_connections()

    try:
        scan_job = ScanJob.objects.select_related("scan_file").get(id=scan_job_id)

        if scan_job.status in {ScanJob.Status.COMPLETED, ScanJob.Status.FAILED}:
            return

        scan_job.status = ScanJob.Status.RUNNING
        scan_job.started_at = timezone.now()
        scan_job.error_message = ""
        scan_job.save(update_fields=["status", "started_at", "error_message", "updated_at"])

        run_scan_for_scan_file(scan_job.scan_file)

        scan_job.status = ScanJob.Status.COMPLETED
        scan_job.completed_at = timezone.now()
        scan_job.save(update_fields=["status", "completed_at", "updated_at"])
    except Exception as exc:
        ScanJob.objects.filter(id=scan_job_id).update(
            status=ScanJob.Status.FAILED,
            error_message=str(exc),
            completed_at=timezone.now(),
        )
    finally:
        close_old_connections()
