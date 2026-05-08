from django.conf import settings
from django.db import close_old_connections
from django.db import IntegrityError
from django.db import transaction
from django.utils import timezone

from scanner.models import ScanJob, ScanResult
from scanner.services.analysis_pipeline import get_existing_result_for_hash, reuse_existing_result, run_scan_for_scan_file


def schedule_scan_job(scan_job_id):
    if getattr(settings, "SCAN_EAGER_JOBS", False):
        process_scan_job(scan_job_id)
        return

    try_complete_scan_job_from_existing_result(scan_job_id)


def claim_scan_job(scan_job_id=None):
    now = timezone.now()

    with transaction.atomic():
        queued_jobs = ScanJob.objects.filter(status=ScanJob.Status.QUEUED).order_by("requested_at", "id")
        if scan_job_id is not None:
            queued_jobs = queued_jobs.filter(id=scan_job_id)

        queued_job = queued_jobs.first()
        if not queued_job:
            return None

        claimed_count = ScanJob.objects.filter(
            id=queued_job.id,
            status=ScanJob.Status.QUEUED,
        ).update(
            status=ScanJob.Status.RUNNING,
            started_at=now,
            error_message="",
            updated_at=now,
        )

        if claimed_count != 1:
            return None

    return ScanJob.objects.select_related("scan_file").get(id=queued_job.id)


def try_complete_scan_job_from_existing_result(scan_job_id):
    close_old_connections()
    claimed_job = False

    try:
        scan_job = ScanJob.objects.select_related("scan_file").get(id=scan_job_id)
        if scan_job.status != ScanJob.Status.QUEUED:
            return False

        source_result = get_existing_result_for_hash(scan_job.scan_file)
        if not source_result:
            return False

        started_at = timezone.now()
        claimed_count = ScanJob.objects.filter(
            id=scan_job.id,
            status=ScanJob.Status.QUEUED,
        ).update(
            status=ScanJob.Status.RUNNING,
            started_at=started_at,
            error_message="",
            updated_at=started_at,
        )

        if claimed_count != 1:
            return False

        claimed_job = True

        try:
            reuse_existing_result(scan_job.scan_file, source_result)
        except IntegrityError:
            if not ScanResult.objects.filter(scan_file=scan_job.scan_file).exists():
                raise

        completed_at = timezone.now()
        ScanJob.objects.filter(id=scan_job.id, status=ScanJob.Status.RUNNING).update(
            status=ScanJob.Status.COMPLETED,
            completed_at=completed_at,
            error_message="",
            updated_at=completed_at,
        )
        return True
    except Exception as exc:
        if claimed_job:
            failed_at = timezone.now()
            ScanJob.objects.filter(id=scan_job_id, status=ScanJob.Status.RUNNING).update(
                status=ScanJob.Status.FAILED,
                error_message=str(exc),
                completed_at=failed_at,
                updated_at=failed_at,
            )
            return False
        raise
    finally:
        close_old_connections()


def process_scan_job(scan_job_id):
    close_old_connections()

    try:
        scan_job = claim_scan_job(scan_job_id)
        if not scan_job:
            return False

        run_scan_for_scan_file(scan_job.scan_file)

        scan_job.status = ScanJob.Status.COMPLETED
        scan_job.completed_at = timezone.now()
        scan_job.save(update_fields=["status", "completed_at", "updated_at"])
        return True
    except Exception as exc:
        ScanJob.objects.filter(id=scan_job_id).update(
            status=ScanJob.Status.FAILED,
            error_message=str(exc),
            completed_at=timezone.now(),
        )
        return False
    finally:
        close_old_connections()


def process_pending_scan_jobs(limit=None):
    processed_jobs = 0

    while limit is None or processed_jobs < limit:
        next_job_id = (
            ScanJob.objects.filter(status=ScanJob.Status.QUEUED)
            .order_by("requested_at", "id")
            .values_list("id", flat=True)
            .first()
        )
        if not next_job_id:
            break

        if process_scan_job(next_job_id):
            processed_jobs += 1

    return processed_jobs
