from pathlib import Path

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .access import filter_scan_jobs_for_user, filter_scan_results_for_user
from .forms import ScanUploadForm
from .models import ScanFile, ScanJob, ScanResult
from .services.analysis_pipeline import persist_uploaded_file
from .services.reporting import build_scan_report
from .tasks import schedule_scan_job


def get_recent_scans(user, limit=5):
    recent_results = ScanResult.objects.select_related("scan_file").order_by("-scanned_at")
    return filter_scan_results_for_user(recent_results, user)[:limit]


def build_scan_home_context(form, user, scan_file=None, result=None, scan_job=None):
    return {
        "form": form,
        "scan_file": scan_file,
        "result": result,
        "scan_job": scan_job,
        "recent_scans": get_recent_scans(user),
    }


def get_scan_result_or_none(scan_file):
    if not scan_file:
        return None
    return getattr(scan_file, "scanresult", None)


@login_required
def scan_home(request):
    if request.method == "POST":
        form = ScanUploadForm(request.POST, request.FILES)

        if form.is_valid():
            uploaded_file = form.cleaned_data["file"]
            scan_file = persist_uploaded_file(uploaded_file, uploaded_by=request.user)
            scan_job = ScanJob.objects.create(scan_file=scan_file)
            schedule_scan_job(scan_job.id)
            scan_job.refresh_from_db()
            result = get_scan_result_or_none(scan_file)

            context = build_scan_home_context(
                ScanUploadForm(),
                request.user,
                scan_file=scan_file,
                result=result,
                scan_job=scan_job,
            )

            if request.headers.get("HX-Request"):
                return render(request, "scanner/partials/scan_submit_response.html", context)

            return render(request, "scanner/scan_home.html", context)

        context = build_scan_home_context(form, request.user)

        if request.headers.get("HX-Request"):
            return render(request, "scanner/partials/scan_submit_response.html", context)

        return render(request, "scanner/scan_home.html", context)

    else:
        form = ScanUploadForm()

    context = build_scan_home_context(form, request.user)
    return render(request, "scanner/scan_home.html", context)


@login_required
def scan_result(request, scan_file_id):
    scan_file = get_object_or_404(
        filter_scan_results_for_user(
            ScanResult.objects.select_related("scan_file"),
            request.user,
        ),
        scan_file_id=scan_file_id,
    ).scan_file
    result = scan_file.scanresult

    context = {
        "scan_file": scan_file,
        "result": result,
    }
    return render(request, "scanner/scan_result.html", context)


@login_required
def scan_job_status(request, scan_job_public_id):
    scan_job = get_object_or_404(
        filter_scan_jobs_for_user(
            ScanJob.objects.select_related("scan_file"),
            request.user,
        ),
        public_id=scan_job_public_id,
    )
    result = get_scan_result_or_none(scan_job.scan_file)
    context = build_scan_home_context(
        ScanUploadForm(),
        request.user,
        scan_file=scan_job.scan_file,
        result=result,
        scan_job=scan_job,
    )

    if scan_job.status == ScanJob.Status.COMPLETED and result:
        return render(request, "scanner/partials/scan_submit_response.html", context)

    return render(request, "scanner/partials/scan_job_status_card.html", context)


def dashboard_redirect(request):
    return redirect("dashboard")


@login_required
def scan_history(request):
    results = filter_scan_results_for_user(
        ScanResult.objects.select_related("scan_file"),
        request.user,
    ).order_by("-scanned_at")

    context = {
        "results": results
    }

    return render(request, "scanner/history.html", context)


@login_required
def scan_result_report(request, scan_file_id):
    result = get_object_or_404(
        filter_scan_results_for_user(
            ScanResult.objects.select_related(
                "scan_file",
                "scan_file__uploaded_by",
                "scan_file__scan_job",
                "source_result",
            ),
            request.user,
        ),
        scan_file_id=scan_file_id,
    )
    report = build_scan_report(result.scan_file, result, request=request)
    filename = f"{Path(result.scan_file.filename).stem or 'scan'}-report.json"
    response = JsonResponse(report)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
