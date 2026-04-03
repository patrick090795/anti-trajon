from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .forms import ScanUploadForm
from .models import ScanFile, ScanJob, ScanResult
from .services.analysis_pipeline import persist_uploaded_file
from .tasks import schedule_scan_job


def get_recent_scans(limit=5):
    return ScanResult.objects.select_related("scan_file").order_by("-scanned_at")[:limit]


def build_scan_home_context(form, scan_file=None, result=None, scan_job=None):
    return {
        "form": form,
        "scan_file": scan_file,
        "result": result,
        "scan_job": scan_job,
        "recent_scans": get_recent_scans(),
    }


def get_scan_result_or_none(scan_file):
    if not scan_file:
        return None
    return getattr(scan_file, "scanresult", None)


def scan_home(request):
    if request.method == "POST":
        form = ScanUploadForm(request.POST, request.FILES)

        if form.is_valid():
            uploaded_file = form.cleaned_data["file"]
            scan_file = persist_uploaded_file(uploaded_file)
            scan_job = ScanJob.objects.create(scan_file=scan_file)
            schedule_scan_job(scan_job.id)
            scan_job.refresh_from_db()
            result = get_scan_result_or_none(scan_file)

            context = build_scan_home_context(
                ScanUploadForm(),
                scan_file=scan_file,
                result=result,
                scan_job=scan_job,
            )

            if request.headers.get("HX-Request"):
                return render(request, "scanner/partials/scan_submit_response.html", context)

            return render(request, "scanner/scan_home.html", context)

        context = build_scan_home_context(form)

        if request.headers.get("HX-Request"):
            return render(request, "scanner/partials/scan_submit_response.html", context)

        return render(request, "scanner/scan_home.html", context)

    else:
        form = ScanUploadForm()

    context = build_scan_home_context(form)
    return render(request, "scanner/scan_home.html", context)


@login_required
def scan_result(request, scan_file_id):
    scan_file = get_object_or_404(ScanFile, id=scan_file_id)
    result = get_object_or_404(ScanResult, scan_file=scan_file)

    context = {
        "scan_file": scan_file,
        "result": result,
    }
    return render(request, "scanner/scan_result.html", context)


def scan_job_status(request, scan_job_public_id):
    scan_job = get_object_or_404(ScanJob.objects.select_related("scan_file"), public_id=scan_job_public_id)
    result = get_scan_result_or_none(scan_job.scan_file)
    context = build_scan_home_context(
        ScanUploadForm(),
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
    results = ScanResult.objects.select_related("scan_file").order_by("-scanned_at")

    context = {
        "results": results
    }

    return render(request, "scanner/history.html", context)
