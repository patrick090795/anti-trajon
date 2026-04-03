from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from scanner.models import ScanResult


@login_required
def dashboard(request):
    total_scans = ScanResult.objects.count()
    high_risk = ScanResult.objects.filter(risk_level="High").count()
    medium_risk = ScanResult.objects.filter(risk_level="Medium").count()
    low_risk = ScanResult.objects.filter(risk_level="Low").count()

    recent_results = ScanResult.objects.select_related("scan_file").order_by("-scanned_at")[:10]
    yara_hits = (
        ScanResult.objects.exclude(yara_matches="")
        .select_related("scan_file")
        .order_by("-scanned_at")[:10]
    )

    context = {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "recent_results": recent_results,
        "yara_hits": yara_hits,
    }
    return render(request, "scanner/dashboard.html", context)


