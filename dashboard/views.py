from collections import Counter

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from scanner.access import filter_scan_results_for_user
from scanner.models import ScanResult


@login_required
def dashboard(request):
    visible_results = filter_scan_results_for_user(
        ScanResult.objects.select_related("scan_file"),
        request.user,
    )

    total_scans = visible_results.count()
    high_risk = visible_results.filter(risk_level="High").count()
    medium_risk = visible_results.filter(risk_level="Medium").count()
    low_risk = visible_results.filter(risk_level="Low").count()

    recent_results = visible_results.order_by("-scanned_at")[:10]
    yara_hits = (
        visible_results.exclude(yara_matches="")
        .order_by("-scanned_at")[:10]
    )
    top_extensions = visible_results.exclude(file_extension="").values("file_extension").order_by("file_extension")
    extension_counts = Counter(item["file_extension"] for item in top_extensions)
    common_indicators = Counter()

    for result in visible_results.exclude(suspicious_strings=""):
        common_indicators.update(
            indicator.strip()
            for indicator in result.suspicious_strings.split(",")
            if indicator.strip()
        )

    context = {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "recent_results": recent_results,
        "yara_hits": yara_hits,
        "top_extensions": extension_counts.most_common(5),
        "common_indicators": common_indicators.most_common(5),
    }
    return render(request, "scanner/dashboard.html", context)


