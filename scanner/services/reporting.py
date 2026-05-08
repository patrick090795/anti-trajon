from django.urls import reverse
from django.utils import timezone


def build_scan_report(scan_file, result, request=None):
    source_result = result.source_result
    include_source_ids = bool(request and request.user.is_staff)
    result_path = reverse("scan_result", args=[scan_file.id])
    report_path = reverse("scan_result_report", args=[scan_file.id])

    api_result_path = reverse("api_scan_result_detail", args=[scan_file.id])
    api_job_path = ""
    if hasattr(scan_file, "scan_job"):
        api_job_path = reverse("api_scan_job_detail", args=[scan_file.scan_job.public_id])

    def build_absolute(path):
        if request is None:
            return path
        return request.build_absolute_uri(path)

    return {
        "generated_at": timezone.now().isoformat(),
        "file": {
            "id": scan_file.id,
            "filename": scan_file.filename,
            "sha256": scan_file.sha256,
            "content_type": scan_file.content_type,
            "uploaded_at": scan_file.uploaded_at.isoformat(),
            "uploaded_by": getattr(scan_file.uploaded_by, "username", None),
        },
        "job": {
            "public_id": str(scan_file.scan_job.public_id) if hasattr(scan_file, "scan_job") else None,
            "status": scan_file.scan_job.status if hasattr(scan_file, "scan_job") else None,
            "requested_at": scan_file.scan_job.requested_at.isoformat() if hasattr(scan_file, "scan_job") else None,
            "started_at": scan_file.scan_job.started_at.isoformat() if hasattr(scan_file, "scan_job") and scan_file.scan_job.started_at else None,
            "completed_at": scan_file.scan_job.completed_at.isoformat() if hasattr(scan_file, "scan_job") and scan_file.scan_job.completed_at else None,
            "error_message": scan_file.scan_job.error_message if hasattr(scan_file, "scan_job") else "",
        },
        "analysis": {
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "entropy": result.entropy,
            "file_size": result.file_size,
            "file_extension": result.file_extension,
            "file_type": result.file_type,
            "content_type": result.content_type,
            "is_executable": result.is_executable,
            "contains_embedded_urls": result.contains_embedded_urls,
            "contains_base64_strings": result.contains_base64_strings,
            "suspicious_string_count": result.suspicious_string_count,
            "suspicious_api_count": result.suspicious_api_count,
            "yara_match_count": result.yara_match_count,
            "yara_available": result.yara_available,
            "scan_duration_ms": result.scan_duration_ms,
            "analysis_version": result.analysis_version,
            "suspicious_strings": result.suspicious_strings,
            "suspicious_apis": result.suspicious_apis,
            "yara_matches": result.yara_matches,
            "explanation": result.explanation,
            "reused_existing_analysis": result.reused_existing_analysis,
            "source_result_id": source_result.id if include_source_ids and source_result else None,
            "source_scan_file_id": source_result.scan_file_id if include_source_ids and source_result else None,
            "scanned_at": result.scanned_at.isoformat(),
        },
        "links": {
            "result": build_absolute(result_path),
            "report": build_absolute(report_path),
            "api_result": build_absolute(api_result_path),
            "api_job": build_absolute(api_job_path) if api_job_path else None,
        },
    }
