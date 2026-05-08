import hashlib
import time
from pathlib import Path

from django.db import IntegrityError

from scanner.models import ScanFile, ScanResult
from scanner.services.scoring import build_scan_result_data
from scanner.services.static_analysis import (
    EXECUTABLE_EXTENSIONS,
    analyze_pe_imports,
    detect_suspicious_strings,
    extract_basic_features,
    infer_file_type,
)
from scanner.services.yara_engine import get_yara_scan_report


def calculate_sha256(uploaded_file):
    sha256_hash = hashlib.sha256()

    for chunk in uploaded_file.chunks():
        sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def persist_uploaded_file(uploaded_file, uploaded_by=None):
    file_hash = calculate_sha256(uploaded_file)
    uploaded_file.seek(0)

    return ScanFile.objects.create(
        file=uploaded_file,
        filename=uploaded_file.name,
        content_type=(uploaded_file.content_type or "").split(";", 1)[0].strip().lower(),
        sha256=file_hash,
        uploaded_by=uploaded_by,
    )


def collect_analysis(filepath, content_type=""):
    features = extract_basic_features(filepath, content_type=content_type)
    suspicious_strings = detect_suspicious_strings(filepath)
    suspicious_apis = analyze_pe_imports(filepath)
    yara_report = get_yara_scan_report(filepath)

    return {
        "features": features,
        "suspicious_strings": suspicious_strings,
        "suspicious_apis": suspicious_apis,
        "yara_matches": yara_report["matches"],
        "yara_available": yara_report["available"],
    }


def create_scan_result(scan_file, analysis_data):
    result_data = build_scan_result_data(
        analysis_data["features"],
        analysis_data["suspicious_strings"],
        analysis_data["suspicious_apis"],
        analysis_data["yara_matches"],
        yara_available=analysis_data.get("yara_available", True),
        scan_duration_ms=analysis_data.get("scan_duration_ms", 0),
    )

    return ScanResult.objects.create(
        scan_file=scan_file,
        **result_data,
    )


def get_existing_result_for_scan_file(scan_file):
    return (
        ScanResult.objects.select_related("scan_file", "source_result")
        .filter(scan_file=scan_file)
        .first()
    )


def get_existing_result_for_hash(scan_file):
    reusable_results = (
        ScanResult.objects.select_related("scan_file", "source_result")
        .filter(scan_file__sha256=scan_file.sha256)
        .exclude(scan_file=scan_file)
    )
    if scan_file.uploaded_by_id:
        reusable_results = reusable_results.filter(scan_file__uploaded_by=scan_file.uploaded_by)
    else:
        reusable_results = reusable_results.filter(scan_file__uploaded_by__isnull=True)
    return reusable_results.order_by("-scanned_at").first()


def build_reused_submission_metadata(scan_file):
    extension = Path(scan_file.filename).suffix
    with scan_file.file.open("rb") as file_handle:
        header = file_handle.read(4)

    return {
        "file_extension": extension,
        "file_type": infer_file_type(extension, header),
        "content_type": scan_file.content_type,
        "is_executable": extension.lower() in EXECUTABLE_EXTENSIONS or header.startswith(b"MZ"),
    }


def reuse_existing_result(scan_file, source_result):
    existing_result = get_existing_result_for_scan_file(scan_file)
    if existing_result:
        return existing_result

    root_source_result = source_result.source_result or source_result
    submission_metadata = build_reused_submission_metadata(scan_file)
    reused_explanation = (
        "Result reused from a previous scan with the same SHA-256 hash. "
        "Static analysis was not rerun for this submission.\n\n"
        f"{source_result.explanation}"
    )

    try:
        return ScanResult.objects.create(
            scan_file=scan_file,
            source_result=root_source_result,
            reused_existing_analysis=True,
            risk_score=source_result.risk_score,
            risk_level=source_result.risk_level,
            entropy=source_result.entropy,
            file_size=source_result.file_size,
            file_extension=submission_metadata["file_extension"],
            file_type=submission_metadata["file_type"],
            content_type=submission_metadata["content_type"],
            is_executable=submission_metadata["is_executable"],
            contains_embedded_urls=source_result.contains_embedded_urls,
            contains_base64_strings=source_result.contains_base64_strings,
            suspicious_string_count=source_result.suspicious_string_count,
            suspicious_api_count=source_result.suspicious_api_count,
            yara_match_count=source_result.yara_match_count,
            yara_available=source_result.yara_available,
            scan_duration_ms=0,
            analysis_version=source_result.analysis_version,
            suspicious_strings=source_result.suspicious_strings,
            suspicious_apis=source_result.suspicious_apis,
            yara_matches=source_result.yara_matches,
            explanation=reused_explanation,
        )
    except IntegrityError:
        existing_result = get_existing_result_for_scan_file(scan_file)
        if existing_result:
            return existing_result
        raise


def run_scan_for_scan_file(scan_file):
    existing_current_result = get_existing_result_for_scan_file(scan_file)
    if existing_current_result:
        return existing_current_result

    existing_result = get_existing_result_for_hash(scan_file)
    if existing_result:
        return reuse_existing_result(scan_file, existing_result)

    started_at = time.perf_counter()
    analysis_data = collect_analysis(scan_file.file.path, content_type=scan_file.content_type)
    analysis_data["scan_duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    try:
        return create_scan_result(scan_file, analysis_data)
    except IntegrityError:
        existing_current_result = get_existing_result_for_scan_file(scan_file)
        if existing_current_result:
            return existing_current_result
        raise


def run_scan_pipeline(uploaded_file, uploaded_by=None):
    scan_file = persist_uploaded_file(uploaded_file, uploaded_by=uploaded_by)
    result = run_scan_for_scan_file(scan_file)

    return scan_file, result
