import hashlib
import time

from scanner.models import ScanFile, ScanResult
from scanner.services.scoring import build_scan_result_data
from scanner.services.static_analysis import analyze_pe_imports
from scanner.services.static_analysis import detect_suspicious_strings, extract_basic_features
from scanner.services.yara_engine import get_yara_scan_report


def calculate_sha256(uploaded_file):
    sha256_hash = hashlib.sha256()

    for chunk in uploaded_file.chunks():
        sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def persist_uploaded_file(uploaded_file):
    file_hash = calculate_sha256(uploaded_file)
    uploaded_file.seek(0)

    return ScanFile.objects.create(
        file=uploaded_file,
        filename=uploaded_file.name,
        content_type=(uploaded_file.content_type or "").split(";", 1)[0].strip().lower(),
        sha256=file_hash,
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


def run_scan_for_scan_file(scan_file):
    started_at = time.perf_counter()
    analysis_data = collect_analysis(scan_file.file.path, content_type=scan_file.content_type)
    analysis_data["scan_duration_ms"] = int((time.perf_counter() - started_at) * 1000)
    return create_scan_result(scan_file, analysis_data)


def run_scan_pipeline(uploaded_file):
    scan_file = persist_uploaded_file(uploaded_file)
    result = run_scan_for_scan_file(scan_file)

    return scan_file, result
