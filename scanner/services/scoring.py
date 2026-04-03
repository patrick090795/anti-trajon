from .heuristics import evaluate_heuristics

ANALYSIS_VERSION = "2026.03"


def determine_risk_level(score):
    if score > 60:
        return "High"
    if score > 25:
        return "Medium"
    return "Low"


def build_explanation(features, suspicious_strings, suspicious_apis, yara_matches, findings):
    heuristic_summary = ", ".join(finding["detail"] for finding in findings) if findings else "No heuristic rules triggered."

    return f"""Entropy: {features['entropy']:.2f}
File size: {features['file_size']} bytes
Extension: {features['extension']}
File type: {features.get('file_type', 'Unknown')}
Content type: {features.get('content_type') or 'Unknown'}
Executable-like: {'Yes' if features.get('is_executable') else 'No'}
Embedded URLs: {'Yes' if features.get('contains_embedded_urls') else 'No'}
Base64-like strings: {'Yes' if features.get('contains_base64_strings') else 'No'}
Suspicious strings: {', '.join(suspicious_strings) if suspicious_strings else 'None'}
Suspicious APIs: {', '.join(suspicious_apis) if suspicious_apis else 'None'}
YARA matches: {', '.join(yara_matches) if yara_matches else 'None'}
Heuristics triggered: {heuristic_summary}"""


def build_scan_result_data(features, suspicious_strings, suspicious_apis, yara_matches, yara_available=True, scan_duration_ms=0):
    findings = evaluate_heuristics(
        features,
        suspicious_strings,
        suspicious_apis,
        yara_matches,
    )
    score = sum(finding["score"] for finding in findings)
    risk_level = determine_risk_level(score)

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "entropy": features["entropy"],
        "file_size": features["file_size"],
        "file_extension": features["extension"],
        "file_type": features.get("file_type", ""),
        "content_type": features.get("content_type", ""),
        "is_executable": features.get("is_executable", False),
        "contains_embedded_urls": features.get("contains_embedded_urls", False),
        "contains_base64_strings": features.get("contains_base64_strings", False),
        "suspicious_string_count": len(suspicious_strings),
        "suspicious_api_count": len(suspicious_apis),
        "yara_match_count": len(yara_matches),
        "yara_available": yara_available,
        "scan_duration_ms": scan_duration_ms,
        "analysis_version": ANALYSIS_VERSION,
        "suspicious_strings": ", ".join(suspicious_strings),
        "suspicious_apis": ", ".join(suspicious_apis),
        "yara_matches": ", ".join(yara_matches),
        "explanation": build_explanation(
            features,
            suspicious_strings,
            suspicious_apis,
            yara_matches,
            findings,
        ),
    }
