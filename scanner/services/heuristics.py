HIGH_ENTROPY_THRESHOLD = 7.2


def evaluate_heuristics(features, suspicious_strings, suspicious_apis, yara_matches):
    findings = []

    if features["entropy"] > HIGH_ENTROPY_THRESHOLD:
        findings.append(
            {
                "name": "high_entropy",
                "score": 30,
                "detail": f"Entropy {features['entropy']:.2f} exceeds {HIGH_ENTROPY_THRESHOLD:.1f}.",
            }
        )

    if suspicious_strings:
        findings.append(
            {
                "name": "suspicious_strings",
                "score": 20,
                "detail": f"Matched {len(suspicious_strings)} suspicious string indicators.",
            }
        )

    if suspicious_apis:
        findings.append(
            {
                "name": "suspicious_apis",
                "score": 40,
                "detail": f"Matched {len(suspicious_apis)} suspicious API imports.",
            }
        )

    if yara_matches:
        findings.append(
            {
                "name": "yara_hits",
                "score": 35,
                "detail": f"Triggered {len(yara_matches)} YARA rule matches.",
            }
        )

    if features.get("contains_embedded_urls"):
        findings.append(
            {
                "name": "embedded_urls",
                "score": 10,
                "detail": "Embedded URLs were detected in the file content.",
            }
        )

    if features.get("contains_base64_strings"):
        findings.append(
            {
                "name": "base64_blob",
                "score": 15,
                "detail": "Long base64-like strings were detected.",
            }
        )

    return findings
