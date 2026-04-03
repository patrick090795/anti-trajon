# Threat Model

## Purpose

This document describes the main security risks for Anti-Trojan Tool as it exists today: a Django application that accepts untrusted file uploads, performs static analysis, stores scan results, and exposes those results through scanner, history, dashboard, and admin interfaces.

The goal is not to claim the system is hardened. The goal is to make the current trust boundaries, likely attacker behavior, and highest-value mitigations explicit so future work can be prioritized well.

## Scope

In scope:

- File upload and storage
- Static analysis services
- Result persistence in SQLite
- Dashboard, history, and admin access paths
- Development-style deployment assumptions reflected in the current codebase

Out of scope for now:

- Dynamic malware execution or sandbox detonation
- Multi-tenant production infrastructure
- Network-based threat intelligence integrations
- Full incident response or forensics workflows

## System summary

The application currently:

- Accepts a file upload from the scanner page
- Stores the file under `media/uploads/`
- Computes SHA-256 and static features
- Scans file contents for suspicious strings and PE imports
- Evaluates YARA rules
- Produces a heuristic risk score and risk level
- Stores the result in `ScanFile` and `ScanResult`

This means the app directly handles attacker-controlled files and passes them through local parsing libraries such as `pefile` and `yara-python`.

## Security assumptions

- The application is currently a prototype and may run in a trusted development environment
- Uploaded files are untrusted and may be intentionally malicious
- Users may submit malformed, oversized, or evasive samples
- The host running the app is more valuable than the uploaded samples
- Static analysis reduces risk compared to execution, but it does not eliminate parser abuse or resource exhaustion risks

## Assets to protect

Primary assets:

- Host machine running Django and analysis libraries
- Uploaded files and their storage location
- Scan results, hashes, and analysis summaries
- YARA rules and scoring logic
- Django admin surface and underlying database

Secondary assets:

- Availability of the scanner service
- Integrity of dashboard/history data
- Confidentiality of submitted files and scan output

## Actors

### Legitimate user

- Uploads files to inspect them
- Views results and history
- Expects the app to remain responsive and accurate enough for triage

### Malicious submitter

- Uploads files designed to exhaust CPU, memory, or disk
- Attempts to exploit file parsers or analysis libraries
- May try to poison stored results or hide malicious intent

### Operator or administrator

- Runs the app, manages the host, and may access Django admin
- Needs safe defaults, visibility into failures, and bounded operational risk

## Entry points

- `/scanner/` upload form
- `/scanner/history/` history page
- `/dashboard/` dashboard page
- `/admin/` Django admin
- Local filesystem storage under `media/uploads/`
- Parsing paths through `pefile` and `yara-python`

## Trust boundaries

### Browser -> Django application

User input, including uploaded files and form submissions, crosses from an untrusted client into the web application.

### Django application -> filesystem

The app stores attacker-controlled content on disk. This introduces persistence, disk consumption, and exposure risks.

### Django application -> analysis libraries

The app passes untrusted bytes to `pefile` and YARA. Even without execution, parser-level bugs, hangs, or excessive memory use remain possible.

### Django application -> database

Analysis output becomes trusted application data once persisted. Poor validation or unsafe rendering could turn malicious input into stored-content issues.

## Primary threats

## 1. Malicious file upload causes parser abuse or host compromise

Description:
An attacker uploads a malformed or specially crafted file intended to trigger a vulnerability in a parsing library or consume excessive resources during analysis.

Why it matters:
This is the highest-risk area because the app is explicitly built to accept attacker-controlled files.

Current mitigations:

- The app performs static analysis only and does not execute files
- `analyze_pe_imports` catches exceptions when PE parsing fails
- YARA failures are caught and converted to empty matches

Gaps:

- No upload size limit is enforced
- No timeout or worker isolation exists for heavy scans
- Parsers run in the main web process
- Uploaded files are stored on the same host as the app

Recommended mitigations:

- Enforce maximum upload size and reject oversized files early
- Run scans asynchronously and outside the web request path
- Isolate analysis workers from the main app host
- Consider scanning in a separate container or VM

## 2. Resource exhaustion through repeated or oversized uploads

Description:
An attacker submits many files or very large files to consume disk, memory, CPU, or database space.

Impact:
Availability loss and increased operator cost. In a small prototype, this can also break the host environment quickly.

Current mitigations:

- None that materially limit abuse today

Gaps:

- No rate limiting
- No file count or storage quota
- No background queue with backpressure
- Uploaded files and results are retained indefinitely

Recommended mitigations:

- Add file size limits and request throttling
- Add storage retention or cleanup policies
- Move scans to a queue with concurrency limits
- Add monitoring for disk usage and scan duration

## 3. Unauthorized access to uploaded samples or scan results

Description:
Anyone with access to the app, filesystem, or admin surface may be able to view sensitive uploaded content or derived results.

Impact:
Confidentiality loss. Samples may contain proprietary or sensitive material in addition to malicious content.

Current mitigations:

- Django admin exists, but broader access control is not yet implemented

Gaps:

- No user authentication for scanner, history, or dashboard views
- Development media serving is enabled
- No per-user or per-role separation

Recommended mitigations:

- Add authentication before exposing the app beyond local development
- Restrict dashboard, history, and admin access by role
- Treat uploaded files and scan results as sensitive by default
- Review media serving strategy for production use

## 4. Stored content risks through rendered filenames or analysis strings

Description:
User-controlled file names and extracted strings may be saved and later rendered in templates or admin pages.

Impact:
Potential cross-site scripting or UI corruption if output escaping is bypassed in the future.

Current mitigations:

- Django templates escape output by default
- Explanations are rendered as text, not HTML

Gaps:

- Future template changes could accidentally mark content as safe
- Admin customizations may introduce unsafe rendering

Recommended mitigations:

- Keep autoescaping enabled everywhere by default
- Never mark uploaded names or extracted content as safe HTML
- Add tests for rendering of hostile filenames and strings

## 5. False negatives and analyst over-trust

Description:
A malicious file may score low because the current heuristics are intentionally simple and limited in coverage.

Impact:
Users may treat low-risk results as proof of safety, leading to bad operational decisions.

Current mitigations:

- The app presents itself as a static analysis tool rather than a full malware verdict engine

Gaps:

- No explicit disclaimer in the UI that low risk does not mean benign
- Limited detector coverage and small YARA rule set

Recommended mitigations:

- Add UI language clarifying that results are triage signals, not guarantees
- Expand YARA and heuristic coverage
- Add confidence notes and analyst-facing caveats

## 6. Integrity issues in stored scan data

Description:
An attacker or bug could lead to incorrect, duplicated, or misleading stored results, especially if the same sample is uploaded repeatedly.

Impact:
Dashboard accuracy degrades and analysts may make decisions on low-quality data.

Current mitigations:

- SHA-256 is calculated for each file

Gaps:

- No deduplication on identical hashes
- No audit trail for rescans or rule changes
- No versioning for scoring logic or YARA rule revisions

Recommended mitigations:

- Reuse or compare prior results by hash
- Store rule/scoring version metadata with each result
- Log scan failures and partial-analysis cases clearly

## Threat ranking

Highest priority:

- Parser abuse from malicious uploads
- Resource exhaustion
- Unauthorized access to samples and scan data

Medium priority:

- Stored-content rendering risks
- Integrity drift in stored results

Ongoing analytical risk:

- False negatives and analyst over-trust

## Current controls

- Static analysis only; no sample execution
- Exception handling around PE parsing and YARA matching
- Django template autoescaping
- SHA-256 hashing for uploaded files
- Basic automated tests for routes, persistence, and scoring

## Security gaps to address next

1. Add upload size limits and validation
2. Move scans out of the synchronous request path
3. Isolate analysis from the main web process
4. Add authentication and authorization
5. Add retention, quota, and cleanup controls for uploaded files
6. Add tests for hostile filenames, malformed files, and parser failure paths
7. Cache YARA rules or control compilation cost

## Recommended engineering follow-up

Based on this threat model, the most useful next implementation steps are:

1. Add file size validation and safer upload handling
2. Introduce a scan orchestration service plus background execution
3. Add authentication before broader deployment
4. Expand test coverage for failure and abuse cases
5. Add operational visibility such as logging, metrics, and scan error reporting

## Residual risk statement

Even after near-term hardening, this project should be treated as a triage-oriented static analysis tool, not a fully isolated malware analysis platform. If the system is expected to process adversarial samples at higher volume or with stronger safety guarantees, the analysis workload should be separated from the main application host and run inside stronger isolation boundaries.
