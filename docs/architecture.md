# Architecture

## Overview

The project is a small Django application organized around two user-facing areas:

- `scanner`: file upload, analysis, result display, and scan history
- `dashboard`: aggregate reporting over stored scan results

SQLite is used as the default persistence layer, and uploaded files are stored under `media/uploads/` during development.

## Request flow

1. `core/urls.py` routes `/` to the scanner landing page and mounts the `scanner` and `dashboard` apps.
2. `scanner.views.scan_home` accepts uploads, stores the file, and triggers analysis services.
3. Static analysis services collect features:
   - `static_analysis.py` extracts entropy, file size, extension, suspicious strings, and suspicious PE imports.
   - `yara_engine.py` compiles and evaluates YARA rules.
4. `heuristics.py` converts raw signals into weighted findings.
5. `scoring.py` aggregates findings into a risk score, a risk level, and a persisted result payload.
6. `ScanResult` records are rendered in scanner result pages, history, and dashboard views.

## Core components

### Routing

- `core/urls.py`: top-level routing and media serving in development
- `scanner/urls.py`: scanner home, scan result detail, legacy dashboard redirect, and history page
- `dashboard/urls.py`: dashboard landing route

### Models

- `ScanFile`: uploaded file metadata and SHA-256 hash
- `ScanResult`: persisted analysis data, risk score, risk level, explanation, and timestamps

### Services

- `scanner/services/static_analysis.py`
  - Entropy calculation
  - Basic file feature extraction
  - Suspicious string matching
  - Suspicious PE import inspection
- `scanner/services/yara_engine.py`
  - Rule path resolution
  - YARA compilation and matching
- `scanner/services/heuristics.py`
  - Weighted heuristic findings based on extracted signals
- `scanner/services/scoring.py`
  - Risk level calculation
  - Explanation generation
  - Scan result payload assembly
- `scanner/services/ml_detector.py`
  - Placeholder for future model-based analysis

### Templates

- `scanner/templates/scanner/base.html`: shared application shell
- `scanner/templates/scanner/scan_home.html`: scanner landing and upload UI
- `scanner/templates/scanner/scan_result.html`: detailed result page
- `scanner/templates/scanner/history.html`: full scan history
- `scanner/templates/scanner/dashboard.html`: aggregate dashboard

## Data flow

The data flow is intentionally straightforward:

- raw file upload -> `ScanFile`
- analyzer outputs -> heuristic findings
- heuristic findings -> `ScanResult`
- `ScanResult` -> templates and dashboard statistics

This keeps the current implementation easy to reason about while preserving extension points for more advanced detectors.

## Extension points

- Add new static detectors in `static_analysis.py`
- Add or adjust weighted rules in `heuristics.py`
- Change score thresholds or explanation output in `scoring.py`
- Add asynchronous execution with Celery or Django-Q if scans become slow
- Replace or augment heuristic scoring with `ml_detector.py`

## Known architectural constraints

- Scans currently run synchronously in the request/response cycle
- YARA rules are compiled on each scan request instead of being cached
- The dashboard reads directly from the primary scan tables
- There is no isolation layer between uploaded content and the app host beyond static inspection
