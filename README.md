# Anti-Trojan Tool

Anti-Trojan Tool is a Django-based static file analysis prototype for triaging potentially suspicious files. It lets you upload a file, inspect basic metadata and indicators, persist the result, and review aggregate scan activity in a small dashboard.

## What it does

- Calculates a SHA-256 hash for each uploaded file
- Extracts static metadata such as file size, extension, and entropy
- Searches for suspicious strings often associated with downloaders or process injection
- Inspects PE imports for suspicious APIs
- Runs YARA rules from `scanner/rules/trojan_rules.yar`
- Scores the file using heuristic rules and stores the result in SQLite
- Reuses prior analysis for duplicate SHA-256 uploads to avoid rescanning the same file
- Shows recent scans, full scan history, dashboard summaries, and downloadable JSON reports
- Exposes authenticated API endpoints for scan submission and result retrieval

## Project layout

- `core/`: Django project settings and top-level URL routing
- `scanner/`: upload flow, scan result pages, models, forms, services, and templates
- `dashboard/`: dashboard route and summary view
- `docs/`: architecture and roadmap notes
- `media/uploads/`: uploaded files stored by Django during development
- `test_samples/`: local sample files for exercising the scanner manually

## Main routes

- `/`: redirects to the scanner landing page
- `/scanner/`: upload and scan workflow
- `/scanner/history/`: full scan history
- `/scanner/result/<scan_file_id>/report.json`: downloadable JSON report for a completed scan
- `/scanner/api/scans/`: authenticated API endpoint for scan submission
- `/scanner/api/jobs/<public_id>/`: authenticated API endpoint for job status
- `/scanner/api/results/`: authenticated API endpoint for recent results
- `/dashboard/`: aggregate scan dashboard
- `/admin/`: Django admin

## Core scanning pipeline

1. The user uploads a file from the scanner page.
2. The app stores the file, computes its SHA-256 hash, and creates a queued `ScanJob`.
3. If the same SHA-256 was already analyzed, the app reuses the prior result immediately.
4. Otherwise a worker processes the queued job, runs the static analyzers, and produces a `ScanResult`.
5. The result is rendered in the scanner UI, exposed through authenticated API endpoints, and available as a JSON report.

## Local development

### Requirements

- Python 3.14 or another supported Python 3 release
- Django
- djangorestframework
- pefile
- yara-python

### Setup

1. Create and activate a virtual environment.
2. Install dependencies.
3. Run database migrations.
4. Start a scan worker.
5. Start the Django dev server.

Example commands:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install django djangorestframework pefile yara-python
python manage.py migrate
python manage.py run_scan_worker
python manage.py runserver
```

## Verification

Run the built-in checks and tests with:

```powershell
python manage.py check
python manage.py test
```

## Current limitations

- The scanner is static-analysis only and does not execute samples in a sandbox
- Risk scoring is intentionally simple and heuristic-driven
- The default worker uses database polling instead of a dedicated background queue service
- The ML service is still a placeholder
