# Anti-Trojan Tool

Anti-Trojan Tool is a Django-based static file analysis prototype for triaging potentially suspicious files. It lets you upload a file, inspect basic metadata and indicators, persist the result, and review aggregate scan activity in a small dashboard.

## What it does

- Calculates a SHA-256 hash for each uploaded file
- Extracts static metadata such as file size, extension, and entropy
- Searches for suspicious strings often associated with downloaders or process injection
- Inspects PE imports for suspicious APIs
- Runs YARA rules from `scanner/rules/trojan_rules.yar`
- Scores the file using heuristic rules and stores the result in SQLite
- Shows recent scans, full scan history, and dashboard summaries

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
- `/dashboard/`: aggregate scan dashboard
- `/admin/`: Django admin

## Core scanning pipeline

1. The user uploads a file from the scanner page.
2. The app stores the file and computes its SHA-256 hash.
3. Static analyzers extract metadata, suspicious strings, PE imports, and YARA matches.
4. Heuristic rules convert those signals into a risk score and risk level.
5. The result is stored in `ScanResult` and rendered in the scanner, history, and dashboard views.

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
4. Start the Django dev server.

Example commands:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install django djangorestframework pefile yara-python
python manage.py migrate
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
- Scans run synchronously during the request cycle
- Authentication and per-user access controls are not implemented
- The ML service is still a placeholder
