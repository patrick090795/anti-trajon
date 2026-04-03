# Roadmap

## Current state

- Basic scanner workflow is working end to end
- Dashboard and scan history pages are live
- Static analysis covers entropy, suspicious strings, PE imports, and YARA
- Risk scoring has been moved into dedicated service modules
- Test coverage exists for core routes, persistence, and dashboard rendering

## Near-term priorities

- Expand automated test coverage around clean files, malformed files, and YARA failures
- Cache compiled YARA rules so repeated scans are cheaper
- Move the remaining scan orchestration out of `scanner.views` into a higher-level service
- Add clearer upload validation and error handling for unsupported files
- Fill in `docs/threat_model.md`

## Product improvements

- Add richer dashboard metrics such as top file types and most common triggered indicators
- Support scan filtering and search in history
- Add downloadable JSON reports for each scan
- Expose a small REST API for programmatic file submission and result lookup

## Detection improvements

- Expand the YARA rule set beyond downloader and injection-oriented rules
- Add additional file type handlers beyond PE-focused inspection
- Introduce de-duplication so identical files can reuse prior results
- Implement the placeholder ML detector as an optional confidence signal

## Operational improvements

- Add environment-based settings and production-ready static/media handling
- Add authentication and role-based access for dashboard and history views
- Move scans to background jobs for better responsiveness
- Add structured logging and audit trails
