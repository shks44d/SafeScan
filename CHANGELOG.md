# Changelog

## 2.0.0 — 2026-11-02

### Added
- Retry of unfinished chunks in the current tab, including cancelled and failed checks.
- Custom comma-separated port lists with ranges, sorting and deduplication.
- Completed/failed/pending counts and explicit partial-result status.
- Port/service/product search and identification-confidence filters.
- Visible app version and release header, security-reporting and deployment documentation.
- Production Vercel WAF API rate rule spanning function instances (per edge region and client IP).

### Improved
- Banner service inference, HTTP Server-header boundaries, and MySQL/MariaDB version handling.
- Retry-After support for transient responses and independent chunk failure handling.
- Shared worker admission, cost-weighted quotas, CSV formula protection, and the scanning S logo from post-1.0 fixes.

### Breaking export/API changes
- JSON exports use schemaVersion 2; scanned is actual completed count, total is selected count; status and per-chunk scope identify unfinished work.
- CSV exports include scan context/coverage before service columns.
- /api/scan start and end must be JSON integers, with no implicit coercion.

## 1.0.0 — 2026-10-10
- First tagged release of the stateless browser-driven port scanner.
