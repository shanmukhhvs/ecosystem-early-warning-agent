# Design notes: public intelligence sources

Backend data comes only from public sources: Google OSV.dev (primary, per-package CVEs and malicious-package
advisories) and the NVD API 2.0 (enrichment: pulse, trust, severity detail).

## Sources

| Concern | Source |
|---|---|
| Per-package CVE lookup | OSV.dev `POST /v1/querybatch` |
| Malware detection | OSV.dev `MAL-*` advisories (OpenSSF malicious-packages) |
| Malware narrative | MAL `details` free text, passed to the AI narrative |
| Trust signal per version | NVD-derived composite (see below) |
| "New threats today" / pulse | NVD `pubStartDate` / `pubEndDate` window (published CVEs) |
| Trends | NVD date-bucketed counts (7d / 30d) |
| Reachability check at startup | OSV ping, NVD ping (best effort) |
| Environment variables | `NVD_API_KEY` (optional), `NVD_MAX_PER_SCAN` (default 10) |

### What the public datasets do not provide

- **Environments, spread or affected customers.** No public API provides this telemetry, so it is not shown.
- **A structured threat type** (typosquat, backdoor). MAL advisories carry free-text `details` only.
- **A "new malware today" list.** OSV has no list-by-date endpoint; the pulse is NVD published CVEs.
- **A static catalog.** No CSV is read anywhere.

## Bounded-state design

Holders and caps:
- `_nvd_cache`: dict, LRU, **max 500 keys**, 24h TTL. Key `(eco, name, ns)`, value a small dict (about 1 KB or less).
  Worst case about 0.5 MB.
- `_pulse_cache`: one dict (today's NVD window result), 1h TTL. A few KB.
- Per-`/analyze` NVD calls: capped by `NVD_MAX_PER_SCAN` (**default 10**). All other packages resolve from the OSV
  batch only (a single POST, at most 1000 queries per request).
- OSV batch request: one `querybatch` POST per scan, queries capped at 1000 (the upload cap of 512 KB is about 2000
  dependencies, chunked into at most 2 requests if exceeded).
- No background threads and no scheduled refresh. Caches fill only on request threads of the FastAPI worker, and
  lookups run inside `run_in_executor` (off the event loop).

In every state:
- Steady state: the caps above hold.
- First window after startup: caches are empty; NVD calls are still at most 10 per scan and OSV is still one batch per
  scan. There is no eager warm-up.
- Degraded (NVD down or rate limited): NVD fields are omitted from the response (never `0` or `[]`) and `source` marks
  `"osv"`.
- `NVD_API_KEY` absent: the unkeyed rate is 5 requests per 30 seconds. The 10-call cap is enforced with a rolling
  30-second window limiter (keyed: 50 per 30 seconds); overflow packages are OSV-only.

When a budget is exceeded, the field is omitted (a distinguishable "unknown"), never a fake value.

## Trust score

A 0 to 100 composite from NVD data for the package's matched CVEs:
- base 100; minus 12 per critical (9 or higher), minus 7 per high (7 or higher), minus 3 per medium (4 or higher)
- minus 15 if any CVE is in CISA KEV or has an exploit reference
- plus 5 if no CVE was published in the last 12 months (staleness of vulnerabilities, not of the package)
- clamped to 0 to 100; omitted entirely if NVD has no data for the package.

## Files

- `backend/data_loader.py`: NVD client (pulse, trends, stats).
- `backend/oss_index.py`: OSV `querybatch`; flags `MAL-*` as malware (`source="osv-mal"`) and GHSA/CVE as
  vulnerabilities; NVD composite trust; pulse and trends (NVD).
- `backend/intelligence.py`: all packages go to OSV; the risk model handles `osv-mal` (malware, high base) versus
  `osv` / `nvd` (CVE).
- `backend/main.py`: startup OSV ping; pulse, trends and stats import from `oss_index`.
- `backend/tests/test_public_sources.py`: tests.

## Verification

- Unit: OSV batch mapping, `MAL-*` classification to `osv-mal`, NVD composite score, rate limiter, cache cap (the 501st
  key evicts), NVD-down degraded path (fields omitted).
- Boot: `uvicorn` starts with no special environment; `/health`, `/pulse` and `/analyze` return 200; a known malicious
  package (node-ipc) flags RED through `MAL-*`.
- Worst-case payload: a 2000-dependency scan stays within the OSV batch limit; NVD calls are at most 10.

## Goals for developers

- **Zero setup:** clone, `pip install -r requirements.txt`, run. No account of any kind. `NVD_API_KEY` is optional and
  raises the rate limit.
- **Every developer covered:** npm, PyPI, Maven, Cargo, RubyGems and NuGet through OSV, which aggregates NVD, GHSA,
  RustSec, PyPA, Go and others.
- **Honest output:** missing data is omitted, never a fake `0` or `[]`.
- **Free:** both APIs are public and usable without a key.
