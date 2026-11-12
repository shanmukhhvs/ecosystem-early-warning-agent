"""
Vulnerability lookups from public sources only.

Primary: OSV.dev (Google) batch API — no auth, aggregates NVD/GHSA/RustSec/PyPA/Go.
Severity/trust: NVD API 2.0 — optional NVD_API_KEY raises rate limit.

OSV's querybatch returns vuln IDs without severity; severity is enriched from NVD
for flagged packages only, capped per scan (NVD_MAX_PER_SCAN). Missing severity is
omitted (None) — never a fake 0. Bounded state and caps: docs/SPEC-public-intel-sources.md.
"""
import os
import re
import time
import logging
from datetime import date, datetime, timedelta, timezone

import httpx

from data_loader import (
    _nvd_cache_get,
    _nvd_cache_put,
    nvd_trust_score,
    nvd_new_threats_count,
    _nvd_get,
)

log = logging.getLogger(__name__)

# pulse cache: single dict, 1h TTL
_pulse_cache: dict | None = None
_pulse_cache_at: float = 0.0
_PULSE_TTL_SEC = 3600

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

_ECO_MAP_OSV = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
}

# NVD calls per scan are capped (default 10); everything else is OSV-only.
# Read per-scan so an env change takes effect without a restart.
def _max_nvd_per_scan() -> int:
    return int(os.getenv("NVD_MAX_PER_SCAN", "10"))


def _clean_version(version: str) -> str:
    v = re.sub(r"^[^0-9a-zA-Z]*", "", (version or "").strip())
    return re.split(r"[,\s]", v)[0] if v else ""


def _cvss_from_osv(sev_list) -> float | None:
    """Approximate CVSS from an OSV severity vector. None if no vector present."""
    for s in sev_list or []:
        vec = s.get("score", "")
        parts = {x.split(":")[0]: x.split(":")[1] for x in vec.split("/") if ":" in x}
        c, i, a = parts.get("C", "N"), parts.get("I", "N"), parts.get("A", "N")
        high = sum(1 for x in (c, i, a) if x == "H")
        med = sum(1 for x in (c, i, a) if x == "M")
        if high >= 2: return 9.0
        if high == 1: return 7.5
        if med >= 1: return 5.0
        if vec: return 3.0
    return None


def _nvd_cves_for_package(pkg: dict) -> list[dict] | None:
    """NVD CVEs for one package (cached 24h, rate-limited). None = unknown — never raises."""
    key = (pkg["ecosystem"].lower(), pkg["name"].lower(), pkg.get("namespace", "").lower())
    cached = _nvd_cache_get(key)
    if cached is not None:
        return cached.get("cves")

    keyword = pkg["name"] if not pkg.get("namespace") else f"{pkg['namespace']} {pkg['name']}"
    body = _nvd_get({"keywordSearch": keyword, "resultsPerPage": 20})
    if body is None:
        return None
    cves = []
    for it in body.get("vulnerabilities", []):
        c = it.get("cve", {})
        metrics = c.get("metrics", {})
        base = 0.0
        for key_m in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key_m) or []
            if arr:
                base = float(arr[0].get("cvssData", {}).get("baseScore", 0))
                break
        refs = c.get("references", [])
        cves.append({
            "baseScore": base,
            "published": str(c.get("published", ""))[:10],
            "cisaExploitAdd": c.get("cisaExploitAdd"),
            "hasExploitRef": any("exploit" in t.lower() for ref in refs for t in ref.get("tags", [])),
        })
    _nvd_cache_put(key, {"cves": cves})
    return cves


def _batch_osv(packages: list) -> dict:
    queries = []
    for p in packages:
        eco = _ECO_MAP_OSV.get(p["ecosystem"].lower(), p["ecosystem"])
        name = p["name"]
        if p["ecosystem"].lower() == "maven" and p.get("namespace"):
            name = f"{p['namespace']}:{p['name']}"
        q = {"package": {"name": name, "ecosystem": eco}}
        version = _clean_version(p.get("version", ""))
        if version:
            q["version"] = version
        queries.append(q)

    results = {}
    # OSV querybatch accepts up to 1000 queries per request
    for start in range(0, len(queries), 1000):
        chunk = queries[start:start + 1000]
        try:
            resp = httpx.post(_OSV_BATCH_URL, json={"queries": chunk},
                              headers={"Content-Type": "application/json"}, timeout=15)
            if resp.status_code != 200:
                log.warning("OSV.dev returned %s", resp.status_code)
                continue
            data = resp.json()
            for i, item in enumerate(data.get("results", [])):
                pkg = packages[start + i]
                vulns = item.get("vulns", [])
                if not vulns:
                    continue
                key = (pkg["ecosystem"].lower(), pkg["name"].lower(), pkg.get("namespace", "").lower())
                mal = next((v for v in vulns if v.get("id", "").startswith("MAL")), None)
                if mal:
                    # Malicious package — confirmed malware via OSV MAL-* advisory
                    results[key] = {
                        "found": True,
                        "source": "osv-mal",
                        "malware_id": mal.get("id", ""),
                        "malware_title": (mal.get("summary") or mal.get("id", ""))[:120],
                        "malware_details": mal.get("details", "") or mal.get("summary", ""),
                        "discovered_date": str(mal.get("published", ""))[:10],
                    }
                    continue
                vuln_entries = [
                    {
                        "id": v.get("id", ""),
                        "title": (v.get("summary") or v.get("id", ""))[:120],
                        "severity": _cvss_from_osv(v.get("severity", [])),
                        "cve": next((a for a in v.get("aliases", []) if a.startswith("CVE-")), ""),
                    }
                    for v in vulns[:5]
                ]
                scores = [e["severity"] for e in vuln_entries if e["severity"] is not None]
                results[key] = {
                    "found": True,
                    "vulnerability_count": len(vulns),
                    "vulnerabilities": vuln_entries,
                    "top_cvss": max(scores) if scores else None,
                    "source": "osv",
                }
        except Exception as e:
            log.warning("OSV.dev batch check failed: %s", e)
    return results


def batch_check(packages: list[dict]) -> dict[tuple, dict]:
    """
    OSV.dev per-package vuln lookup, with severity enriched from NVD for flagged
    packages (capped per scan). Severity unknown → omitted (None), never fake.
    """
    if not packages:
        return {}
    log.info("Vuln check via OSV.dev (%d packages)", len(packages))
    results = _batch_osv(packages)

    # Enrich severity from NVD for OSV-flagged CVE packages lacking it — within cap.
    # (MAL-* malware hits have no CVSS to enrich.)
    by_key = {(p["ecosystem"].lower(), p["name"].lower(), p.get("namespace", "").lower()): p for p in packages}
    needs = [k for k, v in results.items()
             if v.get("source") == "osv" and v.get("top_cvss") is None][: _max_nvd_per_scan()]
    for key in needs:
        cves = _nvd_cves_for_package(by_key[key])
        if cves is None:
            continue  # unknown → leave severity omitted
        top = max((float(c.get("baseScore", 0)) for c in cves), default=0.0)
        results[key]["top_cvss"] = top
        for e in results[key]["vulnerabilities"]:
            if e["severity"] is None:
                e["severity"] = top
    return results


def batch_trust_scores(packages: list[dict]) -> dict[tuple, int]:
    """
    0-100 trust score per package from NVD data. Packages beyond the per-scan
    NVD cap, or with no NVD data, are omitted entirely (never a fake 0/100).
    """
    versioned = [p for p in packages if _clean_version(p.get("version", ""))][: _max_nvd_per_scan()]
    scores: dict[tuple, int] = {}
    for pkg in versioned:
        cves = _nvd_cves_for_package(pkg)
        if cves is None:
            continue  # unknown → omit
        key = (pkg["ecosystem"].lower(), pkg["name"].lower(), pkg.get("namespace", "").lower())
        scores[key] = nvd_trust_score(cves)
    return scores


# ---------------------------------------------------------------------------
# Pulse / trends / stats — NVD published-CVE counts. No CSV.
# ---------------------------------------------------------------------------

def catalog_stats() -> dict:
    """Live catalog stats from NVD. No local catalog — fields omitted if unknown."""
    global _pulse_cache, _pulse_cache_at
    if _pulse_cache and time.time() - _pulse_cache_at < _PULSE_TTL_SEC:
        return _pulse_cache

    stats: dict = {"source": "nvd"}
    new_today = nvd_new_threats_count(days=1)
    if new_today is not None:
        stats["new_threats_today"] = new_today
    # No malware catalog exists in public data — omit total_malware rather than fake it.
    _pulse_cache = stats
    _pulse_cache_at = time.time()
    return stats


def threats_count_for_days(days: int) -> int | None:
    """Distinct CVEs published in the last `days` days. None if NVD unknown."""
    return nvd_new_threats_count(days)


def differentiator_stats() -> dict:
    """Public-source differentiator stats — NVD-derived only."""
    stats: dict = {"source": "nvd"}
    today = nvd_new_threats_count(days=1)
    if today is not None:
        stats["nvd_new_cves_today"] = today
    week = nvd_new_threats_count(days=7)
    if week is not None:
        stats["nvd_new_cves_7d"] = week
    return stats


def trends_data(days: int = 30) -> dict:
    """Daily published-CVE counts from NVD (one request per day bucket)."""
    end = datetime.now(timezone.utc)
    daily, dates = [], []
    for i in range(days, 0, -1):
        day = (end - timedelta(days=i)).date()
        start_dt = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end_dt = start_dt + timedelta(days=1)
        body = _nvd_get({
            "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 1,
        })
        if body is None:
            continue  # unknown day — omit, don't fake 0
        count = int(body.get("totalResults", 0))
        daily.append({"date": str(day), "count": count})
        dates.append(str(day))

    mid = date.today() - timedelta(days=days // 2)
    recent_count = sum(r["count"] for r in daily if r["date"] >= str(mid))
    prior_count = sum(r["count"] for r in daily if r["date"] < str(mid))
    pct_change = round(((recent_count - prior_count) / max(prior_count, 1)) * 100, 1) if daily else 0

    return {
        "days": days,
        "daily": daily,
        "dates": dates,
        "ecosystem_series": {},
        "ecosystems": [],
        "severity": [],
        "pct_change": pct_change,
        "source": "nvd",
    }
