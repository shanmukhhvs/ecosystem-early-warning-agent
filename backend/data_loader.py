"""
NVD API 2.0 client + shared NVD helpers. No CSV, no Databricks, no Sonatype.

NVD is keyless-usable (5 req/30s); NVD_API_KEY raises that to 50 req/30s.
Every in-memory holder is hard-capped — see docs/SPEC-public-intel-sources.md.

This module owns: the NVD HTTP client (_nvd_get), the per-package CVE cache,
the rate limiter, and the trust-score composite. OSV.dev logic lives in oss_index.py.
"""
import os
import time
import logging
import threading
from collections import OrderedDict
from datetime import date, datetime, timedelta, timezone

import httpx

log = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ---- bounded state (caps in the spec) ----
_MAX_NVD_CACHE_KEYS = 500          # ~0.5 MB worst case
_NVD_CACHE_TTL_SEC = 24 * 3600

_nvd_cache: OrderedDict[tuple, tuple[float, dict]] = OrderedDict()
_cache_lock = threading.Lock()

# rate limiter: rolling 30s window
_window_lock = threading.Lock()
_window_start = time.monotonic()
_window_count = 0


def _rate_limit() -> int:
    """Max requests allowed per 30s window (keyless 5, keyed 50)."""
    return 50 if os.getenv("NVD_API_KEY", "").strip() else 5


def _throttle() -> bool:
    """True if another NVD request is allowed right now."""
    global _window_start, _window_count
    with _window_lock:
        now = time.monotonic()
        if now - _window_start >= 30:
            _window_start = now
            _window_count = 0
        if _window_count >= _rate_limit():
            return False
        _window_count += 1
        return True


def _nvd_get(params: dict) -> dict | None:
    """Single throttled NVD GET. None on any failure — never raises."""
    if not _throttle():
        log.info("NVD rate window full — skipping request")
        return None
    headers = {}
    key = os.getenv("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    try:
        r = httpx.get(_NVD_URL, params=params, headers=headers, timeout=20)
        if r.status_code != 200:
            log.warning("NVD returned %s", r.status_code)
            return None
        return r.json()
    except Exception as e:
        log.warning("NVD unreachable: %s", e)
        return None


# ---------- per-package CVE cache ----------

def _nvd_cache_get(key: tuple) -> dict | None:
    with _cache_lock:
        item = _nvd_cache.get(key)
        if not item:
            return None
        ts, val = item
        if time.time() - ts > _NVD_CACHE_TTL_SEC:
            del _nvd_cache[key]
            return None
        _nvd_cache.move_to_end(key)
        return val


def _nvd_cache_put(key: tuple, val: dict) -> None:
    with _cache_lock:
        _nvd_cache[key] = (time.time(), val)
        _nvd_cache.move_to_end(key)
        while len(_nvd_cache) > _MAX_NVD_CACHE_KEYS:
            _nvd_cache.popitem(last=False)  # evict oldest


# ---------- NVD helpers ----------

def nvd_new_threats_count(days: int = 1) -> int | None:
    """Distinct CVEs published in the last `days` days. None if NVD unknown."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    body = _nvd_get({
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 1,
    })
    if body is None:
        return None
    return int(body.get("totalResults", 0))


def nvd_trust_score(cves: list[dict]) -> int:
    """0-100 composite from a package's NVD CVEs; see spec."""
    score = 100
    now = date.today()
    recent = False
    for c in cves:
        base = float(c.get("baseScore", 0))
        if base >= 9:
            score -= 12
        elif base >= 7:
            score -= 7
        elif base >= 4:
            score -= 3
        if c.get("cisaExploitAdd") or c.get("hasExploitRef"):
            score -= 15
        try:
            published = date.fromisoformat(str(c.get("published", ""))[:10])
            if (now - published).days <= 365:
                recent = True
        except (ValueError, TypeError):
            pass
    if cves and not recent:
        score += 5
    return max(0, min(100, score))
