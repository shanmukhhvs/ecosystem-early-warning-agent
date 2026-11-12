"""Tests for the Sonatype/Databricks-free, CSV-free backend (OSV.dev + NVD)."""
from unittest.mock import MagicMock, patch

import data_loader
import oss_index
from data_loader import _MAX_NVD_CACHE_KEYS, _nvd_cache, nvd_trust_score, nvd_new_threats_count
from oss_index import _batch_osv, batch_check, batch_trust_scores


def setup_function():
    _nvd_cache.clear()
    oss_index._pulse_cache = None


# ---------- OSV: CVEs ----------

def test_osv_batch_maps_vulns():
    resp = MagicMock(status_code=200)
    resp.json.return_value = {
        "results": [{
            "vulns": [{
                "id": "GHSA-xxxx",
                "summary": "Prototype pollution",
                "aliases": ["CVE-2021-1234"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            }]
        }]
    }
    pkgs = [{"ecosystem": "npm", "name": "lodash", "namespace": "", "version": "4.17.20"}]
    with patch("oss_index.httpx.post", return_value=resp), \
         patch("oss_index.httpx.get", return_value=MagicMock(status_code=404)):
        out = _batch_osv(pkgs)
    hit = out[("npm", "lodash", "")]
    assert hit["found"] is True
    assert hit["vulnerability_count"] == 1
    assert hit["source"] == "osv"
    assert hit["vulnerabilities"][0]["cve"] == "CVE-2021-1234"


def test_batch_check_never_calls_sonatype():
    pkgs = [{"ecosystem": "npm", "name": "x", "namespace": "", "version": "1.0.0"}]
    with patch("oss_index.httpx.post", return_value=MagicMock(status_code=200, json=lambda: {"results": []})) as m, \
         patch("oss_index.httpx.get", return_value=MagicMock(status_code=404)):
        batch_check(pkgs)
    for call in m.call_args_list:
        assert "sonatype" not in str(call.args[0]).lower()


def test_osv_failure_returns_empty_not_fake():
    pkgs = [{"ecosystem": "npm", "name": "x", "namespace": "", "version": "1"}]
    with patch("oss_index.httpx.post", side_effect=Exception("down")):
        assert _batch_osv(pkgs) == {}


# ---------- OSV: MAL-* malware detection ----------

def test_osv_mal_advisory_flags_malware():
    resp = MagicMock(status_code=200)
    resp.json.return_value = {
        "results": [{
            "vulns": [{
                "id": "MAL-2026-3744",
                "summary": "Malicious code in node-ipc (npm)",
                "details": "Versions published by a compromised maintainer; obfuscated payload exfiltrates data.",
                "published": "2026-05-14T16:53:17Z",
                "aliases": [],
                "severity": None,
            }]
        }]
    }
    pkgs = [{"ecosystem": "npm", "name": "node-ipc", "namespace": "", "version": "12.0.1"}]
    with patch("oss_index.httpx.post", return_value=resp), \
         patch("oss_index.httpx.get", return_value=MagicMock(status_code=404)):
        out = batch_check(pkgs)
    hit = out[("npm", "node-ipc", "")]
    assert hit["source"] == "osv-mal"
    assert hit["found"] is True
    assert hit["malware_details"].startswith("Versions published")
    assert hit["discovered_date"] == "2026-05-14"


def test_osv_cve_only_is_not_malware():
    resp = MagicMock(status_code=200)
    resp.json.return_value = {
        "results": [{"vulns": [{"id": "GHSA-x", "summary": "ReDoS", "aliases": ["CVE-2021-1"], "severity": None}]}]
    }
    pkgs = [{"ecosystem": "npm", "name": "legit", "namespace": "", "version": "1.0.0"}]
    with patch("oss_index.httpx.post", return_value=resp), \
         patch("oss_index.httpx.get", return_value=MagicMock(status_code=404)):
        out = batch_check(pkgs)
    hit = out[("npm", "legit", "")]
    assert hit["source"] == "osv"


# ---------- OSV severity enrichment via NVD ----------

def test_osv_severity_enriched_from_nvd_within_cap(monkeypatch):
    monkeypatch.setenv("NVD_MAX_PER_SCAN", "5")
    osv_resp = MagicMock(status_code=200)
    osv_resp.json.return_value = {
        "results": [{"vulns": [{"id": "GHSA-x", "summary": "s", "aliases": ["CVE-2024-0001"], "severity": None}]}]
    }
    nvd_resp = MagicMock(status_code=200)
    nvd_resp.json.return_value = {
        "vulnerabilities": [{
            "cve": {
                "published": "2024-01-01T00:00:00.000",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "references": [],
            }
        }]
    }
    pkgs = [{"ecosystem": "maven", "name": "bcprov-jdk18on", "namespace": "org.bouncycastle", "version": ""}]
    with patch("oss_index.httpx.post", return_value=osv_resp), \
         patch("oss_index.httpx.get", return_value=nvd_resp):
        out = batch_check(pkgs)
    hit = out[("maven", "bcprov-jdk18on", "org.bouncycastle")]
    assert hit["top_cvss"] == 9.8


def test_osv_severity_omitted_when_nvd_down(monkeypatch):
    monkeypatch.setenv("NVD_MAX_PER_SCAN", "5")
    osv_resp = MagicMock(status_code=200)
    osv_resp.json.return_value = {"results": [{"vulns": [{"id": "GHSA-x", "summary": "s", "aliases": [], "severity": None}]}]}
    pkgs = [{"ecosystem": "npm", "name": "x", "namespace": "", "version": ""}]
    with patch("oss_index.httpx.post", return_value=osv_resp), \
         patch("oss_index.httpx.get", side_effect=Exception("nvd down")):
        out = batch_check(pkgs)
    hit = out[("npm", "x", "")]
    assert hit["found"] is True
    assert hit["top_cvss"] is None


# ---------- NVD trust score ----------

def _cve(base, kev=False, exploit=False):
    from datetime import date, timedelta
    return {
        "baseScore": base,
        "published": str(date.today() - timedelta(days=30)),
        "cisaExploitAdd": "2024-01-01" if kev else None,
        "hasExploitRef": exploit,
    }


def test_trust_score_perfect_when_no_cves():
    assert nvd_trust_score([]) == 100


def test_trust_score_penalises_critical_and_kev():
    assert nvd_trust_score([_cve(9.5, kev=True)]) == 73


def test_trust_score_omitted_on_nvd_failure():
    pkgs = [{"ecosystem": "npm", "name": "x", "namespace": "", "version": "1.2.3"}]
    with patch("oss_index._nvd_cves_for_package", return_value=None):
        assert batch_trust_scores(pkgs) == {}


# ---------- NVD cache + rate caps ----------

def test_nvd_cache_is_bounded():
    for i in range(_MAX_NVD_CACHE_KEYS + 5):
        data_loader._nvd_cache_put(("npm", f"pkg{i}", ""), {"x": 1})
    assert len(_nvd_cache) == _MAX_NVD_CACHE_KEYS
    assert ("npm", "pkg0", "") not in _nvd_cache


def test_nvd_per_scan_cap(monkeypatch):
    monkeypatch.setenv("NVD_MAX_PER_SCAN", "3")
    pkgs = [{"ecosystem": "npm", "name": f"p{i}", "namespace": "", "version": "1"} for i in range(10)]
    calls = {"n": 0}

    def fake(*a, **k):
        calls["n"] += 1
        return MagicMock(status_code=200, json=lambda: {"vulnerabilities": []})

    with patch("oss_index.httpx.get", side_effect=fake):
        batch_trust_scores(pkgs)
    assert calls["n"] <= 3


# ---------- Pulse (NVD, no CSV) ----------

def test_pulse_omits_fields_when_nvd_down():
    with patch("data_loader.httpx.get", side_effect=Exception("down")):
        assert nvd_new_threats_count(days=1) is None


def test_no_csv_dependency():
    import inspect
    src = inspect.getsource(data_loader)
    assert "malware_catalog.csv" not in src
    assert "spread_velocity.csv" not in src
    assert "read_csv" not in src


# ---------- Typosquat heuristic ----------

def test_typosquat_flags_one_edit_from_popular():
    from intelligence import analyze_packages_batch
    deps = [{"ecosystem": "npm", "name": "lodsh", "namespace": "", "version": "1.0.0"}]
    with patch("intelligence.osv_batch_check", return_value={}), \
         patch("intelligence.batch_trust_scores", return_value={}):
        out = analyze_packages_batch(deps)
    pkg = out[0]
    assert pkg["intel"].get("typosquat_of") == "lodash"
    assert pkg["traffic_light"] == "YELLOW"
    # A warning, not a malware verdict
    assert pkg["intel"].get("source") != "osv-mal"


def test_typosquat_does_not_flag_exact_popular_name():
    from intelligence import analyze_packages_batch
    deps = [{"ecosystem": "npm", "name": "lodash", "namespace": "", "version": "4.17.20"}]
    with patch("intelligence.osv_batch_check", return_value={}), \
         patch("intelligence.batch_trust_scores", return_value={}):
        out = analyze_packages_batch(deps)
    assert "typosquat_of" not in out[0]["intel"]


def test_typosquat_ignores_unrelated_names():
    from intelligence import analyze_packages_batch
    deps = [{"ecosystem": "npm", "name": "my-internal-utils", "namespace": "", "version": "1.0.0"}]
    with patch("intelligence.osv_batch_check", return_value={}), \
         patch("intelligence.batch_trust_scores", return_value={}):
        out = analyze_packages_batch(deps)
    assert "typosquat_of" not in out[0]["intel"]


def test_typosquat_respects_namespace_scope():
    """@types/lodash is legitimate — scoped packages matching a popular name are not squats."""
    from intelligence import analyze_packages_batch
    deps = [{"ecosystem": "npm", "name": "lodash", "namespace": "@types", "version": "4.0.0"}]
    with patch("intelligence.osv_batch_check", return_value={}), \
         patch("intelligence.batch_trust_scores", return_value={}):
        out = analyze_packages_batch(deps)
    assert "typosquat_of" not in out[0]["intel"]
