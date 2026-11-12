from collections import defaultdict
from oss_index import batch_check as osv_batch_check, batch_trust_scores


# ---------------------------------------------------------------------------
# Typosquat name heuristic.
#
# A package named ~1 edit from a widely-used package is a classic typosquat
# signal (e.g. "lodsh" → "lodash"). This is a *warning*, never a malware verdict
# — the malware verdict comes only from OSV MAL-* advisories.
#
# _POPULAR_PACKAGES is a small curated reference set of the most-depended-on
# names across npm/PyPI/Maven. It is detection reference data (like a phishing
# blocklist), NOT telemetry/stats — see docs/SPEC-public-intel-sources.md.
# Bounded: a fixed constant, no growth.
# ---------------------------------------------------------------------------
_POPULAR_PACKAGES = {
    # npm
    "lodash", "react", "react-dom", "express", "axios", "moment", "chalk",
    "commander", "debug", "request", "async", "underscore", "vue", "angular",
    "jquery", "bootstrap", "dotenv", "fs-extra", "uuid", "yargs", "webpack",
    "babel", "eslint", "typescript", "next", "redux", "mongoose", "socket.io",
    "node-fetch", "cors", "body-parser", "jsonwebtoken", "bcrypt", "minimist",
    "semver", "glob", "mkdirp", "rimraf", "colors", "qs", "prop-types",
    # pypi
    "requests", "urllib3", "numpy", "pandas", "django", "flask", "scipy",
    "setuptools", "pip", "wheel", "six", "certifi", "idna", "charset-normalizer",
    "python-dateutil", "pyyaml", "jinja2", "click", "sqlalchemy", "boto3",
    "botocore", "cryptography", "pillow", "matplotlib", "pytest", "attrs",
    "packaging", "typing-extensions", "importlib-metadata", "zipp", "tornado",
    # maven (artifactIds commonly squatted)
    "gson", "guava", "junit", "slf4j", "log4j", "commons-lang", "commons-io",
    "jackson-databind", "okhttp", "retrofit", "spring-core", "spring-web",
}

# Names shorter than this are too noisy for edit-distance matching.
_MIN_TYPO_LEN = 4


def _edit_distance_leq(a: str, b: str, limit: int) -> bool:
    """True if Levenshtein(a, b) <= limit. Early-exit DP, O(len(a)*limit)."""
    if abs(len(a) - len(b)) > limit:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            row_min = min(row_min, v)
        if row_min > limit:
            return False
        prev = cur
    return prev[-1] <= limit


def _typosquat_target(name: str, namespace: str) -> str | None:
    """Return the popular package this name squats on, or None.

    Scoped packages (namespace present) are not typosquat candidates — a scoped
    name like @types/lodash is legitimate. Only unscoped names are checked.
    """
    if namespace:
        return None
    n = name.lower()
    if len(n) < _MIN_TYPO_LEN or n in _POPULAR_PACKAGES:
        return None  # exact popular names and very short names are not squats
    for popular in _POPULAR_PACKAGES:
        if _edit_distance_leq(n, popular, 1):
            return popular
    return None


def detect_namespace_clusters(packages: list[dict]) -> list[dict]:
    """Return list of namespace threat clusters: namespaces where 2+ packages are flagged."""
    # Group flagged packages by (ecosystem, namespace)
    ns_groups: dict[tuple, list] = defaultdict(list)
    for pkg in packages:
        if pkg.get("traffic_light") in ("RED", "YELLOW") and pkg.get("intel", {}).get("found"):
            ns = pkg.get("namespace", "")
            # For unscoped packages, group by name prefix (e.g. "aone-*")
            if not ns:
                # Extract potential namespace from name prefix (word before first dash)
                name = pkg.get("name", "")
                parts = name.split("-")
                if len(parts) >= 2:
                    ns = parts[0]
            if ns:
                key = (pkg["ecosystem"], ns)
                ns_groups[key].append(pkg["name"])

    clusters = []
    for (ecosystem, ns), names in ns_groups.items():
        if len(names) >= 2:
            clusters.append({
                "ecosystem": ecosystem,
                "namespace": ns,
                "packages": names,
                "count": len(names),
            })
    return sorted(clusters, key=lambda c: c["count"], reverse=True)


def _risk_score(intel: dict) -> int:
    """Compute 0-100 risk score from intelligence data."""
    if not intel["found"]:
        return 30 if intel.get("typosquat_of") else 0  # typosquat warning → YELLOW

    if intel.get("source") == "osv-mal":
        return 90  # confirmed malware via OSV MAL-* advisory → RED

    # Public CVE source (OSV/NVD)
    if intel.get("source") in ("osv", "nvd"):
        score = 30  # base: known CVE but not confirmed malware
        raw_cvss = intel.get("top_cvss")
        cvss = float(raw_cvss) if raw_cvss is not None else 0.0  # unknown → base only
        if cvss >= 9.0:
            score += 30   # critical → 60 = RED
        elif cvss >= 7.0:
            score += 20   # high → 50 = YELLOW
        elif cvss >= 4.0:
            score += 10   # medium → 40 = YELLOW
        # else low → 30 = YELLOW
        return min(score, 100)

    return 0


def _traffic_light(score: int) -> str:
    if score >= 60:
        return "RED"
    elif score >= 25:
        return "YELLOW"
    return "GREEN"


def analyze_package(ecosystem: str, name: str, namespace: str = "", version: str = "") -> dict:
    """Single-package analysis via OSV.dev."""
    intel_map = osv_batch_check([{"ecosystem": ecosystem, "name": name, "namespace": namespace, "version": version}])
    intel = intel_map.get((ecosystem.lower(), name.lower(), namespace.lower()), {"found": False})
    score = _risk_score(intel)
    return {
        "ecosystem": ecosystem,
        "namespace": namespace,
        "name": name,
        "version": version,
        "risk_score": score,
        "traffic_light": _traffic_light(score),
        "intel": intel,
    }


def analyze_packages_batch(deps: list[dict]) -> list[dict]:
    """Analyze all packages against OSV.dev (CVEs + MAL-* malware) in one batch."""
    osv_results = osv_batch_check(deps)

    results = []
    for d in deps:
        key = (d["ecosystem"].lower(), d["name"].lower(), d.get("namespace", "").lower())
        intel = osv_results.get(key, {"found": False})

        # CVE packages: derive a coarse severity band from the top CVSS (if known)
        if intel.get("source") == "osv":
            scored = [v for v in intel.get("vulnerabilities", []) if v.get("severity") is not None]
            top_vuln = max(scored, key=lambda v: v["severity"]) if scored else {}
            cvss = top_vuln.get("severity")
            if cvss is not None:
                intel["severity"] = "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
            # else: severity unknown — omit, never guess

        # Typosquat name heuristic — a warning layered on top of OSV results,
        # never a malware verdict. Only fires when OSV found nothing.
        if not intel.get("found"):
            target = _typosquat_target(d["name"], d.get("namespace", ""))
            if target:
                intel["typosquat_of"] = target
                intel["typosquat_warning"] = (
                    f"Name is 1 edit away from the popular package '{target}' — "
                    f"a common typosquatting pattern. Verify this is the package you intended."
                )

        score = _risk_score(intel)
        # A CVE hit is at least YELLOW even with unknown severity
        if intel.get("source") == "osv":
            score = max(25, score)
        pkg = {
            "ecosystem": d["ecosystem"],
            "namespace": d.get("namespace", ""),
            "name": d["name"],
            "version": d.get("version", ""),
            "risk_score": score,
            "traffic_light": _traffic_light(score),
            "intel": intel,
        }
        results.append(pkg)

    # Developer Trust Score — NVD composite per exact version
    trust_scores = batch_trust_scores(deps)
    for pkg in results:
        key = (pkg["ecosystem"].lower(), pkg["name"].lower(), pkg["namespace"].lower())
        ts = trust_scores.get(key)
        if ts is not None:
            pkg["intel"]["developer_trust_score"] = ts

    return results
