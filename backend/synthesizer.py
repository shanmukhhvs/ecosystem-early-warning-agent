import asyncio
import hashlib
import litellm
import os
import logging

log = logging.getLogger(__name__)

_MODEL = os.getenv("LITELLM_MODEL", "claude-sonnet-4-6")
_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "")

# Cache narratives by threat fingerprint — same threat signature reuses the narrative
_narrative_cache: dict[str, str] = {}


def _cache_key(pkg: dict) -> str:
    intel = pkg.get("intel", {})
    src = intel.get("source", "")
    ident = intel.get("malware_id", "") if src == "osv-mal" else str(intel.get("top_cvss", ""))
    # Include package identity — two different packages with the same source/CVSS
    # must never share a narrative.
    raw = f"{pkg['ecosystem']}{pkg['name']}{src}{ident}{pkg.get('traffic_light','')}"
    return hashlib.md5(raw.encode()).hexdigest()


def _pkg_context(pkg: dict) -> str:
    intel = pkg["intel"]
    parts = [f"Package: {pkg['ecosystem']}/{pkg['namespace']+'/' if pkg['namespace'] else ''}{pkg['name']} {pkg['version']}"]
    parts.append(f"Risk score: {pkg['risk_score']}/100 ({pkg['traffic_light']})")
    if intel.get("typosquat_of"):
        parts.append(f"Typosquat warning: name is 1 edit from the popular package '{intel['typosquat_of']}' — a common typosquatting pattern. Not confirmed malware, but suspicious.")
    if intel.get("found"):
        source = intel.get("source", "")
        if source == "osv-mal":
            # Confirmed malicious package via OSV MAL-* advisory
            parts.append("Malicious package: YES (OSV MAL advisory)")
            parts.append(f"Advisory: {intel.get('malware_id', '')}")
            parts.append(f"Reported: {intel.get('discovered_date', 'unknown')}")
            details = intel.get("malware_details", "")
            if details:
                parts.append(f"Attack details: {details}")
        else:
            # Public CVE — legitimate package with known vulnerabilities, NOT malware
            parts.append("Malicious package: NO")
            parts.append(f"Known CVEs: {intel.get('vulnerability_count', 0)} (source: {source})")
            if intel.get("top_cvss") is not None:
                parts.append(f"Top CVSS score: {intel['top_cvss']}")
            vulns = intel.get("vulnerabilities", [])
            if vulns:
                parts.append(f"Vulnerabilities: {', '.join(v['id'] for v in vulns[:3])}")
    else:
        parts.append("Malicious package: NO")
    return "\n".join(parts)


async def _synthesize_one(pkg: dict) -> str:
    if pkg["traffic_light"] == "GREEN" and not pkg["intel"].get("found"):
        return "No known threats detected across OSV.dev and NVD public vulnerability data."
    if pkg["intel"].get("typosquat_of") and not pkg["intel"].get("found"):
        return pkg["intel"]["typosquat_warning"]

    key = _cache_key(pkg)
    if key in _narrative_cache:
        log.info("narrative cache hit for %s (key=%s)", pkg["name"], key[:8])
        return _narrative_cache[key]

    ctx = _pkg_context(pkg)
    try:
        resp = await litellm.acompletion(
            model=_MODEL,
            api_key=_API_KEY,
            **({"api_base": _BASE_URL} if _BASE_URL else {}),
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a supply chain security expert. Given intelligence data about a software package, "
                        "write exactly 2-3 sentences explaining the risk to a developer. "
                        "Be specific about what the threat does and why it matters. "
                        "Be direct, no fluff."
                    ),
                },
                {"role": "user", "content": ctx},
            ],
            max_tokens=150,
            timeout=20.0,
        )
        narrative = resp.choices[0].message.content.strip()
        _narrative_cache[key] = narrative
        return narrative
    except Exception as e:
        log.warning("synthesize_one failed for %s: %s", pkg["name"], e)
        intel = pkg["intel"]
        if intel.get("source") == "osv-mal":
            return f"This package is malicious (OSV advisory {intel.get('malware_id', '')}). {intel.get('malware_details', 'Remove it immediately.')}"
        if intel.get("found"):
            return f"This package has {intel.get('vulnerability_count', 0)} known CVE(s); review and upgrade to a patched version."
        return "Elevated risk detected from public vulnerability data."


async def synthesize_all(packages: list[dict]) -> list[dict]:
    """Add narrative to each package in parallel. Returns packages with 'narrative' field added."""
    narratives = await asyncio.gather(*[_synthesize_one(p) for p in packages])
    for pkg, narrative in zip(packages, narratives):
        pkg["narrative"] = narrative
    return packages


async def chat_response(question: str, report_context: str, settings: dict) -> str:
    try:
        resp = await litellm.acompletion(
            model=_MODEL,
            api_key=_API_KEY,
            **({"api_base": _BASE_URL} if _BASE_URL else {}),
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a supply chain security expert. You have just analyzed a developer's dependencies "
                        "and produced the following risk report. Answer the developer's follow-up question.\n\n"
                        "Format your answer as 3-5 concise bullet points (use '- ' for each point). "
                        "Each bullet should be short and information-dense — do not pad with filler words, "
                        "but do not drop any important detail from the risk report either. "
                        "Do not add an intro sentence or a closing summary; output only the bullet points.\n\n"
                        f"RISK REPORT:\n{report_context}"
                    ),
                },
                {"role": "user", "content": question},
            ],
            max_tokens=400,
            timeout=30.0,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        log.warning("chat_response failed: %s", e)
        return "I couldn't process that question. Please try again."
