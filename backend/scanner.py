import json
import re
import xml.etree.ElementTree as ET
from typing import Any

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


def parse_dependencies(filename: str, content: str) -> list[dict]:
    """Parse package.json, pom.xml, requirements.txt, or *.toml into a list of {ecosystem, namespace, name, version}."""
    fname = filename.lower()
    if fname == "package.json":
        return _parse_npm(content)
    elif fname == "pom.xml":
        return _parse_maven(content)
    elif fname in ("requirements.txt", "requirements.in"):
        return _parse_pypi(content)
    elif fname.endswith(".toml"):
        return _parse_toml(content)
    else:
        # Try to auto-detect
        if content.strip().startswith("{"):
            return _parse_npm(content)
        elif "<project" in content or "<dependencies" in content:
            return _parse_maven(content)
        else:
            return _parse_pypi(content)


def _parse_npm(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except Exception:
        return []
    deps = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps.update(data.get(section, {}))
    result = []
    for pkg, version in deps.items():
        namespace = ""
        name = pkg
        if pkg.startswith("@"):
            parts = pkg[1:].split("/", 1)
            if len(parts) == 2:
                namespace, name = parts[0], parts[1]
        result.append({"ecosystem": "npm", "namespace": namespace, "name": name, "version": str(version)})
    return result


def _parse_maven(content: str) -> list[dict]:
    try:
        root = ET.fromstring(content)
    except Exception:
        return []
    NS = "http://maven.apache.org/POM/4.0.0"
    # Support both namespaced and non-namespaced POMs
    prefixes = [f"{{{NS}}}", ""]
    result = []
    seen = set()
    for prefix in prefixes:
        for dep in root.findall(f".//{prefix}dependency"):
            group_id = dep.find(f"{prefix}groupId")
            artifact_id = dep.find(f"{prefix}artifactId")
            version_el = dep.find(f"{prefix}version")
            if group_id is not None and artifact_id is not None:
                gid = (group_id.text or "").strip()
                aid = (artifact_id.text or "").strip()
                ver = (version_el.text or "").strip() if version_el is not None else ""
                key = (gid, aid)
                if key not in seen and gid and aid:
                    seen.add(key)
                    result.append({
                        "ecosystem": "maven",
                        "namespace": gid,
                        "name": aid,
                        "version": ver,
                    })
    return result


def _parse_toml(content: str) -> list[dict]:
    if tomllib is None:
        # Fallback: regex-scrape dependency names from raw TOML text
        result = []
        seen = set()
        for match in re.finditer(r'"([A-Za-z0-9_\-\.]+)"', content):
            name = match.group(1).lower()
            if name not in seen:
                seen.add(name)
                result.append({"ecosystem": "pypi", "namespace": "", "name": name, "version": ""})
        return result

    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    result = []

    # pyproject.toml — PEP 621 [project.dependencies] and [project.optional-dependencies]
    project = data.get("project", {})
    deps_raw = list(project.get("dependencies", []))
    for extras in project.get("optional-dependencies", {}).values():
        deps_raw.extend(extras)

    # pyproject.toml — [tool.poetry.dependencies] / [tool.poetry.dev-dependencies]
    poetry = data.get("tool", {}).get("poetry", {})
    for section in ("dependencies", "dev-dependencies", "group"):
        val = poetry.get(section)
        if isinstance(val, dict):
            for k, v in val.items():
                if k.lower() == "python":
                    continue
                ver = v if isinstance(v, str) else (v.get("version", "") if isinstance(v, dict) else "")
                result.append({"ecosystem": "pypi", "namespace": "", "name": k.lower(), "version": ver})

    # PEP 621 / setuptools deps strings like "requests>=2.0"
    for dep in deps_raw:
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([^\s].*)?$", dep.strip())
        if m:
            result.append({"ecosystem": "pypi", "namespace": "", "name": m.group(1).lower(), "version": (m.group(2) or "").strip()})

    # Cargo.toml — [dependencies] / [dev-dependencies] / [build-dependencies]
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, val in data.get(section, {}).items():
            ver = val if isinstance(val, str) else (val.get("version", "") if isinstance(val, dict) else "")
            result.append({"ecosystem": "cargo", "namespace": "", "name": name, "version": ver})

    # Deduplicate by (ecosystem, name)
    seen = set()
    deduped = []
    for pkg in result:
        key = (pkg["ecosystem"], pkg["name"])
        if key not in seen:
            seen.add(key)
            deduped.append(pkg)
    return deduped


def _parse_pypi(content: str) -> list[dict]:
    result = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~].*)?$", line)
        if match:
            result.append({
                "ecosystem": "pypi",
                "namespace": "",
                "name": match.group(1).lower(),
                "version": (match.group(2) or "").strip(),
            })
    return result
