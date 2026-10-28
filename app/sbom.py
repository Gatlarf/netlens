"""A software bill of materials (SBOM) of this very installation: what Netlens is made of, as it runs.

Enterprise buyers ask for one (supply-chain reviews, vulnerability matching, licence checks). It is made from what is installed, not from a file that could
be out of date: the Python packages of the running environment (with their declared licences), the vendored browser libraries (with the SHA-256 of each file),
and, when the system offers `dpkg`, the operating-system packages of the image. Two standard formats from the same list:

    CycloneDX 1.5 (JSON)     python -m app.sbom                 or  GET /api/sbom                  (administrators)
    SPDX 2.3 (JSON)          python -m app.sbom --format spdx   or  GET /api/sbom?format=spdx

Every package has a package URL (purl) so a scanner (Grype, Trivy, Dependency-Track, OSV) can match it to known vulnerabilities. The container image published by
the project also carries a build-time SBOM and provenance attestation (see the workflow), made independently from the image layers.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_NAME = "netlens"
LICENSE_ID = "PolyForm-Noncommercial-1.0.0"
VENDOR = Path(__file__).resolve().parent / "static" / "vendor"
# The browser libraries kept under app/static/vendor: what they are, their version and licence (the README lists the same).
VENDORED = [
    {"file": "vis-network.min.js", "name": "vis-network", "version": "9.1.9", "license": "Apache-2.0 OR MIT", "purl": "pkg:npm/vis-network@9.1.9", "url": "https://visjs.github.io/vis-network/"},
    {"file": "xterm.js", "name": "xterm", "version": "5.5.0", "license": "MIT", "purl": "pkg:npm/xterm@5.5.0", "url": "https://github.com/xtermjs/xterm.js"},
    {"file": "xterm.css", "name": "xterm (stylesheet)", "version": "5.5.0", "license": "MIT", "purl": "pkg:npm/xterm@5.5.0", "url": "https://github.com/xtermjs/xterm.js"},
    {"file": "addon-fit.js", "name": "xterm-addon-fit", "version": "0.10.0", "license": "MIT", "purl": "pkg:npm/%40xterm/addon-fit@0.10.0", "url": "https://github.com/xtermjs/xterm.js"},
    {"file": "guacamole-common.min.js", "name": "guacamole-common-js", "version": "1.5.0", "license": "Apache-2.0", "purl": "pkg:npm/guacamole-common-js@1.5.0", "url": "https://guacamole.apache.org/"},
    {"file": "qrcode.js", "name": "qrcode-generator", "version": "1.4.4", "license": "MIT", "purl": "pkg:npm/qrcode-generator@1.4.4", "url": "https://github.com/kazuhikoarase/qrcode-generator"},
]


def _version() -> str:
    try:
        from app.version import VERSION

        return str(VERSION)
    except Exception:  # noqa: BLE001
        return os.environ.get("NETLENS_VERSION") or "dev"


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _licence_of(dist: md.Distribution) -> str:
    meta = dist.metadata
    expression = meta.get("License-Expression")
    if expression:
        return expression.strip()[:120]
    classifiers = [c.split("::")[-1].strip() for c in (meta.get_all("Classifier") or []) if c.startswith("License ::") and "OSI Approved" in c]
    text = (meta.get("License") or "").strip()
    if classifiers:
        return classifiers[0][:120] if len(classifiers) == 1 else " OR ".join(classifiers)[:120]
    if text and len(text) < 80 and "\n" not in text:
        return text
    return "NOASSERTION"


def _direct_requirements() -> set[str]:
    path = Path(__file__).resolve().parent.parent / "requirements.txt"
    names: set[str] = set()
    try:
        for line in path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                names.add(_normalise(re.split(r"[\[<>=!~; ]", line, maxsplit=1)[0]))
    except OSError:
        pass
    return names


def python_packages() -> list[dict[str, Any]]:
    """The Python distributions of the running environment (the application's own dependencies, installed in the image)."""
    direct = _direct_requirements()
    seen: dict[str, dict[str, Any]] = {}
    for dist in md.distributions():
        name = dist.metadata.get("Name")
        version = dist.version
        if not name or not version:
            continue
        key = _normalise(name)
        if key in seen:
            continue
        seen[key] = {"name": name, "version": version, "license": _licence_of(dist), "purl": f"pkg:pypi/{key}@{version}", "direct": key in direct,
                     "url": (dist.metadata.get("Home-page") or "")[:200] or None}
    return sorted(seen.values(), key=lambda p: p["name"].lower())


def vendored_libraries() -> list[dict[str, Any]]:
    out = []
    for item in VENDORED:
        path = VENDOR / item["file"]
        if not path.is_file():
            continue
        out.append({**item, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
    return out


def _os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
    except OSError:
        pass
    return data


def os_packages() -> list[dict[str, Any]]:
    """The operating-system packages of the image (Debian based), when dpkg is there; nothing otherwise."""
    if not shutil.which("dpkg-query"):
        return []
    try:
        out = subprocess.run(["dpkg-query", "-W", "-f", "${binary:Package}\t${Version}\t${Architecture}\n"], capture_output=True, text=True, timeout=20, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    release = _os_release()
    distro = f"{release.get('ID', 'debian')}-{release.get('VERSION_ID', '')}".rstrip("-")
    packages = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            name, version = parts[0].split(":")[0], parts[1]
            packages.append({"name": name, "version": version, "license": "NOASSERTION", "purl": f"pkg:deb/{release.get('ID', 'debian')}/{name}@{version}?distro={distro}"})
    return sorted(packages, key=lambda p: p["name"])


def inventory() -> dict[str, Any]:
    return {"version": _version(), "python": python_packages(), "vendored": vendored_libraries(), "os": os_packages(), "os_release": _os_release()}


# ----------------------------------------------------------------------------- CycloneDX 1.5
def _is_expression(text: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.+-]+( (AND|OR|WITH) [A-Za-z0-9.+-]+)*", (text or "").strip())) and (text or "").strip().upper() != "NOASSERTION"


def _cdx_licenses(text: str) -> list[dict[str, Any]]:
    """An SPDX expression where the declared licence is one, else the declared text as a name (never a guess), else nothing."""
    t = (text or "").strip()
    if not t or t.upper() == "NOASSERTION":
        return []
    return [{"expression": t}] if _is_expression(t) else [{"license": {"name": t[:120]}}]


def cyclonedx(inv: dict[str, Any] | None = None, now: datetime | None = None) -> dict[str, Any]:
    inv = inv or inventory()
    now = now or datetime.now(timezone.utc)
    app_ref = f"pkg:generic/{APP_NAME}@{inv['version']}"
    components: list[dict[str, Any]] = []
    for p in inv["python"]:
        components.append({"type": "library", "bom-ref": p["purl"], "name": p["name"], "version": p["version"], "purl": p["purl"],
                           "licenses": _cdx_licenses(p["license"]),
                           "properties": [{"name": "netlens:scope", "value": "direct" if p["direct"] else "transitive"}, {"name": "netlens:ecosystem", "value": "python"}]})
    for v in inv["vendored"]:
        components.append({"type": "library", "bom-ref": f"{v['purl']}#{v['file']}", "name": v["name"], "version": v["version"], "purl": v["purl"],
                           "licenses": _cdx_licenses(v["license"]), "hashes": [{"alg": "SHA-256", "content": v["sha256"]}],
                           "properties": [{"name": "netlens:ecosystem", "value": "browser (vendored)"}, {"name": "netlens:file", "value": f"app/static/vendor/{v['file']}"}]})
    for o in inv["os"]:
        components.append({"type": "library", "bom-ref": o["purl"], "name": o["name"], "version": o["version"], "purl": o["purl"], "properties": [{"name": "netlens:ecosystem", "value": "operating system"}]})
    release = inv["os_release"]
    if release.get("PRETTY_NAME"):
        components.append({"type": "operating-system", "bom-ref": "os", "name": release.get("ID", "linux"), "version": release.get("VERSION_ID", ""), "description": release["PRETTY_NAME"]})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "tools": {"components": [{"type": "application", "name": "netlens-sbom", "version": inv["version"]}]},
                     "component": {"type": "application", "bom-ref": app_ref, "name": APP_NAME, "version": inv["version"], "purl": app_ref, "licenses": [{"license": {"id": LICENSE_ID}}],
                                   "supplier": {"name": "Netlens"}, "properties": [{"name": "netlens:python", "value": platform.python_version()}]}},
        "components": components,
        "dependencies": [{"ref": app_ref, "dependsOn": [c["bom-ref"] for c in components if c["type"] == "library"]}],
    }


# ----------------------------------------------------------------------------- SPDX 2.3
def _spdx_id(text: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]+", "-", text).strip("-")[:120]


def spdx(inv: dict[str, Any] | None = None, now: datetime | None = None) -> dict[str, Any]:
    inv = inv or inventory()
    now = now or datetime.now(timezone.utc)
    root = "SPDXRef-Netlens"
    packages: list[dict[str, Any]] = [{"SPDXID": root, "name": APP_NAME, "versionInfo": inv["version"], "downloadLocation": "https://github.com/Gatlarf/netlens", "filesAnalyzed": False,
                                       "licenseConcluded": "NOASSERTION", "licenseDeclared": "LicenseRef-PolyForm-Noncommercial-1.0.0", "supplier": "Organization: Netlens",
                                       "primaryPackagePurpose": "APPLICATION", "copyrightText": "NOASSERTION"}]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root}]
    seen: set[str] = set()

    def add(name: str, version: str, purl: str, licence: str, extra: dict[str, Any] | None = None) -> None:
        sid = _spdx_id(f"{name}-{version}")
        if sid in seen:
            sid = _spdx_id(f"{name}-{version}-{len(seen)}")
        seen.add(sid)
        entry = {"SPDXID": sid, "name": name, "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
                 "licenseDeclared": licence if licence and licence != "NOASSERTION" else "NOASSERTION", "copyrightText": "NOASSERTION",
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]}
        entry.update(extra or {})
        packages.append(entry)
        relationships.append({"spdxElementId": root, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": sid})

    for p in inv["python"]:
        add(p["name"], p["version"], p["purl"], _spdx_expression(p["license"]))
    for v in inv["vendored"]:
        add(v["name"], v["version"], v["purl"], _spdx_expression(v["license"]), {"checksums": [{"algorithm": "SHA256", "checksumValue": v["sha256"]}]})
    for o in inv["os"]:
        add(o["name"], o["version"], o["purl"], "NOASSERTION")
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": f"netlens-{inv['version']}",
            "documentNamespace": f"https://github.com/Gatlarf/netlens/spdx/{inv['version']}/{uuid.uuid4()}",
            "creationInfo": {"created": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": [f"Tool: netlens-sbom-{inv['version']}"]},
            "hasExtractedLicensingInfos": [{"licenseId": "LicenseRef-PolyForm-Noncommercial-1.0.0", "name": "PolyForm Noncommercial License 1.0.0",
                                            "extractedText": "https://polyformproject.org/licenses/noncommercial/1.0.0/"}],
            "packages": packages, "relationships": relationships}


def _spdx_expression(text: str) -> str:
    """A declared licence as an SPDX expression where it already is one; otherwise NOASSERTION (never a guess)."""
    return (text or "").strip() if _is_expression(text) else "NOASSERTION"


def render(fmt: str = "cyclonedx") -> dict[str, Any]:
    if fmt in ("cyclonedx", "cdx"):
        return cyclonedx()
    if fmt == "spdx":
        return spdx()
    raise ValueError("format must be cyclonedx or spdx")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m app.sbom", description="Print the software bill of materials of this installation (JSON).")
    parser.add_argument("--format", choices=("cyclonedx", "spdx"), default="cyclonedx")
    args = parser.parse_args(argv)
    json.dump(render(args.format), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
