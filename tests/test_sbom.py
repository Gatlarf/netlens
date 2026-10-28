"""The software bill of materials: what it must contain, that it stays honest when a library is added, and who may fetch it."""

import hashlib
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import sbom
from app.config import load_settings
from app.main import create_app
from app.version import VERSION

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def inv():
    return sbom.inventory()


def test_cyclonedx_has_the_required_shape_and_the_application(inv):
    doc = sbom.cyclonedx(inv)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5" and doc["serialNumber"].startswith("urn:uuid:") and doc["version"] == 1
    app = doc["metadata"]["component"]
    assert app["name"] == "netlens" and app["version"] == VERSION and app["purl"] == f"pkg:generic/netlens@{VERSION}"
    assert app["licenses"][0]["license"]["id"] == "PolyForm-Noncommercial-1.0.0"
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))                                                   # a reference is unique
    assert doc["dependencies"][0]["ref"] == app["bom-ref"] and set(doc["dependencies"][0]["dependsOn"]) <= set(refs)


def test_the_python_packages_are_listed_with_purls_and_declared_licences(inv):
    names = {p["name"].lower(): p for p in inv["python"]}
    for must in ("fastapi", "cryptography", "uvicorn", "asyncssh", "h11"):
        assert must in names, must
    assert names["fastapi"]["purl"] == f"pkg:pypi/fastapi@{names['fastapi']['version']}" and names["fastapi"]["direct"] is True
    assert names["h11"]["license"] not in ("", None)
    assert all(re.fullmatch(r"pkg:pypi/[a-z0-9-]+@\S+", p["purl"]) for p in inv["python"])


def test_every_vendored_browser_library_is_in_the_bill_with_the_hash_of_its_file(inv):
    vendor = ROOT / "app" / "static" / "vendor"
    listed = {v["file"] for v in inv["vendored"]}
    on_disk = {p.name for p in vendor.iterdir() if p.is_file()}
    assert on_disk == listed, f"add the new file to VENDORED in app/sbom.py (and the README list): {sorted(on_disk ^ listed)}"
    for v in inv["vendored"]:
        assert v["sha256"] == hashlib.sha256((vendor / v["file"]).read_bytes()).hexdigest() and v["version"] and v["license"]
    assert {"qrcode-generator", "xterm", "vis-network", "guacamole-common-js"} <= {v["name"] for v in inv["vendored"]}
    doc = sbom.cyclonedx(inv)
    comp = next(c for c in doc["components"] if c["name"] == "qrcode-generator")
    assert comp["hashes"][0]["alg"] == "SHA-256" and comp["purl"] == "pkg:npm/qrcode-generator@1.4.4"


def test_the_readme_names_every_vendored_library_and_the_licence_text_is_kept():
    readme = (ROOT / "README.md").read_text()
    for name in ("vis-network", "xterm", "guacamole-common-js", "qrcode-generator"):
        assert name in readme[readme.index("## Third-party"):], name
    assert (ROOT / "licenses" / "MIT-qrcode-generator.txt").read_text().startswith("MIT License")


def test_spdx_is_well_formed(inv):
    doc = sbom.spdx(inv)
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["SPDXID"] == "SPDXRef-DOCUMENT" and doc["dataLicense"] == "CC0-1.0"
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids)) and all(re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", i) for i in ids)
    assert doc["relationships"][0] == {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Netlens"}
    assert {r["relatedSpdxElement"] for r in doc["relationships"][1:]} <= set(ids)
    assert any(p.get("checksums") for p in doc["packages"])
    for p in doc["packages"]:                                                             # a licence is an SPDX expression or NOASSERTION, never a guess in prose
        assert " License" not in p["licenseDeclared"] or p["licenseDeclared"].startswith("LicenseRef-")


def test_the_licence_helpers_never_invent_a_licence():
    assert sbom._cdx_licenses("MIT") == [{"expression": "MIT"}]
    assert sbom._cdx_licenses("Apache-2.0 OR MIT") == [{"expression": "Apache-2.0 OR MIT"}]
    assert sbom._cdx_licenses("MIT License") == [{"license": {"name": "MIT License"}}]
    assert sbom._cdx_licenses("NOASSERTION") == [] and sbom._cdx_licenses("") == []
    assert sbom._spdx_expression("MIT License") == "NOASSERTION" and sbom._spdx_expression("MIT") == "MIT"


def test_the_command_prints_json(capsys):
    assert sbom.main(["--format", "spdx"]) == 0
    assert json.loads(capsys.readouterr().out)["spdxVersion"] == "SPDX-2.3"
    assert sbom.main([]) == 0
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"


def test_only_an_administrator_can_fetch_it(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    admin = {"Authorization": "Bearer secret"}
    with TestClient(app) as c:
        assert c.get("/api/sbom").status_code == 401
        r = c.get("/api/sbom", headers=admin)
        assert r.status_code == 200 and r.json()["bomFormat"] == "CycloneDX" and "attachment" in r.headers["content-disposition"] and r.headers["cache-control"] == "no-store"
        assert c.get("/api/sbom?format=spdx", headers=admin).json()["spdxVersion"] == "SPDX-2.3"
        assert c.get("/api/sbom?format=xml", headers=admin).status_code == 422
        assert c.post("/api/users", json={"username": "viola", "password": "longenough1", "role": "viewer"}, headers=admin).status_code == 201
        viewer = TestClient(app)
        assert viewer.post("/api/login", json={"username": "viola", "password": "longenough1"}).status_code == 200
        assert viewer.get("/api/sbom").status_code == 403
