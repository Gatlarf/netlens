from pathlib import Path

from fastapi.testclient import TestClient

from app import changelog
from app.config import load_settings
from app.main import create_app

SAMPLE = """# Changelog

intro text

## 0.2.10 — 2026-01-02
### Added
- ★ **Big thing**: does `x`
  and wraps.
- **Small thing**: minor
### Added
- plain item
### Fixed
- ★ **A fix**: done

## 0.2.9 and earlier builds
### Changed
- **Old**: text

## 0.1.0
### Added
- first
"""


def test_parse_structure_and_order():
    releases = changelog.parse(SAMPLE)
    assert [r["version"] for r in releases] == ["0.2.10", "0.2.9", "0.1.0"]
    top = releases[0]
    assert top["date"] == "2026-01-02" and top["note"] is None
    assert [s["title"] for s in top["sections"]] == ["Added", "Fixed"]     # the second "Added" is merged
    added = top["sections"][0]["items"]
    assert [i["title"] for i in added] == ["Big thing", "Small thing", ""]
    assert added[0]["notable"] and "wraps" in added[0]["text"] and not added[1]["notable"]
    assert releases[1]["note"] == "and earlier builds" and releases[1]["date"] is None


def test_versions_compare_numerically_not_as_text():
    assert changelog.version_key("0.2.100") > changelog.version_key("0.2.99")
    assert changelog.version_key("0.2.0-dev") == (0, 2, 0)


def test_releases_between():
    releases = changelog.parse(SAMPLE)
    assert [r["version"] for r in changelog.releases_between(releases, "0.2.9", "0.2.10")] == ["0.2.10"]
    assert [r["version"] for r in changelog.releases_between(releases, "0.2.10", "0.2.10")] == []
    assert [r["version"] for r in changelog.releases_between(releases, "0.2.0", "0.2.9")] == ["0.2.9"]   # a release beyond the running one is not shown
    assert len(changelog.releases_between(releases, None, "0.2.0-dev")) == 3                              # a dev build shows all


def test_the_real_changelog_parses_and_has_notable_changes():
    releases = changelog.load()
    assert releases and releases[0]["version"] == max((r["version"] for r in releases), key=changelog.version_key)
    assert any(i["notable"] for r in releases for s in r["sections"] for i in s["items"])
    assert all(i["title"] or i["text"] for r in releases for s in r["sections"] for i in s["items"])


def test_the_image_ships_the_changelog():
    assert "CHANGELOG.md" in (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()


def test_api(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.changelog.VERSION", "0.2.96")
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer t"}) as client:
        body = client.get("/api/changelog").json()
        assert body["current"] == "0.2.96" and len(body["releases"]) >= 2
        newer = client.get("/api/changelog?since=0.2.95").json()["releases"]
        assert [r["version"] for r in newer] == ["0.2.96"]
        assert client.get("/api/changelog?since=0.2.96").json()["releases"] == []
    with TestClient(app, headers={"Authorization": "Bearer wrong"}) as anonymous:
        assert anonymous.get("/api/changelog").status_code == 401
