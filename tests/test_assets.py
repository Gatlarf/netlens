"""Versioned, long-cached interface files (app/assets.py)."""

import re

import pytest
from fastapi.testclient import TestClient

from app import assets
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(assets, "VERSION", "9.9.9")
    assets._PAGES.clear()
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    with TestClient(app) as tc:
        yield tc
    assets._PAGES.clear()


def test_the_page_points_at_versioned_addresses_and_preloads_the_scripts(client):
    r = client.get("/")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-cache" and r.headers["etag"]
    html = r.text
    assert 'src="v/9.9.9/js/app.js"' in html and 'href="v/9.9.9/css/app.css"' in html and 'href="v/9.9.9/img/favicon.svg"' in html
    assert 'href="manifest.webmanifest"' in html and 'href="favicon.ico"' in html          # these stay where browsers and the service worker expect them
    preload = re.findall(r'rel="modulepreload" href="v/9.9.9/(js/[^"]+)"', html)
    assert "js/app.js" in preload and "js/pages/dashboard.js" in preload and len(preload) == len(set(preload)) > 10
    assert all(client.get(f"/v/9.9.9/{p}").status_code == 200 for p in preload)            # everything it announces exists


def test_the_page_is_revalidated_with_its_etag(client):
    r = client.get("/")
    again = client.get("/", headers={"If-None-Match": r.headers["etag"]})
    assert again.status_code == 304 and again.content == b""
    assert client.get("/index.html").text == r.text


def test_files_of_the_current_version_are_cached_for_a_year_and_other_files_are_not(client):
    cached = client.get("/v/9.9.9/js/app.js")
    assert cached.status_code == 200 and cached.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert "cloudflare-cdn-cache-control" not in cached.headers
    assert client.get("/v/9.9.9/css/app.css").headers["cache-control"] == assets.IMMUTABLE
    old = client.get("/v/9.9.8/js/app.js")                                                 # a tab opened before an update still finds its scripts
    assert old.status_code == 200 and old.headers["cache-control"] == "no-cache" and old.text == cached.text
    missing = client.get("/v/9.9.9/js/nope.js")
    assert missing.status_code == 404 and "immutable" not in missing.headers["cache-control"]
    plain = client.get("/js/app.js")                                                       # the old address keeps working, revalidated
    assert plain.status_code == 200 and plain.headers["cache-control"] == "no-cache"
    assert client.get("/sw.js").headers["cache-control"] == "no-cache"
    assert "immutable" not in client.get("/api/health").headers.get("cache-control", "")


def test_api_answers_stay_uncached(client):
    r = client.get("/api/health")
    assert r.headers["cache-control"] == "no-store"


def test_a_dev_build_is_never_cached_for_long(tmp_path, monkeypatch):
    monkeypatch.setattr(assets, "VERSION", "0.2.0-dev")
    assets._PAGES.clear()
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    with TestClient(app) as tc:
        html = tc.get("/").text
        assert 'src="js/app.js"' in html and "modulepreload" not in html
        assert tc.get("/v/0.2.0-dev/js/app.js").headers["cache-control"] == "no-cache"
    assets._PAGES.clear()


def test_module_graph_follows_relative_imports(tmp_path):
    (tmp_path / "js" / "sub").mkdir(parents=True)
    (tmp_path / "js" / "a.js").write_text('import { x } from "./b.js";\nimport "./c.js";\nexport * from "./sub/d.js";\nconst m = await import("./lazy.js");\n')
    (tmp_path / "js" / "b.js").write_text('import { y } from "../js/sub/d.js";\n')
    (tmp_path / "js" / "c.js").write_text("")
    (tmp_path / "js" / "sub" / "d.js").write_text('import e from "../e.js";\n')
    (tmp_path / "js" / "e.js").write_text("")
    (tmp_path / "js" / "lazy.js").write_text("")
    assert assets.module_graph(("js/a.js",), tmp_path) == ["js/a.js", "js/b.js", "js/c.js", "js/sub/d.js", "js/e.js"]       # dynamic imports stay lazy


def test_every_static_import_resolves():
    """A script that imports a file that does not exist would break the page; the preload list must never name a missing file."""
    graph = assets.module_graph()
    assert all((assets.STATIC / p).is_file() for p in graph) and len(graph) > 10
