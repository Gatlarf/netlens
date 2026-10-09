import hashlib
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins import index as idx
from app.plugins import index_install as inst
from app.plugins.index import OFFICIAL_URL, PluginIndexError, download_release, get_index, incompatible_reason, is_newer, parse_index, pick_release, version_tuple, view
from app.plugins.registry import InstallError, discover
from app.plugins.service import get_state, save_state

AUTH = {"Authorization": "Bearer secret"}
PY = "def test(config):\n    return {'message': 'ok'}\ndef fetch(config):\n    return {'nodes': [], 'clients': []}\n"
CUSTOM = "https://index.example/index.json"


def make_zip(plugin_id="omada", version="1.0.0", kind="topology", **manifest):
    data = {"id": plugin_id, "name": plugin_id.title(), "version": version, "api_version": 1, "kind": kind,
            "config": [{"key": "host", "type": "text", "label": "Host", "required": True}], **manifest}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("plugin.json", json.dumps(data))
        z.writestr("plugin.py", PY)
    return buf.getvalue()


def release(zip_bytes, version="1.0.0", level="community", url=None, **extra):
    r = {"version": version, "download_url": url or f"https://github.com/x/omada/releases/download/v{version}/omada.zip", "sha256": hashlib.sha256(zip_bytes).hexdigest(),
         "api_version": 1, "released": "2026-10-09", "review": {"level": level, "reviewer": "bert" if level != "community" else "", "tested_on": ["OC200"] if level == "verified" else []}, **extra}
    return r


def entry(plugin_id="omada", releases=(), **extra):
    return {"id": plugin_id, "name": plugin_id.title(), "kind": "topology", "description": "d", "author": "a", "releases": list(releases), **extra}


def index_doc(*entries):
    return {"schema": 1, "plugins": list(entries)}


class Server:
    """A fake network: url -> bytes; counts requests and records headers."""

    def __init__(self):
        self.files, self.calls, self.fail = {}, [], None

    def put_index(self, doc, url=OFFICIAL_URL, etag='"v1"'):
        self.files[url] = (json.dumps(doc).encode(), etag)

    def put_zip(self, data, url):
        self.files[url] = (data, None)

    def __call__(self, url, *, max_bytes, headers=None, timeout=20.0):
        self.calls.append((url, headers or {}))
        if self.fail:
            raise PluginIndexError(self.fail)
        if url not in self.files:
            raise PluginIndexError("the server answered HTTP 404")
        body, etag = self.files[url]
        if headers and etag and headers.get("If-None-Match") == etag:
            return 304, b"", {}
        return 200, body[: max_bytes + 1], {"ETag": etag} if etag else {}


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    return c


# ------------------------------------------------------------------ versions and parsing
def test_versions():
    assert version_tuple("1.2.3") == (1, 2, 3) and version_tuple("0.2.0-dev") == (0, 2, 0) and version_tuple(None) == (0,) and version_tuple("junk") == (0,)
    assert is_newer("1.10.0", "1.9.9") and is_newer("1.0.1", "1.0") and not is_newer("1.0.0", "1.0") and not is_newer("0.9", "1.0")


def test_parse_skips_bad_entries_but_keeps_the_good_ones():
    z = make_zip()
    good = entry(releases=[release(z, "1.0.0"), release(z, "1.10.0"), release(z, "1.2.0")])
    doc = index_doc(
        good,
        entry("builtin1", builtin=True, kind="hypervisor"),  # built-in entries need no release
        entry("norelease"),  # nothing to install
        entry("Bad Id", releases=[release(z)]),
        entry("badkind", releases=[release(z)], kind="toaster"),
        {**entry("nohash", releases=[{"version": "1.0.0", "download_url": "https://github.com/x.zip"}])},
        entry("http", releases=[release(z, url="http://github.com/x.zip")]),
        "not an object",
        entry("omada", releases=[release(z)]),  # duplicate id
    )
    entries, skipped = parse_index(doc)
    assert [e["id"] for e in entries] == ["omada", "builtin1"] and skipped == 7
    assert [r["version"] for r in entries[0]["releases"]] == ["1.10.0", "1.2.0", "1.0.0"]  # newest first, numerically
    assert entries[1]["builtin"] is True and entries[1]["releases"] == []


def test_the_official_index_may_only_point_at_github():
    z = make_zip()
    doc = index_doc(entry("aa", releases=[release(z, url="https://evil.example/a.zip")]), entry("bb", releases=[release(z, url="https://objects.githubusercontent.com/b.zip")]))
    assert [e["id"] for e in parse_index(doc, official=True)[0]] == ["bb"]
    assert [e["id"] for e in parse_index(doc, official=False)[0]] == ["aa", "bb"]  # a custom index may use any https host


def test_wrong_format_is_refused_and_text_is_bounded():
    for bad in ([], {"schema": 2, "plugins": []}, {"schema": 1}, {"schema": 1, "plugins": "x"}):
        with pytest.raises(PluginIndexError, match="not a Netlens plugin index"):
            parse_index(bad)
    z = make_zip()
    e = parse_index(index_doc(entry(releases=[release(z)], description="x" * 5000, homepage="http://insecure.example", supports=["a"] * 100)))[0][0]
    assert len(e["description"]) == 500 and e["homepage"] == "" and len(e["supports"]) == 30


def test_review_levels_default_to_community():
    z = make_zip()
    rel = release(z)
    rel["review"] = {"level": "gold-plated", "reviewer": "x"}
    e = parse_index(index_doc(entry(releases=[rel])))[0][0]
    assert e["releases"][0]["review"]["level"] == "community" and e["releases"][0]["review"]["reviewer"] == ""


# ------------------------------------------------------------------ fetching and caching
def test_index_is_cached_refreshed_and_falls_back_to_the_old_copy(conn):
    z = make_zip()
    server = Server()
    server.put_index(index_doc(entry(releases=[release(z)])))
    first = get_index(conn, getter=server, now="2026-03-10T12:00:00Z")
    assert [e["id"] for e in first["entries"]] == ["omada"] and first["fetched"] == "2026-03-10T12:00:00Z" and not first["stale"] and first["error"] is None
    get_index(conn, getter=server, now="2026-03-10T13:00:00Z")
    assert len(server.calls) == 1  # inside six hours: from the cache
    get_index(conn, getter=server, now="2026-03-10T19:00:00Z")
    assert len(server.calls) == 2 and server.calls[1][1].get("If-None-Match") == '"v1"'  # old enough: asks again, politely (304)
    forced = get_index(conn, force=True, getter=server, now="2026-03-10T19:05:00Z")
    assert len(server.calls) == 3 and forced["entries"]
    server.fail = "cannot reach the server (timed out)"
    down = get_index(conn, force=True, getter=server, now="2026-03-10T20:00:00Z")
    assert down["stale"] is True and down["error"] and [e["id"] for e in down["entries"]] == ["omada"]  # still usable


def test_no_cache_and_no_server_is_an_error_not_a_crash(conn):
    server = Server()
    server.fail = "cannot reach the server (timed out)"
    r = get_index(conn, getter=server)
    assert r["entries"] == [] and "cannot reach" in r["error"] and not r["stale"]


def test_bad_files(conn):
    server = Server()
    server.files[OFFICIAL_URL] = (b"<html>", None)
    assert "not valid JSON" in get_index(conn, getter=server)["error"]
    server.files[OFFICIAL_URL] = (b'{"schema": 9}', None)
    assert "not a Netlens plugin index" in get_index(conn, getter=server)["error"]
    server.files[OFFICIAL_URL] = (b"x" * (idx.MAX_INDEX_BYTES + 5), None)
    assert "too large" in get_index(conn, getter=server)["error"]


def test_settings_disable_and_custom_url(conn):
    server = Server()
    z = make_zip()
    server.put_index(index_doc(entry("official", releases=[release(z)])))
    server.put_index(index_doc(entry("custom", releases=[release(z, url="https://elsewhere.example/c.zip")])), url=CUSTOM)
    assert idx.save_settings(conn, True, CUSTOM) == {"enabled": True, "url": CUSTOM}
    assert [e["id"] for e in get_index(conn, getter=server)["entries"]] == ["custom"]  # the cache of another url is not reused
    idx.save_settings(conn, False, CUSTOM)
    server.calls.clear()
    assert get_index(conn, getter=server)["entries"] == [] and server.calls == []
    with pytest.raises(ValueError, match="https"):
        idx.save_settings(conn, True, "http://insecure.example/i.json")
    assert idx.save_settings(conn, True, "")["url"] == OFFICIAL_URL


# ------------------------------------------------------------------ compatibility and download
def test_compatibility():
    z = make_zip()
    old = parse_index(index_doc(entry(releases=[release(z, "2.0.0", min_netlens="0.9.0"), release(z, "1.0.0", min_netlens="0.2.0"), release(z, "0.5.0", api_version=2)])))[0][0]
    assert incompatible_reason(old["releases"][0], "0.2.44") == "needs Netlens 0.9.0 or newer (you have 0.2.44)"
    assert "plugin API version 2" in incompatible_reason(old["releases"][2], "0.2.44")
    best, _ = pick_release(old, "0.2.44")
    assert best["version"] == "1.0.0"  # newest one this Netlens can run
    assert pick_release(old, "0.9.1")[0]["version"] == "2.0.0"
    assert pick_release(old, "0.2.44", "2.0.0")[0] is None and "0.9.0" in pick_release(old, "0.2.44", "2.0.0")[1]
    assert pick_release(old, "0.2.44", "9.9.9")[1] == "version 9.9.9 is not in the index"
    only_new = parse_index(index_doc(entry(releases=[release(z, "2.0.0", min_netlens="0.9.0")])))[0][0]
    assert pick_release(only_new, "0.2.44")[0] is None


def test_download_verifies_the_checksum_and_size():
    z = make_zip()
    server = Server()
    rel = parse_index(index_doc(entry(releases=[release(z)])))[0][0]["releases"][0]
    server.put_zip(z, rel["download_url"])
    assert download_release(rel, getter=server) == z
    server.put_zip(z + b"tampered", rel["download_url"])
    with pytest.raises(PluginIndexError, match="does not match the checksum"):
        download_release(rel, getter=server)
    server.put_zip(b"x" * (3 * 1024 * 1024), rel["download_url"])
    with pytest.raises(PluginIndexError, match="too large"):
        download_release(rel, getter=server)


# ------------------------------------------------------------------ installing
@pytest.fixture
def world(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    server = Server()
    return conn, tmp_path, server


def publish(server, version="1.0.0", level="community", plugin_id="omada", **zip_kwargs):
    z = make_zip(plugin_id, version, **zip_kwargs)
    rel = release(z, version, level, url=f"https://github.com/x/{plugin_id}/releases/download/v{version}/{plugin_id}.zip")
    server.put_zip(z, rel["download_url"])
    return rel


def entry_of(*rels, plugin_id="omada"):
    return parse_index(index_doc(entry(plugin_id, releases=list(rels))))[0][0]


def test_install_starts_off_keeps_provenance_and_a_copy(world):
    conn, tmp, server = world
    rel = publish(server, level="verified")
    e = entry_of(rel)
    out = inst.install_release(conn, tmp, e, e["releases"][0], getter=server, index_url=OFFICIAL_URL)
    assert out == {"id": "omada", "version": "1.0.0", "replaced": False, "level": "verified"}
    p = discover(tmp)["omada"]
    assert p.problem is None and p.manifest["version"] == "1.0.0"
    assert get_state(conn, p)["enabled"] is False
    info = inst.provenance(conn, "omada")
    assert info["source"] == "index" and info["level"] == "verified" and info["sha256"] == rel["sha256"] and info["reviewer"] == "bert"
    assert [v for v, _ in inst.backups(tmp, "omada")] == ["1.0.0"]
    state = inst.installed_map(conn, discover(tmp), tmp)["omada"]
    assert state["version"] == "1.0.0" and state["source"] == "index" and state["level"] == "verified" and state["can_rollback"] is False


def test_update_keeps_the_settings_and_rollback_restores_the_old_version(world):
    conn, tmp, server = world
    r1 = publish(server, "1.0.0")
    e1 = entry_of(r1)
    inst.install_release(conn, tmp, e1, e1["releases"][0], getter=server)
    p = discover(tmp)["omada"]
    save_state(conn, "omada", True, {"host": "10.0.0.1"})
    r2 = publish(server, "1.1.0", level="reviewed")
    e2 = entry_of(r2, r1)
    out = inst.install_release(conn, tmp, e2, e2["releases"][0], getter=server)
    assert out["replaced"] is True
    p = discover(tmp)["omada"]
    assert p.manifest["version"] == "1.1.0" and get_state(conn, p) == {"enabled": True, "config": {"host": "10.0.0.1"}}  # still on, same settings
    assert inst.installed_map(conn, discover(tmp), tmp)["omada"]["can_rollback"] is True
    back = inst.rollback(conn, tmp, "omada")
    assert back == {"id": "omada", "version": "1.0.0", "from": "1.1.0"}
    p = discover(tmp)["omada"]
    assert p.manifest["version"] == "1.0.0" and get_state(conn, p)["config"]["host"] == "10.0.0.1"
    assert inst.provenance(conn, "omada")["source"] == "rollback"


def test_only_the_newest_backups_are_kept(world):
    conn, tmp, server = world
    for i in range(5):
        inst.remember_zip(tmp, "omada", f"1.0.{i}", make_zip(version=f"1.0.{i}"))
    assert len(inst.backups(tmp, "omada")) == inst.KEEP_BACKUPS


def test_rollback_needs_an_earlier_version(world):
    conn, tmp, server = world
    r = publish(server)
    e = entry_of(r)
    inst.install_release(conn, tmp, e, e["releases"][0], getter=server)
    with pytest.raises(InstallError, match="no earlier version"):
        inst.rollback(conn, tmp, "omada")
    with pytest.raises(InstallError, match="only installed"):
        inst.rollback(conn, tmp, "proxmox")


@pytest.mark.parametrize("zip_kwargs,message", [
    ({"plugin_id": "other"}, "not 'omada'"),
    ({"version": "9.9.9"}, "says version 9.9.9"),
    ({"kind": "hypervisor"}, "type in the download"),
])
def test_a_download_that_does_not_match_its_index_entry_is_refused(world, zip_kwargs, message):
    conn, tmp, server = world
    z = make_zip(**{"plugin_id": "omada", "version": "1.0.0", **zip_kwargs})
    rel = release(z, "1.0.0", url="https://github.com/x/omada/releases/download/v1.0.0/omada.zip")
    server.put_zip(z, rel["download_url"])
    e = entry_of(rel)
    with pytest.raises(InstallError, match=message):
        inst.install_release(conn, tmp, e, e["releases"][0], getter=server)
    assert "omada" not in discover(tmp) and not (tmp / "plugins").exists()


def test_builtin_ids_cannot_be_installed_from_the_index(world):
    conn, tmp, server = world
    z = make_zip("proxmox", kind="hypervisor")
    rel = release(z, url="https://github.com/x/p.zip")
    server.put_zip(z, rel["download_url"])
    e = entry_of(rel, plugin_id="proxmox")
    with pytest.raises(InstallError, match="built in"):
        inst.install_release(conn, tmp, e, e["releases"][0], getter=server)


def test_view_flags_updates_and_builtins(world):
    conn, tmp, server = world
    r1 = publish(server, "1.0.0")
    e1 = entry_of(r1)
    inst.install_release(conn, tmp, e1, e1["releases"][0], getter=server)
    r2 = publish(server, "1.2.0", level="verified")
    entries = [entry_of(r2, r1), parse_index(index_doc(entry("proxmox", builtin=True, kind="hypervisor")))[0][0]]
    rows = {r["id"]: r for r in view(entries, inst.installed_map(conn, discover(tmp), tmp), "0.2.44")}
    assert rows["omada"]["update_available"] is True and rows["omada"]["installed_version"] == "1.0.0" and rows["omada"]["latest"]["version"] == "1.2.0"
    assert rows["omada"]["latest"]["review"]["level"] == "verified"
    assert rows["proxmox"]["builtin"] is True and rows["proxmox"]["installed"] is True and rows["proxmox"]["update_available"] is False
    assert list(rows)[0] == "omada"  # updates first
    only_v2 = view([entry_of(r2)], {"omada": {"version": "1.2.0", "builtin": False, "source": "index"}}, "0.2.44")
    assert only_v2[0]["update_available"] is False


# ------------------------------------------------------------------ API
@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    server = Server()
    app.state.index_getter = server
    with TestClient(app, headers=AUTH) as tc:
        tc.server, tc.tmp = server, tmp_path
        yield tc


def test_api_browse_install_update_rollback(client):
    s = client.server
    r1 = publish(s, "1.0.0", level="community")
    s.put_index(index_doc(entry("omada", releases=[r1]), entry("proxmox", builtin=True, kind="hypervisor", name="Proxmox VE")))
    body = client.get("/api/plugin-index").json()
    assert body["index"]["error"] is None and body["updates"] == 0 and set(body["levels"]) == {"verified", "reviewed", "community"}
    assert {p["id"]: (p["installed"], p["builtin"]) for p in body["plugins"]} == {"omada": (False, False), "proxmox": (True, True)}

    r = client.post("/api/plugin-index/omada/install", json={})
    assert r.status_code == 409 and "has not been reviewed" in r.json()["detail"]  # community needs a confirmation
    ok = client.post("/api/plugin-index/omada/install", json={"accept_risk": True})
    assert ok.status_code == 200 and ok.json()["version"] == "1.0.0"
    assert client.get("/api/plugins/omada").json()["enabled"] is False

    r2 = publish(s, "1.1.0", level="verified")
    s.put_index(index_doc(entry("omada", releases=[r2, r1])), etag='"v2"')
    assert client.get("/api/plugin-index").json()["updates"] == 0  # still the cached copy
    body = client.get("/api/plugin-index", params={"refresh": "true"}).json()
    assert body["updates"] == 1 and body["plugins"][0]["update_available"] is True
    done = client.post("/api/plugin-index/omada/install", json={})  # a verified release needs no confirmation
    assert done.status_code == 200 and done.json()["replaced"] is True
    assert client.get("/api/plugins/omada").json()["manifest"]["version"] == "1.1.0"
    assert client.get("/api/plugin-index").json()["plugins"][0]["can_rollback"] is True
    assert client.post("/api/plugin-index/omada/rollback").json()["version"] == "1.0.0"


def test_api_errors(client):
    s = client.server
    assert client.post("/api/plugin-index/nothing/install", json={}).status_code == 404
    r = publish(s, "1.0.0", level="verified")
    r["sha256"] = "0" * 64
    s.put_index(index_doc(entry("omada", releases=[r])))
    bad = client.post("/api/plugin-index/omada/install", json={})
    assert bad.status_code == 502 and "checksum" in bad.json()["detail"]
    assert client.post("/api/plugin-index/omada/install", json={"version": "7.0.0"}).status_code == 422
    assert client.post("/api/plugin-index/omada/rollback").status_code == 422
    s.fail = "cannot reach the server (timed out)"
    down = client.get("/api/plugin-index", params={"refresh": "true"}).json()
    assert down["index"]["stale"] is True and "cannot reach" in down["index"]["error"] and down["plugins"]  # old copy still usable


def test_api_settings_and_auth(client):
    assert client.get("/api/plugin-index/settings").json() == {"enabled": True, "url": OFFICIAL_URL, "official_url": OFFICIAL_URL}
    assert client.put("/api/plugin-index/settings", json={"enabled": True, "url": CUSTOM}).json()["url"] == CUSTOM
    assert client.put("/api/plugin-index/settings", json={"enabled": True, "url": "http://x"}).status_code == 422
    off = client.put("/api/plugin-index/settings", json={"enabled": False}).json()
    assert off["enabled"] is False and client.get("/api/plugin-index").json()["plugins"] == []
    bad = {"Authorization": "Bearer no"}
    for method, url in (("get", "/api/plugin-index"), ("put", "/api/plugin-index/settings"), ("post", "/api/plugin-index/x/install"), ("post", "/api/plugin-index/x/rollback")):
        assert getattr(client, method)(url, headers=bad, **({"json": {}} if method in ("put", "post") else {})).status_code == 401


def test_a_manual_upload_is_remembered_for_rollback(client):
    z1, z2 = make_zip("manual", "1.0.0"), make_zip("manual", "1.1.0")
    for z, params in ((z1, {}), (z2, {"replace": "true"})):
        assert client.post("/api/plugins", content=z, headers={"Content-Type": "application/zip"}, params=params).status_code == 200
    assert client.post("/api/plugin-index/manual/rollback").json()["version"] == "1.0.0"


def test_offline_only_uses_what_is_cached(conn):
    server = Server()
    z = make_zip()
    server.put_index(index_doc(entry(releases=[release(z)])))
    assert get_index(conn, getter=server, offline=True)["entries"] == [] and server.calls == []  # nothing cached: no request either
    get_index(conn, getter=server, now="2026-03-10T12:00:00Z")
    n = len(server.calls)
    old = get_index(conn, getter=server, offline=True, now="2026-04-10T12:00:00Z")  # a month later: still no request
    assert [e["id"] for e in old["entries"]] == ["omada"] and len(server.calls) == n


def test_api_cache_only(client):
    s = client.server
    s.put_index(index_doc(entry("omada", releases=[publish(s, "1.0.0", "verified")])))
    assert client.get("/api/plugin-index", params={"cache_only": "true"}).json()["plugins"] == []
    assert s.calls == []
    client.get("/api/plugin-index")
    assert len(client.get("/api/plugin-index", params={"cache_only": "true"}).json()["plugins"]) == 1
