"""Newer-image checks: the reference parser, the registry lookup (with a token login), the cache, and the whole path through a sync."""

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import containers, imageupdates
from app.db import connect, get_or_create_device, init_db
from app.plugins.service import PluginService, save_state
from tests.plugin_helpers import fake, make_runner, write_plugin

OLD, NEW = "sha256:" + "a" * 64, "sha256:" + "b" * 64


class FakeRegistry:
    """`digests` maps 'repo:tag' to a digest. Every manifest request needs a bearer token from /token, like Docker Hub and ghcr."""

    def __init__(self, digests, auth=True):
        self.digests, self.auth, self.hits = digests, auth, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.startswith("/token"):
                    body = json.dumps({"token": "t0k"}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_HEAD(self):
                outer.hits.append(self.path)
                if outer.auth and self.headers.get("Authorization") != "Bearer t0k":
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", f'Bearer realm="http://127.0.0.1:{outer.port}/token",service="reg"')
                    self.end_headers()
                    return
                _, _, rest = self.path.partition("/v2/")
                repo, _, tag = rest.partition("/manifests/")
                digest = outer.digests.get(f"{repo}:{tag}")
                self.send_response(200 if digest else 404)
                if digest:
                    self.send_header("Docker-Content-Digest", digest)
                self.end_headers()

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.host = f"127.0.0.1:{self.port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()


def test_references_are_understood():
    p = imageupdates.parse_ref
    assert p("nginx") == ("registry-1.docker.io", "library/nginx", "latest")
    assert p("grafana/grafana:11.2") == ("registry-1.docker.io", "grafana/grafana", "11.2")
    assert p("ghcr.io/gatlarf/netlens:0.3") == ("ghcr.io", "gatlarf/netlens", "0.3")
    assert p("docker.io/library/redis:7") == ("registry-1.docker.io", "library/redis", "7")
    assert p("192.168.0.5:5000/app") == ("192.168.0.5:5000", "app", "latest")
    for skipped in ("", "nginx@" + OLD, "sha256:" + "c" * 64, "0123456789ab", "UPPER Case"):
        assert p(skipped) is None


def test_the_registry_is_asked_with_a_token_and_answers_with_a_digest():
    with FakeRegistry({"app:1": NEW}) as reg:
        assert imageupdates.fetch_digest(reg.host, "app", "1") == NEW
        with pytest.raises(OSError):
            imageupdates.fetch_digest(reg.host, "app", "missing")
    with pytest.raises(OSError):     # nothing listens there
        imageupdates.fetch_digest("127.0.0.1:9", "app", "1")


def test_answers_are_cached_and_a_failure_is_not_retried_at_once(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    calls = []

    def fetch(registry, repo, tag):
        calls.append(repo)
        if repo == "me/broken":
            raise OSError("down")
        return NEW

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert imageupdates.refresh(conn, {"me/good:1", "me/broken:1", "x@" + OLD}, fetch, now) == 2
    assert imageupdates.refresh(conn, {"me/good:1", "me/broken:1"}, fetch, now + timedelta(minutes=30)) == 0        # all fresh
    assert imageupdates.refresh(conn, {"me/good:1", "me/broken:1"}, fetch, now + timedelta(hours=2)) == 1             # the failure is retried after an hour
    assert imageupdates.refresh(conn, {"me/good:1", "me/broken:1"}, fetch, now + timedelta(hours=7)) == 2             # the good answer after six
    assert sorted(calls) == ["me/broken"] * 3 + ["me/good"] * 2
    assert imageupdates.refresh(conn, {"me/good:1"}, fetch, now + timedelta(hours=7, minutes=1)) == 0
    imageupdates.refresh(conn, {"me/good:1"}, fetch, now + timedelta(hours=9))
    assert "me/broken" not in json.dumps(imageupdates._load(conn))          # forgotten once no container uses it


def guest(name, image, digest, **extra):
    return {"id": name, "name": name, "kind": "container", "host_id": "h", "status": "running", "details": {"image": image, "image_digest": digest, **extra}}


def test_annotate_marks_only_containers_with_a_different_digest(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    imageupdates.refresh(conn, {"me/app:1", "me/same:1"}, lambda r, repo, t: NEW if repo == "me/app" else OLD, datetime.now(timezone.utc))
    guests = [guest("a", "me/app:1", OLD), guest("b", "me/same:1", OLD), guest("c", "me/unknown:1", OLD), guest("d", "me/app:1", ""), {"id": "vm", "name": "vm", "kind": "qemu", "details": {}}]
    assert imageupdates.annotate(conn, guests) == 1
    assert guests[0]["details"]["update_available"] and guests[0]["details"]["image_checked"]
    assert guests[1]["details"]["image_checked"] and "update_available" not in guests[1]["details"]
    assert "image_checked" not in guests[2]["details"] and "image_checked" not in guests[3]["details"]


def test_the_event_comes_only_once_the_container_was_judged_before():
    guests = [guest("a", "app:1", OLD, update_available=True, image_checked=True)]
    unjudged = {"a": {"status": "running", "health": None, "restarts": None, "update": False, "checked": False}}
    judged = {"a": {"status": "running", "health": None, "restarts": None, "update": False, "checked": True}}
    already = {"a": {"status": "running", "health": None, "restarts": None, "update": True, "checked": True}}
    assert containers.changes(unjudged, guests, {"h": "docker1"}) == []
    assert containers.changes(already, guests, {"h": "docker1"}) == []
    [(kind, text, _)] = containers.changes(judged, guests, {"h": "docker1"})
    assert kind == "guest_update_available" and "newer image" in text and "a on docker1" in text


def test_summary_counts_container_image_updates(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    for gid, upd in (("a", True), ("b", False)):
        conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, macs, ips, updated, details) VALUES ('docker', ?, ?, 'container', 'h', 'running', '[]', '[]', 'x', ?)",
                     (gid, gid, json.dumps({"update_available": upd})))
    summary = containers.guest_summary(conn)
    assert summary["image_updates"] == 1 and summary["update_available"] == 1
    assert summary["attention"][0]["why"] == "newer image available"


@pytest.mark.asyncio
async def test_a_sync_asks_the_registry_and_flags_the_container_only_when_switched_on(tmp_path, monkeypatch):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.5")
    conn.close()
    write_plugin(tmp_path, "dock", "hypervisor", manifest={"config": [{"key": "check_image_updates", "type": "bool", "label": "x", "default": False}]})
    output = {"hosts": [{"id": "h", "name": "docker1", "ip": "10.0.0.5"}], "guests": [guest("web", "me/app:1", OLD)]}
    asked = []
    monkeypatch.setattr(imageupdates, "fetch_digest", lambda registry, repo, tag: asked.append(repo) or NEW)
    svc = PluginService(str(path), tmp_path, make_runner(dock=fake(fetch=lambda cfg: json.loads(json.dumps(output)))))

    def details():
        c = connect(path)
        try:
            return json.loads(c.execute("SELECT details FROM hypervisor_guests WHERE guest_id = 'web'").fetchone()[0])
        finally:
            c.close()

    def enable(on):
        c = connect(path)
        save_state(c, "dock", True, {"check_image_updates": on})
        c.close()

    enable(False)
    await svc.sync("dock")
    assert asked == [] and "update_available" not in details()
    enable(True)
    await svc.sync("dock")
    assert asked == ["me/app"] and details()["update_available"] is True and details()["image_checked"] is True
    await svc.sync("dock")
    assert asked == ["me/app"]          # cached
    c = connect(path)
    kinds = [r[0] for r in c.execute("SELECT kind FROM events")]
    c.close()
    assert kinds.count("guest_update_available") == 0          # the first verdict is not news
