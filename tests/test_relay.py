"""Looking at a remote site through the central Netlens: the queue, what is refused, and a real round trip between two applications."""

import asyncio
import base64
import json

import pytest

from app import relay


def test_what_is_never_relayed():
    ok = ["/api/devices", "/api/devices/5/applications?days=7", "/api/stats?range=7d", "/api/timeseries/device/3", "/api/dashboard"]
    no = ["/api/users", "/api/backup", "/api/backup/download", "/api/vault", "/api/licence", "/api/probes", "/api/probe/push", "/api/site-view/1/api/devices",
          "/api/export", "/api/central", "/api/database/compact", "/api/tokens", "/api/session", "/static/x.js", "/api/../etc", "/api//users", "devices", "/api/usersx/../users"]
    assert all(relay.allowed_path(p) for p in ok)
    assert not any(relay.allowed_path(p) for p in no[:-1] if p != "/api/usersx/../users") and not relay.allowed_path("/api/usersx/../users")
    assert relay.allowed_path("/api/user-list") is True        # only the listed first segments are refused, not anything that starts with the same letters


def test_a_request_is_queued_picked_up_and_answered():
    async def go():
        hub = relay.Hub()
        assert not hub.connected(1)
        with pytest.raises(relay.SiteOffline):
            await hub.ask(1, "/api/devices")
        poller = asyncio.create_task(hub.poll(1, wait=2))
        await asyncio.sleep(0.05)
        assert hub.connected(1)
        asking = asyncio.create_task(hub.ask(1, "/api/devices"))
        items = await poller
        assert [i["path"] for i in items] == ["/api/devices"] and items[0]["method"] == "GET"
        assert hub.answer(2, items[0]["id"], {"status": 200}) is False          # another site cannot answer for this one
        assert hub.answer(1, items[0]["id"], {"status": 200, "body": "e30="})
        assert (await asking)["status"] == 200
        assert hub.answer(1, items[0]["id"], {"status": 200}) is False          # nothing is waiting any more
        assert (await hub.poll(1, wait=0.05)) == []                              # an idle poll comes back empty
    asyncio.run(go())


def test_a_site_that_does_not_answer_times_out():
    async def go():
        hub = relay.Hub()
        hub.last_poll[7] = relay.time.monotonic()
        with pytest.raises(relay.SiteOffline):
            await hub.ask(7, "/api/devices", timeout=0.1)
    asyncio.run(go())


# ----------------------------------------------------------------------------- two applications: a central one and a remote site
import gzip
import threading
import time

from fastapi.testclient import TestClient

from app import tsdb
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app


@pytest.fixture
def pair(tmp_path):
    tsdb.forget_all()
    paths = {}
    for name in ("central", "remote"):
        paths[name] = tmp_path / f"{name}.db"
        c = connect(paths[name])
        init_db(c)
        c.close()
    rconn = connect(paths["remote"])
    get_or_create_device(rconn, "aa:00:00:00:00:77", "10.9.0.7")
    rconn.close()
    central = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=paths["central"])
    remote = create_app(load_settings({"NETLENS_TOKEN": "other"}), db_path=paths["remote"])
    with TestClient(central, headers={"Authorization": "Bearer secret"}) as c, TestClient(remote, headers={"Authorization": "Bearer other"}) as r:
        yield c, r, remote
    tsdb.forget_all()


def start_site(central_client, remote_app, token, stop):
    """What the remote Netlens does, in a thread: poll the central one and answer through its own application."""
    anon = central_client            # one client, so one event loop: the queue of the hub belongs to it (the explicit header wins over the default one)
    headers = {"Authorization": f"Bearer {token}"}

    def answer(request_id, payload):
        anon.post(f"/api/probe/relay/{request_id}", json=payload, headers=headers)

    def run():
        while not stop.is_set():
            items = anon.get("/api/probe/relay?wait=1", headers=headers).json().get("requests", [])
            for item in items:
                asyncio.run(relay.serve(remote_app, answer, item))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_the_central_netlens_shows_the_pages_of_a_remote_site(pair):
    central, remote, remote_app = pair
    made = central.post("/api/probes", json={"name": "Branch"}).json()
    pid, token = made["probe"]["id"], made["token"]
    anon = central
    # not allowed yet: the site has not said it lets the central Netlens look
    assert central.get(f"/api/site-view/{pid}/api/devices").status_code == 403
    body = gzip.compress(json.dumps({"version": "0.4.0", "devices": [], "services": [], "accepts_view": True}).encode())
    assert anon.post("/api/probe/push", content=body, headers={"Authorization": f"Bearer {token}", "Content-Encoding": "gzip", "Content-Type": "application/json"}).status_code == 200
    # allowed, but nobody is polling: a clear answer instead of a hang
    assert central.get(f"/api/site-view/{pid}/api/devices").status_code == 504
    stop = threading.Event()
    thread = start_site(central, remote_app, token, stop)
    try:
        for _ in range(50):
            if relay.HUB.connected(pid):
                break
            time.sleep(0.1)
        got = central.get(f"/api/site-view/{pid}/api/devices")
        assert got.status_code == 200 and [d["primary_ip"] for d in got.json()] == ["10.9.0.7"]          # the site's own device list, not the central one's
        assert central.get("/api/devices").json() == []
        assert central.get(f"/api/site-view/{pid}/api/devices/1").json()["primary_ip"] == "10.9.0.7"
        assert central.get(f"/api/site-view/{pid}/api/devices/9999").status_code == 404                 # the site's own errors come through
        # parts that hand out secrets or accounts are refused here, and again by the site
        for refused in ("api/users", "api/backup", "api/vault", "api/licence", "api/probes"):
            assert central.get(f"/api/site-view/{pid}/{refused}").status_code == 403, refused
        # a site cannot be written to through this
        assert central.post(f"/api/site-view/{pid}/api/scans", json={}).status_code in (404, 405)
        assert central.get("/api/probes").json()[0]["view"] == {"allowed": True, "connected": True}
    finally:
        stop.set()
        thread.join(timeout=5)


def test_only_an_administrator_of_the_central_netlens_may_look(pair):
    central, remote, remote_app = pair
    pid = central.post("/api/probes", json={"name": "Branch"}).json()["probe"]["id"]
    made = central.post("/api/users", json={"username": "viewer1", "password": "a-long-password-1", "role": "viewer"})
    assert made.status_code in (200, 201), made.text
    anon = TestClient(central.app)
    assert anon.post("/api/login", json={"username": "viewer1", "password": "a-long-password-1"}).status_code == 200
    assert anon.get(f"/api/site-view/{pid}/api/devices").status_code == 403


def test_a_request_that_only_claims_to_be_the_relay_is_not_trusted(pair):
    central, remote, remote_app = pair
    anon = TestClient(remote_app)
    assert anon.get("/api/devices", headers={"X-Netlens-Relay": "guess"}).status_code == 401
    assert anon.get("/api/devices", headers={"X-Netlens-Relay": relay.secret_for(remote_app)}).status_code == 401      # right secret, but from the network, not through call_app


def test_the_view_setting_is_saved_and_reported_to_the_central_netlens(tmp_path, monkeypatch):
    from app import central

    path = tmp_path / "s.db"
    conn = connect(path)
    init_db(conn)
    assert central.get_link(conn)["allow_view"] is False                    # off until somebody ticks it
    central.set_link(conn, {"url": "https://c.example", "token": "nlp_x", "enabled": True})
    assert central.public_link(conn)["allow_view"] is False
    central.set_link(conn, {"allow_view": True})
    assert central.public_link(conn)["allow_view"] is True
    sent = {}
    monkeypatch.setattr(central, "send", lambda url, token, payload, **kw: sent.update(payload) or {"events": 0})
    central.push_once(str(path), force=True)
    assert sent["accepts_view"] is True and sent["accepts_config"] is False
