"""Sites published by a reverse proxy: tying them to devices and containers, certificate events, site checks, the API, DNS names."""

import asyncio
import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app import sites
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app
from app.plugins.contract import validate_output
from app.services import check_http, describe, validate_check

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


def site(i, domains, host, port, **kw):
    base = {"id": i, "proxy_id": "npm", "type": "proxy", "domains": domains, "enabled": True, "forward_host": host, "forward_port": port}
    base.update(kw)
    return base


def output(*site_list, certs=(), ip="192.168.0.184", warnings=()):
    return validate_output("proxy", {"proxies": [{"id": "npm", "name": "npm", "ip": ip, "warnings": list(warnings)}], "sites": list(site_list), "certificates": list(certs)})


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    ids = {
        "proxy": get_or_create_device(conn, "aa:00:00:00:00:84", "192.168.0.184"),      # the host NPM runs on
        "docker": get_or_create_device(conn, "aa:00:00:00:00:89", "192.168.0.189"),     # another Docker host
        "nas": get_or_create_device(conn, "aa:00:00:00:00:50", "192.168.0.50"),
        "wiki": get_or_create_device(conn, "aa:00:00:00:00:60", "192.168.0.60"),
        "lan": get_or_create_device(conn, "02:42:c0:a8:00:70", "192.168.0.70"),         # a macvlan container
    }
    conn.execute("UPDATE devices SET hostname = 'wikibox.home.example.com' WHERE id = ?", (ids["wiki"],))

    def guest(plugin, gid, name, host, device=None, ips=(), ports=(), service="", status="running"):
        conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, ips, device_id, host_device_id, updated, details) VALUES (?, ?, ?, 'container', 'h', ?, ?, ?, ?, 'now', ?)",
                     (plugin, gid, name, status, json.dumps(list(ips)), device, host, json.dumps({"ports": list(ports), "service": service})))

    guest("docker", "d1/jellyfin", "jellyfin", ids["docker"], ports=[{"container_port": 8096, "host_port": 8096, "proto": "tcp", "bind": "0.0.0.0"}])
    guest("docker", "d1/bound", "bound", ids["docker"], ports=[{"container_port": 80, "host_port": 9000, "proto": "tcp", "bind": "127.0.0.1"}])
    guest("docker", "d1/stopped", "stopped", ids["docker"], ports=[{"container_port": 80, "host_port": 9100, "proto": "tcp", "bind": "0.0.0.0"}], status="exited")
    guest("docker", "n/grafana", "grafana-1", ids["proxy"], service="grafana", ports=[{"container_port": 3000, "host_port": None, "proto": "tcp", "bind": ""}])
    guest("docker", "n/self", "app", ids["proxy"], ports=[{"container_port": 80, "host_port": 8081, "proto": "tcp", "bind": "0.0.0.0"}])
    guest("docker", "d1/lan", "lanbox", ids["docker"], device=ids["lan"], ips=["192.168.0.70"])
    conn.commit()
    yield conn, ids
    conn.close()


def match(conn, ids, host, port, **kw):
    s = output(site("s", ["a.example.com"], host, port, **kw))["sites"][0]
    return sites.match_site(s, ids["proxy"], sites.Context(conn))


# ---------------------------------------------------------------- finding what a site leads to
def test_an_address_and_a_published_port_find_the_container(db):
    conn, ids = db
    found = match(conn, ids, "192.168.0.189", 8096)
    assert (found["name"], found["plugin_id"], found["device_id"], found["how"]) == ("jellyfin", "docker", ids["docker"], "published port 8096")


def test_an_address_without_a_matching_port_is_the_host_itself(db):
    conn, ids = db
    found = match(conn, ids, "192.168.0.189", 22)
    assert found["guest_id"] is None and found["device_id"] == ids["docker"] and found["how"] == "address"
    assert match(conn, ids, "192.168.0.50", 80)["device_id"] == ids["nas"]


def test_a_port_bound_to_another_address_or_a_stopped_container_does_not_count(db):
    conn, ids = db
    assert match(conn, ids, "192.168.0.189", 9000)["guest_id"] is None          # bound to 127.0.0.1 on that host
    assert match(conn, ids, "192.168.0.189", 9100)["guest_id"] is None          # the container is not running


def test_a_container_with_its_own_address_is_found_by_that_address(db):
    conn, ids = db
    found = match(conn, ids, "192.168.0.70", 80)
    assert found["name"] == "lanbox" and found["device_id"] == ids["lan"] and found["how"] == "own address"


def test_a_container_name_or_service_name_on_the_proxys_own_docker_host(db):
    conn, ids = db
    assert match(conn, ids, "grafana-1", 3000)["name"] == "grafana-1"
    found = match(conn, ids, "grafana", 3000)                                     # the compose service name
    assert found["name"] == "grafana-1" and found["how"] == "container name"
    assert match(conn, ids, "grafana", 9999)["how"] == "container name (port not listed)"
    assert match(conn, ids, "jellyfin", 8096) is None                             # another host's container is not reachable by name


def test_this_machine_means_the_proxys_host(db):
    conn, ids = db
    assert match(conn, ids, "host.docker.internal", 8081)["name"] == "app"
    assert match(conn, ids, "localhost", 5555)["device_id"] == ids["proxy"]


def test_a_name_is_found_through_its_lookup_or_the_device_name(db):
    conn, ids = db
    assert match(conn, ids, "nas.home.example.com", 80, forward_ips=["192.168.0.50"])["how"] == "name address"
    assert match(conn, ids, "wikibox", 80)["device_id"] == ids["wiki"]
    assert match(conn, ids, "wikibox.home.example.com", 80)["how"] == "name"
    assert match(conn, ids, "nowhere.example.com", 80, forward_ips=["10.9.9.9"]) is None


def test_redirections_and_404_hosts_lead_nowhere_but_streams_do(db):
    conn, ids = db
    assert match(conn, ids, "192.168.0.50", 80, type="redirect") is None and match(conn, ids, "", None, type="dead") is None
    assert match(conn, ids, "192.168.0.50", 22, type="stream")["device_id"] == ids["nas"]


# ---------------------------------------------------------------- storing a sync
def test_a_sync_stores_the_sites_with_their_targets(db):
    conn, ids = db
    data = output(site("1", ["media.example.com"], "192.168.0.189", 8096, ssl=True, certificate_id="9", cert_expires="2026-12-31T00:00:00Z"),
                  site("2", ["lost.example.com"], "10.9.9.9", 80), site("3", ["*.example.com"], "192.168.0.50", 80, enabled=False))
    summary = sites.apply_proxy(conn, "npm", data, {"create_checks": False}, NOW)
    assert (summary["sites"], summary["sites_matched"], summary["proxies"]) == (3, 2, 1)
    listing = {s["id"]: s for s in sites.list_sites(conn)}
    assert listing["1"]["target_container"] and listing["1"]["target_name"] == "jellyfin" and listing["1"]["target_device_id"] == ids["docker"]
    assert listing["1"]["proxy_device_id"] == ids["proxy"] and listing["1"]["cert_days"] == 80 and listing["1"]["ssl"]
    assert listing["2"]["target_device_id"] is None
    sites.apply_proxy(conn, "npm", output(site("1", ["media.example.com"], "192.168.0.189", 8096)), {"create_checks": False}, NOW)      # a site that is gone is gone
    assert [s["id"] for s in sites.list_sites(conn)] == ["1"]


def test_the_device_pages_know_what_they_publish_and_serve(db):
    conn, ids = db
    sites.apply_proxy(conn, "npm", output(site("1", ["media.example.com"], "192.168.0.189", 8096), site("2", ["nas.example.com"], "192.168.0.50", 80)), {"create_checks": False}, NOW)
    docker = sites.device_sites(conn, ids["docker"])
    assert [s["id"] for s in docker["published"]] == ["1"] and docker["serves"] == []
    proxy = sites.device_sites(conn, ids["proxy"])
    assert proxy["published"] == [] and [s["id"] for s in proxy["serves"]] == ["1", "2"]
    assert sites.device_sites(conn, ids["wiki"]) is None
    assert sites.summary(conn)["unmatched"] == 0


# ---------------------------------------------------------------- certificates
def cert(expires, cid="1"):
    return {"id": cid, "proxy_id": "npm", "name": "wildcard", "domains": ["*.example.com"], "expires": expires}


def cert_events(conn):
    return [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'cert_expiring' ORDER BY id")]


def test_a_certificate_is_reported_when_it_gets_close_and_at_each_step_down(db):
    conn, ids = db
    s = site("1", ["a.example.com", "b.example.com"], "192.168.0.50", 80, ssl=True, certificate_id="1")

    def run(days, hours=0):
        when = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)
        expires = datetime.fromtimestamp(when.timestamp() + days * 86400 + hours * 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sites.apply_proxy(conn, "npm", output(s, certs=[cert(expires)]), {"create_checks": False}, when)

    run(30)
    assert cert_events(conn) == []
    run(13, 1)
    assert len(cert_events(conn)) == 1 and "expires in 13 days" in cert_events(conn)[0] and "a.example.com, b.example.com" in cert_events(conn)[0]
    run(12)
    run(11)
    assert len(cert_events(conn)) == 1                                  # same step: no repeat
    run(6, 1)
    run(2, 1)
    run(0, 5)
    assert len(cert_events(conn)) == 4
    run(-1)
    assert "has expired" in cert_events(conn)[-1]
    run(90)                                                             # renewed
    run(5)
    assert len(cert_events(conn)) == 6
    assert conn.execute("SELECT device_id FROM events WHERE kind = 'cert_expiring' LIMIT 1").fetchone()[0] == ids["proxy"]


def test_a_certificate_no_site_uses_is_not_reported(db):
    conn, _ = db
    sites.apply_proxy(conn, "npm", output(site("1", ["a.example.com"], "192.168.0.50", 80), certs=[cert("2026-10-12T00:00:00Z")]), {"create_checks": False}, NOW)
    assert cert_events(conn) == []


def test_the_warning_setting_moves_the_first_step(db):
    conn, _ = db
    s = site("1", ["a.example.com"], "192.168.0.50", 80, ssl=True, certificate_id="1")
    sites.apply_proxy(conn, "npm", output(s, certs=[cert("2026-11-05T12:00:00Z")]), {"create_checks": False, "cert_warn_days": 30}, NOW)     # 25 days left
    assert len(cert_events(conn)) == 1


# ---------------------------------------------------------------- the checks
def checks(conn):
    return {r["source"]: dict(r) for r in conn.execute("SELECT * FROM service_checks")}


def test_every_enabled_site_gets_a_check_through_the_proxy(db):
    conn, ids = db
    data = output(site("1", ["media.example.com", "alt.example.com"], "192.168.0.189", 8096, ssl=True), site("2", ["plain.example.com"], "192.168.0.50", 80),
                  site("3", ["*.example.com"], "192.168.0.50", 80), site("4", ["off.example.com"], "192.168.0.50", 80, enabled=False), site("5", ["x.example.com"], "", None, type="dead"))
    assert sites.apply_proxy(conn, "npm", data, {}, NOW)["checks"] == 2
    got = checks(conn)
    assert set(got) == {"npm:npm:1", "npm:npm:2"}
    one = got["npm:npm:1"]
    assert (one["kind"], one["host"], one["via"], one["port"], one["expect"], one["interval_s"], one["name"]) == ("http", "media.example.com", "192.168.0.184", 443, "alive", 300, "Site media.example.com")
    assert one["device_id"] == ids["docker"] and got["npm:npm:2"]["port"] == 80 and describe(one) == "https://media.example.com:443/ via 192.168.0.184"


def test_checks_follow_the_list_and_keep_what_the_user_changed(db):
    conn, _ = db
    data = output(site("1", ["media.example.com"], "192.168.0.189", 8096, ssl=True), site("2", ["plain.example.com"], "192.168.0.50", 80))
    sites.apply_proxy(conn, "npm", data, {"check_interval": 120}, NOW)
    conn.execute("UPDATE service_checks SET interval_s = 30, enabled = 0, last_up = 1 WHERE source = 'npm:npm:1'")
    conn.execute("INSERT INTO service_checks (name, kind, host, port, created) VALUES ('mine', 'tcp', 'x', 22, 'now')")
    sites.apply_proxy(conn, "npm", output(site("1", ["moved.example.com"], "192.168.0.189", 8096, ssl=True)), {"check_interval": 120}, NOW)
    got = checks(conn)
    assert set(got) - {None} == {"npm:npm:1"} and got[None]["name"] == "mine"                        # the other site's check is gone, the user's own stays
    assert got["npm:npm:1"]["host"] == "moved.example.com" and got["npm:npm:1"]["interval_s"] == 30 and got["npm:npm:1"]["enabled"] == 0
    assert got["npm:npm:1"]["last_up"] is None                                                       # a new target starts a new history
    sites.apply_proxy(conn, "npm", output(site("1", ["moved.example.com"], "192.168.0.189", 8096, ssl=True)), {"create_checks": False}, NOW)
    assert set(checks(conn)) == {None}


def test_a_proxy_without_an_address_gets_no_checks(db):
    conn, _ = db
    assert sites.apply_proxy(conn, "npm", output(site("1", ["a.example.com"], "192.168.0.50", 80), ip=None), {}, NOW)["checks"] == 0


class Backend(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Backend.seen.append(self.headers.get("Host"))
        code = 502 if self.headers.get("Host") == "dead.example.com" else 401
        self.send_response(code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def test_a_check_asks_the_proxy_for_the_name_and_only_a_server_error_is_down():
    server = HTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        def ask(host):
            return asyncio.run(check_http({"host": host, "via": "127.0.0.1", "port": server.server_port, "path": "/", "expect": "alive"}, 5))

        assert ask("live.example.com").up and "HTTP 401" in ask("live.example.com").detail          # the site's own login page is an answer
        assert not ask("dead.example.com").up and ask("dead.example.com").detail == "HTTP 502"
        assert "live.example.com" in Backend.seen and "dead.example.com" in Backend.seen             # the name was sent as the Host header
    finally:
        server.shutdown()
        server.server_close()


def test_alive_is_a_valid_expectation():
    assert validate_check({"kind": "http", "name": "n", "host": "a.example.com", "port": 443, "expect": "alive"})["expect"] == "alive"
    with pytest.raises(Exception):
        validate_check({"kind": "http", "name": "n", "host": "a.example.com", "port": 443, "expect": "mostly"})


# ---------------------------------------------------------------- the API
def test_the_api_lists_sites_and_the_device_detail_carries_them(tmp_path):
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer t"}) as c:
        conn = connect(path)
        proxy = get_or_create_device(conn, "aa:00:00:00:00:84", "192.168.0.184")
        nas = get_or_create_device(conn, "aa:00:00:00:00:50", "192.168.0.50")
        soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")     # the API counts days from the real clock
        sites.apply_proxy(conn, "npm", output(site("1", ["nas.example.com"], "192.168.0.50", 80, ssl=True, certificate_id="1", cert_expires=soon)), {}, NOW)
        conn.close()
        body = c.get("/api/sites").json()
        assert {k: body["summary"][k] for k in ("total", "enabled", "unmatched", "expiring", "down", "certificates", "next_expiry_days")} == {"total": 1, "enabled": 1, "unmatched": 0, "expiring": 1, "down": 0, "certificates": 1, "next_expiry_days": 4}
        s = body["sites"][0]
        assert s["domains"] == ["nas.example.com"] and s["target_device_id"] == nas and s["proxy_device_id"] == proxy and s["check_id"] and s["check_state"] is None
        assert c.get("/api/sites", params={"device_id": nas}).json()["sites"][0]["id"] == "1"
        assert c.get("/api/sites", params={"device_id": 999}).json()["sites"] == []
        assert [x["id"] for x in c.get(f"/api/devices/{nas}").json()["sites"]["published"]] == ["1"]
        assert [x["id"] for x in c.get(f"/api/devices/{proxy}").json()["sites"]["serves"]] == ["1"]
        assert c.get("/api/sites", headers={"Authorization": "Bearer no"}).status_code == 401
        checks_listing = c.get("/api/service-checks").json()
        assert checks_listing[0]["source"] == "npm:npm:1" and checks_listing[0]["target"].endswith("via 192.168.0.184")


# ---------------------------------------------------------------- DNS names for the domains
def test_site_domains_become_aliases_and_the_plan_makes_cnames_in_known_zones(db):
    from app.dns.plan import DnsDevice, DnsSettings, build_plan, parse_networks
    from app.dns.service import load_aliases

    conn, ids = db
    sites.apply_proxy(conn, "npm", output(site("1", ["media.home.example.com", "*.home.example.com", "shop.public.org"], "192.168.0.189", 8096),
                                          site("2", ["gone.home.example.com"], "192.168.0.50", 80, enabled=False), site("3", ["old.home.example.com"], "", None, type="redirect")), {"create_checks": False}, NOW)
    assert load_aliases(conn, containers=False, sites=False) == []
    aliases = load_aliases(conn, containers=False, sites=True)
    assert sorted(a.fqdn for a in aliases) == ["media.home.example.com", "old.home.example.com", "shop.public.org"] and all(a.host_id == ids["proxy"] for a in aliases)

    zone = "home.example.com"
    snapshot = {"zones": [{"name": zone, "kind": "forward", "writable": True}, {"name": "0.168.192.in-addr.arpa", "kind": "reverse", "writable": True}], "server": "dns",
                "records": [{"zone": zone, "name": f"old.{zone}", "type": "A", "value": "192.168.0.99", "ttl": None, "managed": False, "comment": ""}]}
    settings = DnsSettings(networks=parse_networks(f"192.168.0.0/24 = {zone}"), grace_hours=0, register_sites=True)
    result = build_plan([DnsDevice(id=ids["proxy"], ip="192.168.0.184", hostname=f"npm.{zone}")], snapshot, settings, "2026-10-11T12:00:00Z", aliases=aliases)
    by_name = {i["name"]: i for i in result["items"] if i["id"].startswith("s:")}
    assert set(by_name) == {f"media.{zone}", f"old.{zone}"}                         # shop.public.org is not in a zone this DNS server has
    media = by_name[f"media.{zone}"]
    assert media["state"] == "add" and media["changes"][0]["type"] == "CNAME" and media["changes"][0]["value"] == f"npm.{zone}" and "published through media" in media["reason"]
    assert by_name[f"old.{zone}"]["state"] == "skip" and "already exists" in by_name[f"old.{zone}"]["reason"]
    off = build_plan([DnsDevice(id=ids["proxy"], ip="192.168.0.184", hostname=f"npm.{zone}")], snapshot, DnsSettings(networks=settings.networks, grace_hours=0), "2026-10-11T12:00:00Z", aliases=aliases)
    assert not [i for i in off["items"] if i["id"].startswith("s:")]                 # off unless asked for


# ---------------------------------------------------------------- through the plugin service
@pytest.mark.asyncio
async def test_a_proxy_plugin_syncs_through_the_service_and_is_cleaned_up_with_its_data(tmp_path):
    from app.plugins.registry import discover
    from app.plugins.service import PluginService, clear_plugin_data, get_status, save_state
    from tests.plugin_helpers import fake, make_runner, write_plugin

    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    nas = get_or_create_device(conn, "aa:00:00:00:00:50", "192.168.0.50")
    get_or_create_device(conn, "aa:00:00:00:00:84", "192.168.0.184")
    conn.close()
    write_plugin(tmp_path, "npm", kind="proxy")
    conn = connect(path)
    save_state(conn, "npm", True, {"host": "h", "secret": "s", "create_checks": True})
    conn.close()
    data = {"proxies": [{"id": "p", "name": "npm", "ip": "192.168.0.184", "warnings": ["look at me"]}],
            "sites": [{"id": "1", "proxy_id": "p", "domains": ["nas.example.com"], "forward_host": "192.168.0.50", "forward_port": 80}], "certificates": []}
    svc = PluginService(str(path), tmp_path, make_runner(npm=fake(fetch=lambda cfg: data)))
    result = await svc.sync("npm")
    assert result["sites"] == 1 and result["sites_matched"] == 1 and result["warnings"] == ["look at me"]
    conn = connect(path)
    assert get_status(conn, "npm")["ok"] is True and get_status(conn, "npm")["warnings"] == ["look at me"]
    assert sites.list_sites(conn)[0]["target_device_id"] == nas
    assert conn.execute("SELECT COUNT(*) FROM service_checks WHERE source LIKE 'npm:%'").fetchone()[0] == 1
    # an output that breaks the contract is refused and leaves the stored sites alone
    bad = PluginService(str(path), tmp_path, make_runner(npm=fake(fetch=lambda cfg: {"proxies": [], "sites": [{"id": "x", "proxy_id": "zzz"}], "certificates": []})))
    assert "does not follow the contract" in (await bad.sync("npm"))["error"]
    assert len(sites.list_sites(conn)) == 1
    clear_plugin_data(conn, "npm")
    conn.commit()
    assert sites.list_sites(conn) == [] and conn.execute("SELECT COUNT(*) FROM service_checks").fetchone()[0] == 0
    conn.close()
    assert discover(tmp_path)["npm"].manifest["kind"] == "proxy"


def stamp(days):
    return (datetime.now(timezone.utc) + timedelta(days=days, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_certificates_are_counted_once_and_reach_the_summary_and_the_metrics(db):
    from app.metrics import render_metrics
    from app.stats import summary

    conn, _ = db
    data = output(site("1", ["a.example.com"], "192.168.0.189", 8096, ssl=True, certificate_id="1", cert_name="wildcard", cert_expires=stamp(5)),
                  site("2", ["b.example.com"], "192.168.0.50", 80, ssl=True, certificate_id="1", cert_name="wildcard", cert_expires=stamp(5)),
                  site("3", ["c.example.com"], "192.168.0.50", 80, ssl=True, certificate_id="2", cert_name="old", cert_expires=stamp(-3)),
                  site("4", ["d.example.com"], "192.168.0.50", 80, ssl=True, certificate_id="3", cert_name="fine", cert_expires=stamp(90)),
                  site("5", ["off.example.com"], "192.168.0.50", 80, enabled=False, ssl=True, certificate_id="4", cert_name="unused", cert_expires=stamp(1)))
    sites.apply_proxy(conn, "npm", data, {"create_checks": False}, NOW)
    certs = sites.certificates(conn)
    assert [(c["name"], c["days"]) for c in certs] == [("old", -3), ("wildcard", 5), ("fine", 90)]
    assert certs[1]["domains"] == ["a.example.com", "b.example.com"]
    block = summary(conn)["sites"]
    assert (block["certificates"], block["certificates_expiring"], block["certificates_expired"], block["next_expiry_days"]) == (3, 1, 1, -3)
    text = render_metrics(conn)
    assert 'netlens_certificate_days_left{certificate="wildcard",proxy="npm"} 5' in text
    assert 'netlens_certificate_expires_timestamp_seconds{certificate="fine",proxy="npm"}' in text and "unused" not in text
    assert 'netlens_sites{state="enabled"} 4' in text and 'netlens_sites{state="disabled"} 1' in text and "netlens_sites_unmatched" in text


def test_a_network_without_proxy_sites_has_empty_numbers_and_no_metrics(db):
    from app.metrics import render_metrics
    from app.stats import summary

    conn, _ = db
    assert summary(conn)["sites"] == {"total": 0, "enabled": 0, "unmatched": 0, "expiring": 0, "down": 0, "certificates": 0, "certificates_expiring": 0, "certificates_expired": 0, "next_expiry_days": None}
    assert "netlens_sites" not in render_metrics(conn) and "netlens_certificate" not in render_metrics(conn)
