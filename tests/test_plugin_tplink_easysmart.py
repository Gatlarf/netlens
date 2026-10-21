"""The TP-Link Easy Smart plugin against a simulated switch. The pages follow the format described by the public projects check_tplink and
essstat (script variables info_ds, max_port_num and all_info); no real switch has answered yet."""

import importlib.util
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "tplink-easysmart"
spec = importlib.util.spec_from_file_location("tplink_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

STATE = [1] * 7 + [0] + [1] * 8 + [0, 0]
LINK = [6, 5, 0, 6, 0, 2, 0, 0, 6, 0, 0, 0, 0, 0, 0, 1, 0, 0]


def info_page(mac="AA-BB-CC-00-11-22"):
    return f'<html><script>var info_ds = {{\ndescriStr:["SW_TEST"],\nfwareStr:["x"],\nfirmwareStr:["1.0.0 Build 20211020 Rel.34588"],\nhardwareStr:["TL-SG1016PE 3.0"],\nmacStr:["{mac}"],\nipStr:["192.168.0.250"],\nnetmaskStr:["255.255.255.0"],\ngatewayStr:["192.168.0.1"]\n}};</script></html>'


def ports_page(tx=1000):
    pkts = []
    for i in range(16):
        pkts += [tx + i, i % 3, 2 * tx + i, i % 2]
    pkts += [0, 0]
    return ("<html><script>var max_port_num = 16;\nvar all_info = {\nstate:[%s],\nlink_status:[%s],\npkts:[%s]\n};\n</script></html>"
            % (",".join(map(str, STATE)), ",".join(map(str, LINK)), ",".join(map(str, pkts))))


LOGIN_PAGE = "<html><script>var logonInfo = new Array(\n%d,\n0,0);</script></html>"


class FakeSwitch:
    def __init__(self, password="secret", pages=None, error=None):
        self.password, self.seen, self.error = password, [], error
        self.pages = pages or {"/SystemInfoRpm.htm": info_page(), "/PortStatisticsRpm.htm": ports_page()}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, body):
                raw = body.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                outer.seen.append("POST " + self.path)
                if outer.error:
                    return self._send(LOGIN_PAGE % outer.error)
                good = f"password={outer.password}" in body.split("&") and "username=admin" in body.split("&")
                outer.logged_in = good
                self._send(LOGIN_PAGE % (0 if good else 1))

            def do_GET(self):
                outer.seen.append("GET " + self.path)
                if self.path == "/Logout.htm":
                    outer.logged_in = False
                    return self._send("bye")
                self._send(outer.pages.get(self.path, "") if getattr(outer, "logged_in", False) else LOGIN_PAGE % 0)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()


def config(url, password="secret", name=""):
    return {"servers": [{"host": url, "username": "admin", "password": password, "name": name}]}


def test_manifest_and_output_follow_the_contract():
    validate_manifest(__import__("json").loads((ROOT / "plugin.json").read_text()))
    with FakeSwitch() as sw:
        out = plugin.fetch(config(sw.url, name="Core switch"))
    checked = validate_output("topology", out)
    node = checked["nodes"][0]
    assert node["mac"] == "aa:bb:cc:00:11:22" and node["role"] == "switch" and node["name"] == "Core switch" and node["ip"] == "192.168.0.250"
    assert len(node["ports"]) == 16 and node["model"] == "TL-SG1016PE 3.0"


def test_ports_are_decoded():
    ports = plugin.parse_ports(ports_page())
    p1, p2, p3, p6, p8, p16 = (ports[i] for i in (0, 1, 2, 5, 7, 15))
    assert p1["up"] and p1["speed_mbps"] == 1000 and p1["duplex"] == "full" and p1["tx_packets"] == 1000 and p1["rx_packets"] == 2000
    assert p2["speed_mbps"] == 100 and p2["tx_errors"] == 1 and p2["rx_errors"] == 1
    assert not p3["up"] and "speed_mbps" not in p3
    assert p6["speed_mbps"] == 10 and p6["duplex"] == "half"
    assert p8["enabled"] is False
    assert p16["up"] is False        # status 1 is not a negotiated link


def test_logout_always_happens_and_wrong_password_is_auth_failed():
    with FakeSwitch() as sw:
        plugin.fetch(config(sw.url))
        assert sw.seen[-1] == "GET /Logout.htm"
    with FakeSwitch() as sw:
        with pytest.raises(plugin.AuthRefused) as exc:
            plugin.fetch(config(sw.url, password="wrong"))
        assert exc.value.auth_failed is True and "wrong user name or password" in str(exc.value)
        assert "GET /SystemInfoRpm.htm" not in sw.seen            # nothing else is tried after a refusal


def test_sessions_full_is_not_an_auth_failure():
    with FakeSwitch(error=4) as sw:
        with pytest.raises(plugin.SwitchError) as exc:
            plugin.test(config(sw.url))
    assert not getattr(exc.value, "auth_failed", False) and "sessions full" in str(exc.value)


def test_a_page_in_another_format_gives_a_clear_error():
    with FakeSwitch(pages={"/SystemInfoRpm.htm": "<html>nothing</html>", "/PortStatisticsRpm.htm": "<html></html>"}) as sw:
        with pytest.raises(plugin.SwitchError, match="info_ds"):
            plugin.fetch(config(sw.url))


def test_unreachable_switch():
    with pytest.raises(plugin.SwitchError, match="cannot reach"):
        plugin.test(config("http://127.0.0.1:9"))


def test_test_message_and_diagnose_do_not_leak():
    with FakeSwitch() as sw:
        assert "SW_TEST" in plugin.test(config(sw.url))["message"]
        report = plugin.diagnose(config(sw.url))
    text = str(report)
    assert "aa:bb:cc" not in text.lower() and "AA-BB-CC" not in text and "192.168.0.250" not in text
    assert report["steps"]["switch 1"]["PortStatisticsRpm.htm"]["ports"] == 16


def test_ports_are_stored_and_link_changes_become_events(tmp_path):
    from app.db import connect, get_or_create_device, init_db
    from app.plugins.enrich import record_switch_ports

    conn = connect(tmp_path / "p.db")
    init_db(conn)
    get_or_create_device(conn, "aa:bb:cc:00:11:22", "192.168.0.250")
    with FakeSwitch() as sw:
        data = validate_output("topology", plugin.fetch(config(sw.url)))
    assert record_switch_ports(conn, "tplink-easysmart", data, now="2026-10-21T10:00:00Z") == 16
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind IN ('link_up','link_down')").fetchone()[0] == 0     # first sight is not a change
    data["nodes"][0]["ports"][0]["up"] = False
    data["nodes"][0]["ports"][2]["up"] = True
    data["nodes"][0]["ports"][2]["speed_mbps"] = 1000
    record_switch_ports(conn, "tplink-easysmart", data, now="2026-10-21T10:05:00Z")
    kinds = sorted((r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events WHERE kind IN ('link_up','link_down')"))
    assert [k for k, _ in kinds] == ["link_down", "link_up"] and "port 3" in kinds[1][1] and "1000 Mbit/s" in kinds[1][1]
    assert conn.execute("SELECT COUNT(*) FROM switch_port_samples").fetchone()[0] == 32


def test_api_rates_errors_and_flaps(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.db import connect, get_or_create_device
    from app.main import create_app
    from app.plugins.enrich import record_switch_ports

    path = tmp_path / "a.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        conn = connect(path)
        d = get_or_create_device(conn, "aa:bb:cc:00:11:22", "192.168.0.250")
        assert c.get(f"/api/devices/{d}/switch-ports").json()["ports"] == []
        from datetime import datetime, timedelta, timezone

        t0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=10)
        for step, tx in enumerate((1000, 1600)):
            with FakeSwitch(pages={"/SystemInfoRpm.htm": info_page(), "/PortStatisticsRpm.htm": ports_page(tx)}) as sw:
                data = validate_output("topology", plugin.fetch(config(sw.url)))
            data["nodes"][0]["ports"][0]["up"] = step == 0
            record_switch_ports(conn, "tplink-easysmart", data, now=(t0 + timedelta(minutes=5 * step)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        conn.close()
        ports = c.get(f"/api/devices/{d}/switch-ports").json()["ports"]
    assert len(ports) == 16
    assert ports[0]["tx_pps"] == 2.0 and ports[0]["rx_pps"] == 4.0 and ports[0]["flaps"] == 1 and ports[0]["up"] == 0
    assert ports[1]["tx_errors_window"] == 0 and ports[1]["tx_packets_window"] == 600


def test_packets_errors_and_link_state_become_time_series(tmp_path):
    from app import tsdb
    from app.db import connect, get_or_create_device, init_db
    from app.plugins.enrich import record_switch_ports

    conn = connect(tmp_path / "s.db")
    init_db(conn)
    d = get_or_create_device(conn, "aa:bb:cc:00:11:22", "192.168.0.250")
    for step, (tx, bad) in enumerate(((1000, 0), (1600, 5))):
        with FakeSwitch(pages={"/SystemInfoRpm.htm": info_page(), "/PortStatisticsRpm.htm": ports_page(tx)}) as sw:
            data = validate_output("topology", plugin.fetch(config(sw.url)))
        data["nodes"][0]["ports"][0]["tx_errors"] = bad
        record_switch_ports(conn, "tplink-easysmart", data, now=f"2026-10-21T10:0{step * 5}:00Z")
    store = tsdb.for_conn(conn)
    assert store.latest("device", d, "net_tx_pps", "Port 1")[1] == 2.0           # 600 packets in 300 s
    assert store.latest("device", d, "net_rx_pps", "Port 1")[1] == 4.0
    assert store.latest("device", d, "if_up", "Port 1")[1] == 1.0 and store.latest("device", d, "if_up", "Port 3")[1] == 0.0
    assert store.latest("device", d, "if_err_ps", "Port 1")[1] == pytest.approx(5 / 300)
    assert store.latest("device", d, "if_err_ps", "Port 2") is None                # never had an error: no graph
    assert store.latest("device", d, "net_tx_pps", "Port 3") is None               # no link, no traffic series
    assert store.latest("device", d, "if_up", "Port 8") is None                    # switched off by the administrator (state 0): not reported as down


def test_counter_wrap_and_reset():
    from app.plugins.enrich import _counter_delta

    assert _counter_delta(150, 100) == 50
    assert _counter_delta(10, 2 ** 32 - 90) == 100             # wrapped around 32 bits
    assert _counter_delta(10, 5000) is None                    # a restart
    assert _counter_delta(None, 5) is None
