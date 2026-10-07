from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.orchestrator import ScanManager


def _host(ip: str, mac: str, srtt: int | None) -> str:
    times = f'<times srtt="{srtt}" rttvar="100" to="100000"/>' if srtt is not None else ""
    return (
        f'<host><status state="up" reason="arp-response"/><address addr="{ip}" addrtype="ipv4"/>'
        f'<address addr="{mac}" addrtype="mac"/>{times}</host>'
    )


def _xml(*hosts: str) -> str:
    return '<?xml version="1.0"?><nmaprun>' + "".join(hosts) + "</nmaprun>"


A = ("192.168.1.1", "aa:bb:cc:00:00:01")
B = ("192.168.1.2", "aa:bb:cc:00:00:02")


def test_parser_reads_rtt():
    hosts = parse_nmap_xml(_xml(_host(*A, 2500), _host(*B, None)))
    assert hosts[0].rtt_ms == 2.5
    assert hosts[1].rtt_ms is None


async def _noop_names():
    return {}


async def _ranges():
    return ["192.168.1.0/24"]


@pytest.mark.asyncio
async def test_scans_record_heartbeats_and_api_serves_them(tmp_path):
    db = tmp_path / "t.db"
    conn = connect(db)
    init_db(conn)
    conn.close()
    settings = load_settings({"NETLENS_TOKEN": "secret"})
    xmls = [_xml(_host(*A, 2500), _host(*B, None)), _xml(_host(*A, 3500))]

    async def runner(kind, targets, **kw):
        return xmls.pop(0)

    manager = ScanManager(db, settings, runner=runner, names_provider=_noop_names, ranges_provider=_ranges)
    for _ in range(2):
        await manager.start("quick")
        await manager.wait()

    conn = connect(db)
    ids = {r["primary_ip"]: r["id"] for r in conn.execute("SELECT id, primary_ip FROM devices")}
    rows_a = conn.execute("SELECT up, rtt_ms FROM checks WHERE device_id = ? ORDER BY id", (ids[A[0]],)).fetchall()
    rows_b = conn.execute("SELECT up, rtt_ms FROM checks WHERE device_id = ? ORDER BY id", (ids[B[0]],)).fetchall()
    assert [(r["up"], r["rtt_ms"]) for r in rows_a] == [(1, 2.5), (1, 3.5)]
    assert [(r["up"], r["rtt_ms"]) for r in rows_b] == [(1, None), (0, None)]
    conn.close()

    client = TestClient(create_app(settings, db_path=db), headers={"Authorization": "Bearer secret"})
    with client:
        overview = {d["ip"]: d for d in client.get("/api/uptime?bars=10").json()}
        assert overview[A[0]]["bars"] == [1, 1] and overview[A[0]]["up_24h"] == 100.0
        assert overview[B[0]]["bars"] == [1, 0] and overview[B[0]]["up_24h"] == 50.0
        assert overview[B[0]]["online"] is False

        detail = client.get(f"/api/devices/{ids[A[0]]}/uptime").json()
        assert detail["up_24h"] == 100.0 and detail["avg_rtt_ms"] == 3.0
        assert [c["up"] for c in detail["checks"]] == [True, True]

        assert client.get("/api/devices/9999/uptime").status_code == 404
        assert client.get("/api/uptime?bars=0").status_code == 422
        assert client.get("/api/uptime", headers={"Authorization": "Bearer no"}).status_code == 401
