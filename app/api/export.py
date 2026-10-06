import csv
import io
import json
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from app.api.devices import get_conn
import sqlite3

router = APIRouter(prefix="/api/export", tags=["export"])


def _csv_safe(value: str) -> str:
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _build_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = conn.execute(
        """
        SELECT
            id,
            custom_name,
            hostname,
            primary_ip,
            mac,
            vendor,
            type_override,
            device_type,
            os_name,
            os_confidence,
            online,
            first_seen,
            last_seen,
            tags,
            notes
        FROM devices
        ORDER BY primary_ip, id
        """
    )
    for row in cursor.fetchall():
        device_id = row["id"]
        name = row["custom_name"] or row["hostname"] or row["primary_ip"]
        ip = row["primary_ip"]
        mac = row["mac"]
        hostname = row["hostname"]
        vendor = row["vendor"]
        device_type = row["type_override"] or row["device_type"] or "unknown"
        os_name = row["os_name"]
        os_confidence = row["os_confidence"]
        online = bool(row["online"])
        first_seen = row["first_seen"]
        last_seen = row["last_seen"]
        tags_str = row["tags"] or ""
        tags_list = [t.strip() for t in tags_str.split(",") if t.strip()]
        notes = row["notes"] or ""

        ports_cursor = conn.execute(
            """
            SELECT proto, port, service
            FROM ports
            WHERE device_id = ? AND state LIKE 'open%'
            ORDER BY proto, port
            """,
            (device_id,),
        )
        open_ports = []
        for p in ports_cursor.fetchall():
            proto = p["proto"]
            port = p["port"]
            service = p["service"]
            if service:
                open_ports.append(f"{proto}/{port}/{service}")
            else:
                open_ports.append(f"{proto}/{port}")

        rows.append(
            {
                "id": device_id,
                "name": name,
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "type": device_type,
                "os": os_name,
                "os_confidence": os_confidence,
                "online": online,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "tags": tags_list,
                "notes": notes,
                "open_ports": open_ports,
            }
        )
    return rows


@router.get("/devices.json")
def export_devices_json(
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
) -> JSONResponse:
    rows = _build_rows(conn)
    content = json.dumps(rows, ensure_ascii=False)
    headers = {
        "Content-Disposition": 'attachment; filename="netlens-devices.json"',
    }
    return JSONResponse(content=rows, headers=headers)


@router.get("/devices.csv")
def export_devices_csv(
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
) -> Response:
    rows = _build_rows(conn)

    fieldnames = [
        "id",
        "name",
        "ip",
        "mac",
        "hostname",
        "vendor",
        "type",
        "os",
        "os_confidence",
        "online",
        "first_seen",
        "last_seen",
        "tags",
        "notes",
        "open_ports",
    ]

    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(fieldnames)

    for row in rows:
        csv_row = [
            _csv_safe(str(row["id"])),
            _csv_safe(str(row["name"])),
            _csv_safe(str(row["ip"])),
            _csv_safe(str(row["mac"])),
            _csv_safe(str(row["hostname"])),
            _csv_safe(str(row["vendor"])),
            _csv_safe(str(row["type"])),
            _csv_safe(str(row["os"])),
            _csv_safe(str(row["os_confidence"])),
            _csv_safe(str(row["online"])),
            _csv_safe(str(row["first_seen"])),
            _csv_safe(str(row["last_seen"])),
            _csv_safe(", ".join(row["tags"])),
            _csv_safe(str(row["notes"])),
            _csv_safe(" ".join(row["open_ports"])),
        ]
        writer.writerow(csv_row)

    content = buffer.getvalue()
    headers = {
        "Content-Disposition": 'attachment; filename="netlens-devices.csv"',
    }
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )