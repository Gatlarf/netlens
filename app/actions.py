"""Actions on one device: Wake-on-LAN, ping and traceroute (both through nmap, which already has the raw-socket rights)."""

import asyncio
import ipaddress
import re
import socket

from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.nmap_runner import ScanError, _is_valid_target

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
WOL_PORTS = (9, 7)


class ActionError(RuntimeError):
    pass


def magic_packet(mac: str) -> bytes:
    if not MAC_RE.match(mac or ""):
        raise ActionError("this device has no valid MAC address")
    raw = bytes.fromhex(mac.replace(":", ""))
    return b"\xff" * 6 + raw * 16


def broadcast_targets(ip: str | None) -> list[str]:
    """Where to send the packet: the limited broadcast and, when the IP is known, the broadcast of its /24."""
    targets = ["255.255.255.255"]
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None and addr.version == 4:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            targets.append(str(net.broadcast_address))
    return targets


def wake(mac: str, ip: str | None = None, sender=None) -> list[str]:
    """Send a Wake-on-LAN magic packet. Returns the addresses it was sent to."""
    packet = magic_packet(mac)
    sent: list[str] = []
    send = sender or _send_udp_broadcast
    errors = []
    for target in broadcast_targets(ip):
        for port in WOL_PORTS:
            try:
                send(packet, target, port)
                if target not in sent:
                    sent.append(target)
            except OSError as exc:
                errors.append(str(exc))
    if not sent:
        raise ActionError("could not send the packet: " + (errors[0] if errors else "no network"))
    return sent


def _send_udp_broadcast(packet: bytes, target: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (target, port))


async def nmap_output(args: list[str], timeout: float, runner=None) -> str:
    """Run nmap with these arguments and return its output (tests pass a `runner`)."""
    if runner is not None:
        return await runner(args)
    try:
        process = await asyncio.create_subprocess_exec("nmap", *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except (FileNotFoundError, OSError) as exc:
        raise ActionError(f"nmap is not available: {exc}")
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise ActionError("timed out")
    except asyncio.CancelledError:
        process.kill()
        raise
    if process.returncode != 0:
        raise ActionError("nmap failed: " + stderr.decode("utf-8", "replace")[-200:])
    return stdout.decode("utf-8", "replace")


def _check(ip: str | None) -> str:
    if not ip or not _is_valid_target(ip) or "/" in ip:
        raise ActionError("this device has no usable IP address")
    return ip


async def ping(ip: str | None, runner=None) -> dict:
    """Is the host answering right now (ARP/ICMP/TCP probes), and how fast."""
    ip = _check(ip)
    xml = await nmap_output(["-sn", "-n", "-oX", "-", ip], 30, runner)
    try:
        hosts = parse_nmap_xml(xml)
    except ValueError as exc:
        raise ActionError(str(exc))
    if not hosts:
        return {"ip": ip, "up": False, "rtt_ms": None}
    return {"ip": ip, "up": True, "rtt_ms": hosts[0].rtt_ms}


async def trace(ip: str | None, runner=None) -> dict:
    """The hops between Netlens and the host."""
    ip = _check(ip)
    xml = await nmap_output(["-sn", "-n", "--traceroute", "-oX", "-", ip], 60, runner)
    try:
        hosts = parse_nmap_xml(xml)
    except ValueError as exc:
        raise ActionError(str(exc))
    if not hosts:
        return {"ip": ip, "up": False, "hops": []}
    return {"ip": ip, "up": True, "hops": list(hosts[0].hops)}
