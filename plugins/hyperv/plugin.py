"""Netlens plugin for Microsoft Hyper-V (kind "hypervisor").

Talks to Windows Remote Management (WinRM, the protocol behind PowerShell remoting) and runs ONE fixed, read-only PowerShell script
(it only reads the Hyper-V management data with `Get-CimInstance`, nothing else) that prints the virtual machines as JSON. Only the Python standard library is available to plugins, so this
file contains a small WinRM client: the SOAP messages of a remote command shell, and the NTLM login (NTLMv2, with its own MD4) or
Basic login. It only works over HTTPS (port 5986), where the connection itself is encrypted; Windows refuses NTLM over plain HTTP
unless the traffic is sealed, which this client does not do.

    Create shell -> run `powershell -EncodedCommand <script>` -> read stdout until the command is done -> delete shell
"""

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

SCRIPT = r"""$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$ns='root\virtualization\v2'
$st=@{2='Running';3='Off';6='Saved';9='Paused';32768='Paused';32769='Saved';32770='Starting';32773='Saving';32774='Stopping';32776='Pausing';32777='Resuming'}
$au=@{2='Nothing';3='StartIfRunning';4='Start'}
$sw=@{};Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualEthernetSwitch|ForEach-Object{$sw[$_.Name]=$_.ElementName}
function Rel($o,$c){@(Get-CimAssociatedInstance -InputObject $o -ResultClassName $c)}
$vms=@(Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Caption='Virtual Machine'"|ForEach-Object{$v=$_
$s=@(Get-CimAssociatedInstance -InputObject $v -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData)|Select-Object -First 1
if(-not $s){return}
$al=@(Rel $s 'Msvm_EthernetPortAllocationSettingData')
$ports=@(@(Rel $s 'Msvm_SyntheticEthernetPortSettingData')+@(Rel $s 'Msvm_EmulatedEthernetPortSettingData'))
[pscustomobject]@{Id=[string]$v.Name;Name=[string]$v.ElementName;State=[string]$st[[int]$v.EnabledState];Cpu=[int](Rel $s 'Msvm_ProcessorSettingData'|Select-Object -First 1).VirtualQuantity
Mem=[int64](Rel $s 'Msvm_MemorySettingData'|Select-Object -First 1).VirtualQuantity;Gen=[int]($s.VirtualSystemSubType -replace '.*:','');Up=[int64]($v.OnTimeInMilliseconds/1000);Auto=[string]$au[[int]$s.AutomaticStartupAction]
Nics=@($ports|ForEach-Object{$p=$_;$a=$al|Where-Object{$_.Parent -and ([string]$_.Parent).Replace('\\','\').Contains([string]$p.InstanceID)}|Select-Object -First 1
$sn='';if($a -and $a.HostResource){$m=[regex]::Match([string]$a.HostResource[0],',Name="([^"]+)"');if($m.Success){$sn=[string]$sw[$m.Groups[1].Value]}}
$ips=@();if($p.CimClass.CimClassName -eq 'Msvm_SyntheticEthernetPortSettingData'){$g=Rel $p 'Msvm_GuestNetworkAdapterConfiguration'|Select-Object -First 1;if($g){$ips=@($g.IPAddresses)}}
[pscustomobject]@{Mac=[string]$p.Address;Ips=$ips;Switch=$sn}})}})
[pscustomobject]@{Host=$env:COMPUTERNAME;Vms=$vms}|ConvertTo-Json -Depth 5 -Compress"""

SOAP_ACTIONS = {
    "create": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
    "delete": "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
    "command": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
    "receive": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
    "signal": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
}
SHELL_URI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
NS_RSP = "{http://schemas.microsoft.com/wbem/wsman/1/windows/shell}"
NS_SOAP = "{http://www.w3.org/2003/05/soap-envelope}"
STATE_RUNNING = {"running": "running", "off": "stopped", "paused": "paused", "saved": "saved", "starting": "starting", "stopping": "stopping"}
TIMEOUT_TOTAL = 90


class HyperVError(Exception):
    pass


class AuthRefused(HyperVError):
    auth_failed = True      # the login was refused: Netlens stops asking until the settings are saved again


# ----------------------------------------------------------------------------- MD4 and NTLMv2
def md4(message):
    """MD4 (RFC 1320). Python's hashlib may not have it any more, and NTLM needs it for the password hash."""
    mask = 0xFFFFFFFF

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    length = len(message)
    message += b"\x80" + b"\x00" * ((55 - length) % 64) + struct.pack("<Q", length * 8)
    for offset in range(0, len(message), 64):
        x = struct.unpack("<16I", message[offset:offset + 64])
        a, b, c, d = state
        for i in range(16):
            a = rol((a + ((b & c) | (~b & d)) + x[i]) & mask, (3, 7, 11, 19)[i % 4])
            a, b, c, d = d, a, b, c
        for i in range(16):
            a = rol((a + ((b & c) | (b & d) | (c & d)) + x[(i % 4) * 4 + i // 4] + 0x5A827999) & mask, (3, 5, 9, 13)[i % 4])
            a, b, c, d = d, a, b, c
        for i in range(16):
            a = rol((a + (b ^ c ^ d) + x[(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i]] + 0x6ED9EBA1) & mask, (3, 9, 11, 15)[i % 4])
            a, b, c, d = d, a, b, c
        state = [(s + v) & mask for s, v in zip(state, (a, b, c, d))]
    return struct.pack("<4I", *state)


def _hmac_md5(key, data):
    return hmac.new(key, data, hashlib.md5).digest()


def nt_hash_v2(user, password, domain):
    """NTOWFv2 (MS-NLMP 3.3.2)."""
    return _hmac_md5(md4(password.encode("utf-16-le")), (user.upper() + domain).encode("utf-16-le"))


def ntlm_negotiate():
    flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000 | 0x00080000 | 0x20000000 | 0x80000000   # unicode, target, NTLM, always sign, extended session security, 128, 56
    return b"NTLMSSP\x00" + struct.pack("<III", 1, flags, 0) + struct.pack("<HHI", 0, 0, 0) * 2


def _av_pairs(info):
    pairs, pos = {}, 0
    while pos + 4 <= len(info):
        kind, length = struct.unpack_from("<HH", info, pos)
        if kind == 0:
            break
        pairs[kind] = info[pos + 4:pos + 4 + length]
        pos += 4 + length
    return pairs


def _without_flags(info):
    out, pos = b"", 0
    while pos + 4 <= len(info):
        kind, length = struct.unpack_from("<HH", info, pos)
        if kind == 0:
            break
        if kind != 6:         # MsvAvFlags
            out += info[pos:pos + 4 + length]
        pos += 4 + length
    return out + b"\x00\x00\x00\x00"


def ntlm_authenticate(challenge_message, user, password, domain="", workstation="", client_challenge=None, timestamp=None):
    """Answer the server's NTLM challenge (message 2) with message 3 (NTLMv2, no sealing)."""
    if challenge_message[:8] != b"NTLMSSP\x00" or struct.unpack_from("<I", challenge_message, 8)[0] != 2:
        raise HyperVError("the server did not answer with an NTLM challenge")
    flags = struct.unpack_from("<I", challenge_message, 20)[0]
    server_challenge = challenge_message[24:32]
    length, _, offset = struct.unpack_from("<HHI", challenge_message, 40)
    target_info = challenge_message[offset:offset + length]
    stamp = _av_pairs(target_info).get(7)
    target_info = _without_flags(target_info)        # we send no MIC, so we must not echo a "MIC provided" flag
    if stamp is None:
        stamp = timestamp if timestamp is not None else struct.pack("<Q", int((time.time() + 11644473600) * 10_000_000))
    client_challenge = client_challenge or os.urandom(8)
    key = nt_hash_v2(user, password, domain)
    blob = b"\x01\x01\x00\x00\x00\x00\x00\x00" + stamp + client_challenge + b"\x00\x00\x00\x00" + target_info + b"\x00\x00\x00\x00"
    proof = _hmac_md5(key, server_challenge + blob)
    nt_response = proof + blob
    lm_response = _hmac_md5(key, server_challenge + client_challenge) + client_challenge
    unicode_flag = flags & 0x1
    enc = "utf-16-le" if unicode_flag else "latin-1"
    fields = [lm_response, nt_response, domain.encode(enc), user.encode(enc), workstation.encode(enc), b""]
    offset = 64
    header, payload = b"NTLMSSP\x00" + struct.pack("<I", 3), b""
    for data in fields:
        header += struct.pack("<HHI", len(data), len(data), offset + len(payload))
        payload += data
    return header + struct.pack("<I", (flags & (0x1 | 0x200 | 0x8000 | 0x80000 | 0x20000000 | 0x80000000)) | 0x4) + payload


# ----------------------------------------------------------------------------- WinRM
def _xml(text):
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _fault_text(root):
    fault = root.find(f".//{NS_SOAP}Fault")
    if fault is None:
        return None
    reason = " ".join((t.text or "") for t in fault.iter() if t.tag.endswith("}Text")).strip()
    wsman = [t for t in fault.iter() if t.tag.endswith("}WSManFault")]
    number = wsman[0].get("Code") if wsman else None          # for example 2150858793 (nothing to report yet) or 5 (access denied)
    detail = " ".join((t.text or "") for t in fault.iter() if t.tag.endswith("}Message")).strip()
    return " ".join(x for x in (reason, detail if detail != reason else "", f"(code {number})" if number else "") if x) or "the server reported an error"


class Session:
    def __init__(self, host, port, https, username, password, auth="ntlm", verify_tls=False, timeout=30):
        self.host, self.port, self.https = host, port, https
        user, domain = username, ""
        if "\\" in username:
            domain, user = username.split("\\", 1)
        self.user, self.domain, self.password = user, domain, password
        self.auth = auth
        self.timeout = float(timeout)
        self.context = None
        if https:
            self.context = ssl.create_default_context()
            if not verify_tls:
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE
        self.url = f"{'https' if https else 'http'}://{host}:{port}/wsman"
        self.conn = None
        self.negotiated = False
        self.id = f"{host}:{port}"

    # -- transport
    def _connect(self):
        self.close()
        self.negotiated = False
        cls = http.client.HTTPSConnection if self.https else http.client.HTTPConnection
        kwargs = {"context": self.context} if self.https else {}
        self.conn = cls(self.host, self.port, timeout=self.timeout, **kwargs)

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None

    def _send(self, body, extra=None):
        headers = {"Content-Type": "application/soap+xml;charset=UTF-8", "User-Agent": "Netlens", "Connection": "keep-alive", **(extra or {})}
        self.conn.request("POST", "/wsman", body=body, headers=headers)
        response = self.conn.getresponse()
        return response.status, response.read().decode("utf-8", "replace"), response

    def post(self, envelope):
        """Send one SOAP message and return the parsed reply; raises on a refused login or a SOAP fault."""
        data = envelope.encode("utf-8")
        for attempt in (1, 2):
            if self.conn is None:
                self._connect()
            try:
                status, text, response = self._post_once(data)
            except (http.client.HTTPException, ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
                self.close()
                if attempt == 2:
                    raise HyperVError(f"{self.id} closed the connection: {exc}")
                continue
            except ssl.SSLError as exc:
                raise HyperVError(f"cannot make a secure connection to {self.id}: {exc.reason or exc}. Check that the HTTPS listener exists (port 5986); a self-signed certificate is fine when 'Verify TLS certificate' is off")
            except socket.timeout:
                raise HyperVError(f"{self.id} did not answer within {self.timeout:g} seconds")
            except OSError as exc:
                raise HyperVError(f"cannot reach {self.id}: {exc.strerror or exc}")
            if status == 401:
                if attempt == 1 and self.negotiated:        # the connection lost its login: log in again once
                    self.close()
                    continue
                raise AuthRefused(f"{self.id} refused the login: wrong user name or password, or this account may not use remote management (it must be a member of Remote Management Users)")
            if status in (200, 500) and text.lstrip().startswith("<"):
                try:
                    root = ET.fromstring(text)
                except ET.ParseError:
                    raise HyperVError(f"{self.id} sent an answer that is not XML")
                fault = _fault_text(root)
                if fault:
                    if "(code 5)" in fault or "access is denied" in fault.lower():
                        raise AuthRefused(f"{self.id} says access is denied: the account must be a member of the local groups 'Remote Management Users' and 'Hyper-V Administrators' (on Windows in another language they have another name). Run the last line of the setup box on the host to see who is in them, then try again")
                    raise HyperVError(f"{self.id} reported: {fault[:300]}")
                return root
            raise HyperVError(f"{self.id} answered HTTP {status}" + (" (the WinRM service is probably not listening on this port or protocol)" if status in (404, 405) else ""))
        raise HyperVError(f"{self.id} did not answer")

    def _post_once(self, data):
        if self.auth == "basic":
            token = base64.b64encode(f"{(self.domain + chr(92)) if self.domain else ''}{self.user}:{self.password}".encode()).decode()
            return self._send(data, {"Authorization": "Basic " + token})
        if self.negotiated:
            return self._send(data)
        if not self.https:
            raise HyperVError("NTLM needs https (port 5986): over plain http Windows wants the messages sealed, which Netlens cannot do. Use https, or switch the login to Basic if the server allows unencrypted Basic")
        match = status = response = None
        for scheme in ("Negotiate", "NTLM"):         # Windows takes the NTLM message under either name
            if scheme == "NTLM":
                self._connect()
            status, _, response = self._send(b"", {"Authorization": f"{scheme} " + base64.b64encode(ntlm_negotiate()).decode(), "Content-Length": "0"})
            match = re.search(r"(?:Negotiate|NTLM)\s+([A-Za-z0-9+/=]+)", response.getheader("WWW-Authenticate") or "")
            if status == 401 and match:
                break
        if status != 401 or not match:
            raise HyperVError(f"{self.id} does not offer NTLM login (answered HTTP {status}). Check that Negotiate authentication is enabled in WinRM")
        message = ntlm_authenticate(base64.b64decode(match.group(1)), self.user, self.password, self.domain)
        result = self._send(data, {"Authorization": f"{scheme} " + base64.b64encode(message).decode()})
        if result[0] != 401:
            self.negotiated = True
        return result

    # -- messages
    def envelope(self, action, body, shell_id=None, options=None):
        selector = f'<w:SelectorSet><w:Selector Name="ShellId">{_xml(shell_id)}</w:Selector></w:SelectorSet>' if shell_id else ""
        option_set = "<w:OptionSet>" + "".join(f'<w:Option Name="{k}">{v}</w:Option>' for k, v in (options or {}).items()) + "</w:OptionSet>" if options else ""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
            f'<s:Header><a:To>{_xml(self.url)}</a:To><w:ResourceURI s:mustUnderstand="true">{SHELL_URI}</w:ResourceURI>'
            '<a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>'
            f'<a:Action s:mustUnderstand="true">{SOAP_ACTIONS[action]}</a:Action><w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>'
            f'<a:MessageID>uuid:{str(uuid.uuid4()).upper()}</a:MessageID><w:Locale xml:lang="en-US" s:mustUnderstand="false"/>'
            f'<w:OperationTimeout>PT20S</w:OperationTimeout>{selector}{option_set}</s:Header><s:Body>{body}</s:Body></s:Envelope>'
        )

    def run_powershell(self, script):
        """Run a script and return (stdout text, stderr text, exit code)."""
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        root = self.post(self.envelope(
            "create", "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>",
            options={"WINRS_NOPROFILE": "TRUE", "WINRS_CODEPAGE": "65001"}))
        shell = root.find(f".//{NS_RSP}ShellId")
        if shell is None or not shell.text:
            raise HyperVError(f"{self.id} did not create a shell")
        shell_id = shell.text
        try:
            root = self.post(self.envelope(
                "command", f"<rsp:CommandLine><rsp:Command>powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}</rsp:Command></rsp:CommandLine>",
                shell_id, {"WINRS_CONSOLEMODE_STDIN": "TRUE", "WINRS_SKIP_CMD_SHELL": "FALSE"}))
            command = root.find(f".//{NS_RSP}CommandId")
            if command is None or not command.text:
                raise HyperVError(f"{self.id} did not start the command")
            command_id = command.text
            out, err, code = [], [], None
            deadline = time.monotonic() + TIMEOUT_TOTAL
            while time.monotonic() < deadline:
                try:
                    root = self.post(self.envelope(
                        "receive", f'<rsp:Receive><rsp:DesiredStream CommandId="{_xml(command_id)}">stdout stderr</rsp:DesiredStream></rsp:Receive>', shell_id))
                except HyperVError as exc:
                    if "2150858793" in str(exc) or "timed out" in str(exc).lower():     # nothing to report yet: ask again
                        continue
                    raise
                for stream in root.iter(f"{NS_RSP}Stream"):
                    chunk = base64.b64decode(stream.text or "")
                    (out if stream.get("Name") == "stdout" else err).append(chunk)
                state = root.find(f".//{NS_RSP}CommandState")
                if state is not None and (state.get("State") or "").endswith("Done"):
                    exit_code = state.find(f"{NS_RSP}ExitCode")
                    code = int(exit_code.text) if exit_code is not None and (exit_code.text or "").lstrip("-").isdigit() else 0
                    break
            if code is None:
                raise HyperVError(f"{self.id}: the script did not finish within {TIMEOUT_TOTAL} seconds")
            return b"".join(out).decode("utf-8", "replace"), b"".join(err).decode("utf-8", "replace"), code
        finally:
            try:
                self.post(self.envelope("delete", "", shell_id))
            except HyperVError:
                pass
            self.close()


def powershell_error(text):
    """The readable part of what PowerShell wrote to stderr (it arrives as CLIXML)."""
    parts = re.findall(r'<S S="Error">(.*?)</S>', text or "", re.S)
    message = "".join(parts) if parts else re.sub(r"<[^>]+>", "", text or "")
    message = re.sub(r"_x([0-9A-Fa-f]{4})_", lambda m: chr(int(m.group(1), 16)), message)
    return re.sub(r"\s+", " ", message).strip().replace("#< CLIXML", "").strip()[:400]


# ----------------------------------------------------------------------------- reading
def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def parse_target(row, config):
    """(host, port, https, auth) from a row of the server list."""
    text = str(row.get("host") or "").strip()
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HyperVError(f"{row.get('host')!r} is not an address like https://192.168.0.115:5986")
    https = parts.scheme == "https"
    return parts.hostname, parts.port or (5986 if https else 5985), https


def make_session(row, config):
    host, port, https = parse_target(row, config)
    if not str(row.get("username") or "").strip() or not row.get("password"):
        raise AuthRefused(f"{host}: enter the user name and password of the Netlens user on that Windows machine")
    s = Session(host, port, https, str(row["username"]).strip(), str(row["password"]), config.get("auth") or "ntlm", config.get("verify_tls", False), config.get("timeout") or 30)
    s.lan_ip = _ipv4(row.get("lan")) if str(row.get("lan") or "").strip() else None
    if str(row.get("lan") or "").strip() and not s.lan_ip:
        raise HyperVError(f"{row.get('lan')!r} (the host's own address) is not an IPv4 address")
    return s


def parse_servers(config):
    rows = config.get("servers")
    sessions = [make_session(r, config) for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not sessions:
        raise ValueError("enter the address, user name and password of your Hyper-V host")
    return sessions


def _mac(value):
    hexes = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(hexes) != 12 or set(hexes) == {"0"}:
        return None            # a dynamic address that has not been assigned yet
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).lower()


def _as_list(value):
    return value if isinstance(value, list) else [] if value in (None, "") else [value]


def parse_output(stdout, session, now=None):
    """The host entry and guests from the JSON the script printed."""
    start = stdout.find("{")
    if start < 0:
        raise HyperVError(f"{session.id} did not return any data")
    try:
        data = json.loads(stdout[start:])
    except ValueError:
        raise HyperVError(f"{session.id} returned data that is not JSON")
    now = now or datetime.now(timezone.utc)
    ip = session.lan_ip or _ipv4(session.host)
    if ip is None:
        try:
            ip = _ipv4(socket.gethostbyname(session.host))
        except OSError:
            ip = None
    host = {"id": session.id, "name": str(data.get("Host") or session.host)[:100], "ip": ip, "online": True}
    guests = []
    for vm in _as_list(data.get("Vms")):
        if not isinstance(vm, dict) or not vm.get("Id"):
            continue
        state = str(vm.get("State") or "unknown")
        nics = [n for n in _as_list(vm.get("Nics")) if isinstance(n, dict)]
        ips = []
        for nic in nics:
            for address in _as_list(nic.get("Ips")):
                a = _ipv4(address)
                if a and not a.startswith("169.254.") and a not in ips:
                    ips.append(a)
        macs = [m for m in (_mac(n.get("Mac")) for n in nics) if m]
        memory = vm.get("Mem") or vm.get("MemStartup")
        details = {"cpus": vm.get("Cpu"), "memory_mb": memory, "autostart": str(vm.get("Auto") or "Nothing").lower() not in ("nothing", ""),
                   "network": ", ".join(sorted({str(n.get("Switch")) for n in nics if n.get("Switch")}))[:200], "version": f"generation {vm['Gen']}" if vm.get("Gen") else ""}
        if state.lower() == "running" and isinstance(vm.get("Up"), (int, float)) and vm["Up"] > 0:
            details["started"] = (now - timedelta(seconds=vm["Up"])).strftime("%Y-%m-%dT%H:%M:%SZ")
        guests.append({
            "id": f"{session.id}/{vm['Id']}", "name": str(vm.get("Name") or vm["Id"])[:100], "kind": "vm", "host_id": session.id,
            "status": STATE_RUNNING.get(state.lower(), state.lower())[:30], "macs": macs, "ips": ips,
            "details": {k: v for k, v in details.items() if v not in ("", None) and not (k == "autostart" and v is False)},
        })
    return host, guests


def read_host(session):
    try:
        out, err, code = session.run_powershell(SCRIPT)
    finally:
        session.close()
    if code != 0 or not out.strip():
        message = powershell_error(err)
        if "invalid namespace" in message.lower() or "not recognized" in message:
            raise HyperVError(f"{session.id}: Hyper-V is not installed on that machine (its management interface does not exist)")
        if "required permission" in message or "access" in message.lower() and "denied" in message.lower():
            raise AuthRefused(f"{session.id}: the user may not manage Hyper-V. Add it to the local group 'Hyper-V Administrators'")
        raise HyperVError(f"{session.id}: the script failed" + (f": {message}" if message else f" (exit code {code})"))
    return parse_output(out, session)


def connect(config):
    hosts, guests, problems = [], [], []
    for session in parse_servers(config):
        try:
            host, found = read_host(session)
        except AuthRefused:
            raise
        except HyperVError as exc:
            problems.append(str(exc))
            continue
        hosts.append(host)
        guests.extend(found)
    if not hosts:
        raise HyperVError("; ".join(problems) or "no Hyper-V host answered")
    return hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    hosts, guests, problems = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    message = f"Connected to {len(hosts)} Hyper-V host(s): {len(guests)} virtual machine(s), {running} running"
    if any(h["ip"] is None for h in hosts):
        message += ". Fill in 'Host\'s own address' so Netlens can find the host's device"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://\S+", "<host>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<host>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<host>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<host>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """How far the connection gets, as yes/no and counts (no names, addresses or accounts)."""
    try:
        sessions = parse_servers(config)
    except (ValueError, HyperVError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for session in sessions:
        entry = {"steps": {}, "https": session.https, "auth": session.auth, "port": session.port}
        report["servers"].append(entry)
        try:
            out, err, code = session.run_powershell("$PSVersionTable.PSVersion.ToString()")
            version = re.match(r"\d+(\.\d+){0,3}", out.strip())
            entry["steps"]["login_and_shell"] = {"ok": True, "powershell": version.group(0) if version else ""}
        except HyperVError as exc:
            entry["steps"]["login_and_shell"] = {"ok": False, "error": _problem(exc)}
            continue
        try:
            host, guests = read_host(session)
            states = {}
            for g in guests:
                states[g["status"]] = states.get(g["status"], 0) + 1
            entry["steps"]["get_vm"] = {"ok": True, "vms": len(guests), "states": states, "with_mac": sum(1 for g in guests if g["macs"]), "with_ip": sum(1 for g in guests if g["ips"])}
        except HyperVError as exc:
            entry["steps"]["get_vm"] = {"ok": False, "error": _problem(exc)}
    return report
