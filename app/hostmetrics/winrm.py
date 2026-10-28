"""WinRM (Windows Remote Management, the protocol behind PowerShell remoting) for the health readings of a Windows computer.

One fixed, read-only PowerShell script is run in a remote command shell (the same script as for Windows over SSH, see ssh.py),
and its JSON answer is parsed there. This is a small WinRM client: the SOAP messages of a command shell, and the NTLM login
(NTLMv2, with its own MD4) or Basic login. It works over HTTPS (port 5986), where the connection is encrypted; Windows
refuses NTLM over plain HTTP unless the traffic is sealed, which this client does not do (Basic over http is possible only
when the server allows unencrypted Basic, and is refused here for addresses that are not on a private network).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import os
import re
import socket
import ssl
import struct
import time
import uuid
import xml.etree.ElementTree as ET

from app import safexml

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
TIMEOUT_TOTAL = 60


class WinrmError(Exception):
    pass


class AuthRefused(WinrmError):
    """The login was refused."""


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
        raise WinrmError("the server did not answer with an NTLM challenge")
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


ALLOW_PLAIN_HTTP = True      # the application sets it from Settings → Hosts (default there: off). Over plain http only Basic works, and Basic sends the password in clear text.
PLAIN_HTTP_REFUSED = ("WinRM over plain http (port 5985) is switched off: Netlens could only log in with Basic, which sends the Windows password unencrypted over the network. "
                      "Use https (port 5986: Settings → Hosts shows how to switch it on), or allow plain http there if this is a lab")


class Session:
    def __init__(self, host, port, https, username, password, auth="ntlm", verify_tls=False, timeout=30):
        if not https and not ALLOW_PLAIN_HTTP:
            raise WinrmError(PLAIN_HTTP_REFUSED)
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
                    raise WinrmError(f"{self.id} closed the connection: {exc}")
                continue
            except ssl.SSLError as exc:
                raise WinrmError(f"cannot make a secure connection to {self.id}: {exc.reason or exc}. Check that the HTTPS listener exists (port 5986); a self-signed certificate is fine when 'Verify TLS certificate' is off")
            except socket.timeout:
                raise WinrmError(f"{self.id} did not answer within {self.timeout:g} seconds")
            except OSError as exc:
                raise WinrmError(f"cannot reach {self.id}: {exc.strerror or exc}")
            if status == 401:
                if attempt == 1 and self.negotiated:        # the connection lost its login: log in again once
                    self.close()
                    continue
                raise AuthRefused(f"{self.id} refused the login: wrong user name or password, or this account may not use remote management (it must be a member of Remote Management Users)")
            if status in (200, 500) and text.lstrip().startswith("<"):
                try:
                    root = safexml.fromstring(text)
                except (ET.ParseError, safexml.UnsafeXml):
                    raise WinrmError(f"{self.id} sent an answer that is not XML (or one Netlens refuses: a DOCTYPE or entities)")
                fault = _fault_text(root)
                if fault:
                    if "(code 5)" in fault or "access is denied" in fault.lower():
                        raise AuthRefused(f"{self.id} says access is denied: the account must be a member of the local group 'Remote Management Users' (on Windows in another language it has another name), and WinRM must let that group open a shell")
                    raise WinrmError(f"{self.id} reported: {fault[:300]}")
                return root
            raise WinrmError(f"{self.id} answered HTTP {status}" + (" (the WinRM service is probably not listening on this port or protocol)" if status in (404, 405) else ""))
        raise WinrmError(f"{self.id} did not answer")

    def _post_once(self, data):
        if self.auth == "basic":
            token = base64.b64encode(f"{(self.domain + chr(92)) if self.domain else ''}{self.user}:{self.password}".encode()).decode()
            return self._send(data, {"Authorization": "Basic " + token})
        if self.negotiated:
            return self._send(data)
        if not self.https:
            raise WinrmError("NTLM needs https (port 5986): over plain http Windows wants the messages sealed, which Netlens cannot do. Use https, or switch the login to Basic if the server allows unencrypted Basic")
        match = status = response = None
        for scheme in ("Negotiate", "NTLM"):         # Windows takes the NTLM message under either name
            if scheme == "NTLM":
                self._connect()
            status, _, response = self._send(b"", {"Authorization": f"{scheme} " + base64.b64encode(ntlm_negotiate()).decode(), "Content-Length": "0"})
            match = re.search(r"(?:Negotiate|NTLM)\s+([A-Za-z0-9+/=]+)", response.getheader("WWW-Authenticate") or "")
            if status == 401 and match:
                break
        if status != 401 or not match:
            raise WinrmError(f"{self.id} does not offer NTLM login (answered HTTP {status}). Check that Negotiate authentication is enabled in WinRM")
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

    def run_powershell(self, script, total=None):
        """Run a script and return (stdout text, stderr text, exit code). `total` is how long it may take (seconds)."""
        total = total or TIMEOUT_TOTAL
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        root = self.post(self.envelope(
            "create", "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>",
            options={"WINRS_NOPROFILE": "TRUE", "WINRS_CODEPAGE": "65001"}))
        shell = root.find(f".//{NS_RSP}ShellId")
        if shell is None or not shell.text:
            raise WinrmError(f"{self.id} did not create a shell")
        shell_id = shell.text
        try:
            root = self.post(self.envelope(
                "command", f"<rsp:CommandLine><rsp:Command>powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}</rsp:Command></rsp:CommandLine>",
                shell_id, {"WINRS_CONSOLEMODE_STDIN": "TRUE", "WINRS_SKIP_CMD_SHELL": "FALSE"}))
            command = root.find(f".//{NS_RSP}CommandId")
            if command is None or not command.text:
                raise WinrmError(f"{self.id} did not start the command")
            command_id = command.text
            out, err, code = [], [], None
            deadline = time.monotonic() + total
            while time.monotonic() < deadline:
                try:
                    root = self.post(self.envelope(
                        "receive", f'<rsp:Receive><rsp:DesiredStream CommandId="{_xml(command_id)}">stdout stderr</rsp:DesiredStream></rsp:Receive>', shell_id))
                except WinrmError as exc:
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
                raise WinrmError(f"{self.id}: the script did not finish within {total} seconds")
            return b"".join(out).decode("utf-8", "replace"), b"".join(err).decode("utf-8", "replace"), code
        finally:
            try:
                self.post(self.envelope("delete", "", shell_id))
            except WinrmError:
                pass
            self.close()


def powershell_error(text):
    """The readable part of what PowerShell wrote to stderr (it arrives as CLIXML). Progress records are not errors: they give ''."""
    parts = re.findall(r'<S S="Error">(.*?)</S>', text or "", re.S)
    if not parts and "CLIXML" in (text or ""):
        return ""
    message = "".join(parts) if parts else re.sub(r"<[^>]+>", "", text or "")
    message = re.sub(r"_x([0-9A-Fa-f]{4})_", lambda m: chr(int(m.group(1), 16)), message)
    return re.sub(r"\s+", " ", message).strip().replace("#< CLIXML", "").strip()[:400]
