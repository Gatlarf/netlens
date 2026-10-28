"""The two listeners of the agent ingest (Enterprise) and the job that keeps them in line with the settings.

    ingest      mutual TLS: a client certificate is REQUIRED, so a party without one never reaches the HTTP parser (the handshake fails first).
                POST /v1/metrics (OTLP/HTTP JSON), POST /telegraf (Telegraf / generic JSON), POST /renew (a new certificate for an agent that already has one).
    enrolment   server TLS only, open for a limited window the administrator starts: POST /enrol with `Authorization: Bearer <one-time token>` and a PEM CSR as body.

Netlens only ever *answers* here: there is no request in the other direction, no command, no setting and no update for an agent. The identity of a request comes from
the certificate and is looked up for every single request, so revoking an agent takes effect on its open connections too.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import ssl
import tempfile
import time
import zlib
from typing import Any

import h11

from app import licence
from app.db import connect
from app.ingest import core, parse, pki

log = logging.getLogger(__name__)

MAX_BODY = 1 << 20                # bytes on the wire and again after decompression
MAX_HEADER = 16 * 1024
HEADER_TIMEOUT, BODY_TIMEOUT, WRITE_TIMEOUT, IDLE_TIMEOUT, HANDSHAKE_TIMEOUT = 10.0, 20.0, 10.0, 60.0, 10.0
MAX_REQUESTS_PER_CONNECTION = 200
MAX_CONNECTIONS = 64
MAX_PER_AGENT = 4
MAX_WORKERS = 8
INGEST_BURST, INGEST_REFILL_S = 10, 5.0          # 10 requests at once, then one every 5 seconds: far above any collector's normal rate
ENROL_BURST, ENROL_REFILL_S = 5, 12.0
ENROL_GLOBAL_PER_MIN = 30
ENROL_MAX_BODY = 8192
NOISE_S = 60.0


class Bucket:
    def __init__(self, burst: int, refill_s: float) -> None:
        self.burst, self.refill_s, self.tokens, self.at = burst, refill_s, float(burst), time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.at) / self.refill_s)
        self.at = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class Response:
    def __init__(self, status: int, body: bytes = b"", ctype: str = "application/json", headers: list[tuple[str, str]] | None = None, close: bool = False) -> None:
        self.status, self.body, self.ctype, self.headers, self.close = status, body, ctype, headers or [], close


def _json(status: int, doc: dict[str, Any], **kw: Any) -> Response:
    return Response(status, json.dumps(doc).encode(), **kw)


def _text(status: int, message: str, **kw: Any) -> Response:
    return _json(status, {"error": message}, **kw)


def make_context(cert_pem: str, key_pem: str, trust_pem: str | None) -> ssl.SSLContext:
    """TLS 1.2 or newer; with `trust_pem` a client certificate from one of those CAs is required."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION | getattr(ssl, "OP_NO_RENEGOTIATION", 0) | ssl.OP_CIPHER_SERVER_PREFERENCE
    with tempfile.TemporaryDirectory(prefix="nl-ingest-") as folder:           # a private (0700) folder, gone again as soon as the context has read the files
        cert_file, key_file = os.path.join(folder, "c.pem"), os.path.join(folder, "k.pem")
        for path, text in ((cert_file, cert_pem), (key_file, key_pem)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
        ctx.load_cert_chain(cert_file, key_file)
    if trust_pem is not None:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=trust_pem)
    return ctx


class Control:
    """Owns the listeners; `apply()` makes them match the saved settings (like the SNMP trap and syslog receivers in app/inbound.py)."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.servers: dict[str, asyncio.AbstractServer] = {}
        self.signature: dict[str, tuple] = {}
        self.errors: dict[str, str] = {}
        self.buckets: dict[int, Bucket] = {}
        self.enrol_ips: dict[str, Bucket] = {}
        self.enrol_global = Bucket(ENROL_GLOBAL_PER_MIN, 60.0 / ENROL_GLOBAL_PER_MIN)
        self.connections = 0
        self.per_agent: dict[str, int] = {}
        self.noise: dict[tuple, float] = {}
        self.expiry: dict[str, str] = {}
        self.workers = asyncio.Semaphore(MAX_WORKERS)
        self._apply_lock = asyncio.Lock()          # the API and the background tick both call apply(): one at a time, or two servers fight for one port
        self.last_silence = 0.0
        self.stats = {"requests": 0, "refused": 0}

    # ------------------------------------------------------------------ lifecycle
    def status(self) -> dict[str, Any]:
        return {"listening": {k: True for k in self.servers}, "errors": dict(self.errors), "connections": self.connections, **self.stats}

    def stop(self) -> None:
        for server in self.servers.values():
            server.close()
        self.servers.clear()
        self.signature.clear()

    async def apply(self) -> None:
        async with self._apply_lock:
            await self._apply()

    async def _apply(self) -> None:
        conn = connect(self.db_path)
        try:
            policy = core.get_policy(conn)
            want_ingest = bool(policy["enabled"] and licence.allows(conn, "agents"))
            want_enrol = want_ingest and core.window_open(policy)
            plan: dict[str, tuple] = {}
            ctxs: dict[str, ssl.SSLContext] = {}
            if want_ingest:
                try:
                    server = core.ensure_server(conn)
                    trust = core.trust_bundle(conn)
                    sig = (policy["bind"], policy["port"], pki.fingerprint(pki.load_cert(server["cert"]).public_bytes(pki.serialization.Encoding.DER)), hash(trust))
                    plan["ingest"] = sig
                    if self.signature.get("ingest") != sig or "ingest" not in self.servers:
                        ctxs["ingest"] = make_context(server["cert"], server["key"], trust)
                    if want_enrol:
                        plan["enrol"] = (policy["bind"], policy["enrol_port"], sig[2])
                        if self.signature.get("enrol") != plan["enrol"] or "enrol" not in self.servers:
                            ctxs["enrol"] = make_context(server["cert"], server["key"], None)
                except (core.IngestError, pki.PkiError, ssl.SSLError, OSError, ValueError) as exc:
                    self.errors["ingest"] = f"the server certificate cannot be used: {exc}"
                    plan = {}
                    ctxs = {}
        finally:
            conn.close()
        for kind in list(self.servers):
            if kind not in plan or self.signature.get(kind) != plan[kind]:
                self.servers.pop(kind).close()
                self.signature.pop(kind, None)
        for kind, ctx in ctxs.items():
            host, port = plan[kind][0], plan[kind][1]
            try:
                self.servers[kind] = await asyncio.start_server(lambda r, w, k=kind: self._connection(r, w, k), host, port, ssl=ctx,
                                                                ssl_handshake_timeout=HANDSHAKE_TIMEOUT, backlog=64, reuse_address=True)
                self.signature[kind] = plan[kind]
                self.errors.pop(kind, None)
                self.errors.pop("ingest", None) if kind == "ingest" else None
            except OSError as exc:
                self.errors[kind] = f"cannot listen on {host}:{port}: {exc.strerror or exc}"
        if not want_ingest:
            self.errors.clear()

    async def tick(self) -> None:
        """Every few seconds: follow the settings (this also closes an enrolment window that ran out); once a minute look for silent agents."""
        await self.apply()
        if time.time() - self.last_silence >= 60:
            self.last_silence = time.time()

            def work() -> list[str]:
                conn = connect(self.db_path)
                try:
                    if not licence.allows(conn, "agents"):
                        return []
                    return core.check_silence(conn)
                finally:
                    conn.close()

            raised = await asyncio.to_thread(work)
            if raised:
                from app.notify.channels import process_channels

                await process_channels(self.db_path)

    # ------------------------------------------------------------------ one connection
    async def _read(self, h: h11.Connection, reader: asyncio.StreamReader, timeout: float):
        while True:
            event = h.next_event()
            if event is h11.NEED_DATA:
                data = await asyncio.wait_for(reader.read(65536), timeout)
                h.receive_data(data)
                continue
            return event

    async def _connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, kind: str) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        ip = str(peer[0])[:60]
        ssl_obj = writer.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if (ssl_obj is not None and kind == "ingest") else None
        key = pki.fingerprint(der) if der else ip
        if self.connections >= MAX_CONNECTIONS or (kind == "ingest" and not der) or self.per_agent.get(key, 0) >= MAX_PER_AGENT:
            writer.close()
            return
        self.connections += 1
        self.per_agent[key] = self.per_agent.get(key, 0) + 1
        h = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEADER)
        try:
            for _ in range(MAX_REQUESTS_PER_CONNECTION):
                try:
                    event = await self._read(h, reader, IDLE_TIMEOUT if h.their_state is h11.IDLE else HEADER_TIMEOUT)
                    if isinstance(event, h11.ConnectionClosed):
                        break
                    if not isinstance(event, h11.Request):
                        break
                    request = event
                    limit = MAX_BODY if kind == "ingest" else ENROL_MAX_BODY
                    chunks, size, too_big = [], 0, False

                    async def body() -> None:
                        nonlocal size, too_big
                        while True:
                            ev = await self._read(h, reader, BODY_TIMEOUT)
                            if isinstance(ev, h11.Data):
                                size += len(ev.data)
                                if size > limit:
                                    too_big = True
                                    return
                                chunks.append(bytes(ev.data))
                            elif isinstance(ev, h11.EndOfMessage):
                                return
                            else:
                                raise h11.RemoteProtocolError("unexpected event")

                    await asyncio.wait_for(body(), BODY_TIMEOUT * 2)
                    if too_big:
                        response = _text(413, "the request is too large", close=True)
                    else:
                        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in request.headers}
                        async with self.workers:
                            response = await asyncio.to_thread(self._process, kind, ip, der, request.method.decode("latin-1"), request.target.decode("latin-1"),
                                                               headers, b"".join(chunks))
                    out = [("content-type", response.ctype), ("content-length", str(len(response.body))), ("cache-control", "no-store"),
                           ("x-content-type-options", "nosniff")] + response.headers
                    if response.close:
                        out.append(("connection", "close"))
                    writer.write(h.send(h11.Response(status_code=response.status, headers=out)))
                    writer.write(h.send(h11.Data(data=response.body)))
                    writer.write(h.send(h11.EndOfMessage()))
                    await asyncio.wait_for(writer.drain(), WRITE_TIMEOUT)
                    if response.close or h.our_state is h11.MUST_CLOSE or h.their_state is h11.MUST_CLOSE:
                        break
                    h.start_next_cycle()
                except (asyncio.TimeoutError, h11.ProtocolError, ConnectionError, ssl.SSLError, OSError):
                    break
        except Exception:  # noqa: BLE001 - one broken connection must never stop the listener
            log.exception("ingest connection failed")
        finally:
            self.connections -= 1
            self.per_agent[key] = self.per_agent.get(key, 1) - 1
            if self.per_agent.get(key, 0) <= 0:
                self.per_agent.pop(key, None)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ one request (runs in a worker thread)
    def _quiet(self, ip: str, reason: str) -> bool:
        """True when this kind of refusal from this address was already written down a moment ago (a flood must not flood the log)."""
        now = time.monotonic()
        if len(self.noise) > 2000:
            self.noise = {k: v for k, v in self.noise.items() if now - v < NOISE_S}
        key = (ip, reason)
        if now - self.noise.get(key, -NOISE_S) < NOISE_S:
            return True
        self.noise[key] = now
        return False

    def _refuse(self, conn, ip: str, reason: str, status: int, agent=None, path: str = "/ingest") -> Response:
        self.stats["refused"] += 1
        core.note_rejected(conn, agent["id"] if agent is not None else None)
        if not self._quiet(ip, reason):
            who = f" (agent '{agent['name']}')" if agent is not None else ""
            core._audit(conn, f"Refused a request from {ip or 'unknown'}{who}: {reason}", path, status)
        return _text(status, reason, close=status in (401, 403))

    def _process(self, kind: str, ip: str, der: bytes | None, method: str, target: str, headers: dict[str, str], body: bytes) -> Response:
        conn = connect(self.db_path)
        try:
            self.stats["requests"] += 1
            path = target.split("?", 1)[0]
            policy = core.get_policy(conn)
            if not policy["enabled"] or not licence.allows(conn, "agents"):
                return _text(503, "agent ingest is switched off", close=True)
            if method != "POST":
                return _text(405, "use POST", headers=[("allow", "POST")])
            if kind == "enrol":
                return self._enrol(conn, ip, path, headers, body, policy)
            agent, why = core.find_agent(conn, der or b"")
            if agent is None:
                return self._refuse(conn, ip, why, 403, path=path)
            bucket = self.buckets.setdefault(agent["id"], Bucket(INGEST_BURST, INGEST_REFILL_S))
            if not bucket.take():
                core.note_rejected(conn, agent["id"])
                return _text(429, "too many requests", headers=[("retry-after", str(int(INGEST_REFILL_S)))])
            fp = pki.fingerprint(der or b"")
            if fp not in self.expiry:
                try:
                    cert = pki.x509.load_der_x509_certificate(der or b"")
                    self.expiry[fp] = cert.not_valid_after_utc.strftime(core.STAMP)
                except ValueError:
                    self.expiry[fp] = ""
                if len(self.expiry) > 1000:
                    self.expiry.clear()
            if self.expiry.get(fp):
                core.note_cert(conn, agent["id"], self.expiry[fp])
            if path == "/renew":
                return self._renew(conn, agent, ip, body)
            if path not in ("/v1/metrics", "/telegraf"):
                return _text(404, "unknown path")
            return self._metrics(conn, agent, ip, path, headers, body)
        except Exception:  # noqa: BLE001 - the answer never contains the reason; it is in the log
            log.exception("ingest request failed")
            return _text(500, "internal error", close=True)
        finally:
            conn.close()

    def _enrol(self, conn, ip: str, path: str, headers: dict[str, str], body: bytes, policy: dict[str, Any]) -> Response:
        if path != "/enrol":
            return _text(404, "unknown path")
        if not core.window_open(policy):
            return _text(403, "enrolment is closed")
        bucket = self.enrol_ips.setdefault(ip, Bucket(ENROL_BURST, ENROL_REFILL_S))
        if len(self.enrol_ips) > 1000:
            self.enrol_ips.clear()
        if not bucket.take() or not self.enrol_global.take():
            if not self._quiet(ip, "enrolment rate"):
                core._audit(conn, f"Too many enrolment attempts from {ip or 'unknown'}", "/ingest/enrol", 429)
            return _text(429, "too many attempts", headers=[("retry-after", "60")])
        auth = headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        try:
            chain = core.enrol(conn, token, body.decode("utf-8", "replace"), ip)
        except core.IngestError as exc:
            if str(exc) == core._REFUSED:
                if not self._quiet(ip, "enrolment refused"):
                    core._audit(conn, f"Refused an enrolment from {ip or 'unknown'} (unknown, used or expired token)", "/ingest/enrol", 401)
                return _text(401, "enrolment refused", close=True)
            return _text(400, str(exc))
        return Response(200, chain.encode(), "application/x-pem-file")

    def _renew(self, conn, agent, ip: str, body: bytes) -> Response:
        if len(body) > ENROL_MAX_BODY:
            return _text(413, "the request is too large", close=True)
        try:
            chain = core.renew(conn, agent, body.decode("utf-8", "replace"))
        except core.IngestError as exc:
            return _text(409 if "ago" in str(exc) else 400, str(exc))
        return Response(200, chain.encode(), "application/x-pem-file")

    def _metrics(self, conn, agent, ip: str, path: str, headers: dict[str, str], body: bytes) -> Response:
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return _text(415, "send JSON (OpenTelemetry Collector: otlphttp exporter with encoding: json)")
        enc = headers.get("content-encoding", "").strip().lower()
        if enc in ("gzip", "x-gzip"):
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                body = d.decompress(body, MAX_BODY + 1)
            except zlib.error:
                return _text(400, "the compressed body is damaged")
            if len(body) > MAX_BODY or d.unconsumed_tail:
                return _text(413, "the request is too large after decompression")
        elif enc not in ("", "identity"):
            return _text(415, "use gzip or no compression")
        try:
            doc = json.loads(body)
        except (ValueError, RecursionError):
            return _text(400, "the body is not valid JSON")
        accepted = dropped = 0
        by_device: dict[int, list] = {}
        try:
            if path == "/v1/metrics":
                resources, dropped = parse.otlp(doc)
                for host, samples in resources:
                    ids = core.pick_targets(conn, agent["id"], host)
                    if not ids:
                        dropped += len(samples)
                    for did in ids:
                        by_device.setdefault(did, []).extend(samples)
            else:
                for host, items in parse.telegraf_hosts(parse.telegraf(doc)).items():
                    ids = core.pick_targets(conn, agent["id"], host)
                    if not ids:
                        dropped += len(items)
                    for did in ids:
                        by_device.setdefault(did, []).extend(items)
        except parse.ParseError as exc:
            return self._refuse(conn, ip, str(exc), 413 if "too many" in str(exc) else 400, agent, path)
        except (TypeError, ValueError, AttributeError, KeyError, IndexError, OverflowError):          # a shape nobody planned for is a bad request, not a server error
            return self._refuse(conn, ip, "the body does not have the expected structure", 400, agent, path)
        stored: list[tuple] = []
        for did, data in by_device.items():
            state = core.state_for(agent["id"], did)
            try:
                if path == "/v1/metrics":
                    points, stamp, bad = parse.otlp_points(data, state)
                else:
                    points, stamp, bad = parse.telegraf_points(data, state)
            except (TypeError, ValueError, AttributeError, KeyError, IndexError, OverflowError):
                return self._refuse(conn, ip, "the body does not have the expected structure", 400, agent, path)
            dropped += bad
            if core.accept(conn, agent, did, points, stamp):
                accepted += len(points)
            else:
                dropped += len(points)
                if not self._quiet(ip, f"other-monitor-{did}"):
                    core._audit(conn, f"Data of agent '{agent['name']}' ignored: a linked device is monitored another way", path, 409)
        core.note(conn, agent, accepted, dropped, ip)
        if path == "/v1/metrics":
            doc_out: dict[str, Any] = {"partialSuccess": {"rejectedDataPoints": dropped}} if dropped else {}
            return _json(200, doc_out)
        return _json(200, {"accepted": accepted, "dropped": dropped})
