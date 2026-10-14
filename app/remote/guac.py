"""The Guacamole protocol, just enough to put a browser in front of guacd.

guacd is the small translator from Apache Guacamole that speaks RDP and VNC to the target and a simple text protocol to its client.
An instruction is `<len>.<opcode>,<len>.<arg>,...;` where every length counts characters. Netlens connects to guacd, does the
handshake itself (so the password never goes through the browser's own connection settings), and then passes instructions
between the browser (a WebSocket) and guacd (TCP).
"""

from __future__ import annotations

import asyncio
import codecs
import uuid

INTERNAL = ""            # the opcode of messages that belong to the tunnel and not to the remote session (ping, the session id)
MAX_INSTRUCTION = 1_000_000


def encode(opcode: str, *args: str) -> str:
    parts = [opcode, *args]
    return ",".join(f"{len(p)}.{p}" for p in parts) + ";"


class ProtocolError(Exception):
    pass


class Parser:
    """Turns a stream of text into complete instructions. feed() returns [(opcode, [args]), ...] and keeps the rest."""

    def __init__(self) -> None:
        self._buf = ""

    def feed(self, text: str) -> list[tuple[str, list[str]]]:
        self._buf += text
        out: list[tuple[str, list[str]]] = []
        buf, pos = self._buf, 0
        while True:
            elements: list[str] = []
            i = pos
            complete = False
            while True:
                dot = buf.find(".", i)
                if dot < 0:
                    break
                length_text = buf[i:dot]
                if not length_text.isdigit() or len(length_text) > 7:
                    raise ProtocolError("malformed instruction")
                length = int(length_text)
                end = dot + 1 + length
                if length > MAX_INSTRUCTION:
                    raise ProtocolError("instruction too long")
                if end >= len(buf):
                    break                                   # the value and its terminator have not arrived yet
                elements.append(buf[dot + 1:end])
                terminator = buf[end]
                i = end + 1
                if terminator == ";":
                    complete = True
                    break
                if terminator != ",":
                    raise ProtocolError("malformed instruction")
            if not complete:
                break
            out.append((elements[0], elements[1:]))
            pos = i
        self._buf = buf[pos:]
        if len(self._buf) > 2 * MAX_INSTRUCTION:
            raise ProtocolError("instruction too long")
        return out


class Connection:
    """A TCP connection to guacd, read as instructions."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer
        self._parser = Parser()
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._queue: list[tuple[str, list[str]]] = []

    @classmethod
    async def open(cls, host: str, port: int, timeout: float = 5.0) -> "Connection":
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        return cls(reader, writer)

    async def send(self, opcode: str, *args: str) -> None:
        self.writer.write(encode(opcode, *args).encode("utf-8"))
        await self.writer.drain()

    async def send_raw(self, text: str) -> None:
        self.writer.write(text.encode("utf-8"))
        await self.writer.drain()

    async def read(self) -> list[tuple[str, list[str]]]:
        """The next batch of complete instructions (empty list at the end of the stream)."""
        while not self._queue:
            data = await self.reader.read(65536)
            if not data:
                return []
            self._queue.extend(self._parser.feed(self._decoder.decode(data)))
        batch, self._queue = self._queue, []
        return batch

    async def expect(self, opcode: str, timeout: float = 10.0) -> list[str]:
        while True:
            batch = await asyncio.wait_for(self.read(), timeout)
            if not batch:
                raise ProtocolError("guacd closed the connection")
            for i, (op, args) in enumerate(batch):
                if op == "error":
                    raise ProtocolError(args[0] if args else "guacd reported an error")
                if op == opcode:
                    self._queue = batch[i + 1:] + self._queue
                    return args

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:  # noqa: BLE001
            pass


async def handshake(conn: Connection, protocol: str, params: dict[str, str], width: int, height: int, dpi: int = 96, timezone: str = "UTC") -> str:
    """select -> args -> size/audio/video/image/timezone -> connect -> ready. Returns the connection id guacd made."""
    await conn.send("select", protocol)
    names = await conn.expect("args")
    await conn.send("size", str(width), str(height), str(dpi))
    await conn.send("audio")
    await conn.send("video")
    await conn.send("image", "image/png", "image/jpeg", "image/webp")
    await conn.send("timezone", timezone)
    # guacd lists what it wants; a VERSION_x_y_z entry must be answered with itself (the client's protocol version)
    await conn.send("connect", *[name if name.startswith("VERSION_") else params.get(name, "") for name in names])
    ready = await conn.expect("ready", timeout=30.0)
    return ready[0] if ready else str(uuid.uuid4())


def tunnel_ready(session_id: str) -> str:
    """The first message the browser's tunnel waits for (it carries the session id)."""
    return encode(INTERNAL, session_id)
