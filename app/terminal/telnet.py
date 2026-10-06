"""Async telnet terminal backend using asyncio and stdlib."""

from __future__ import annotations

import asyncio
from typing import Optional

from app.terminal.base import ConnectFailed, TerminalBackend

# Telnet constants
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240
ECHO = 1
SGA = 3
NAWS = 31


def escape_iac(data: bytes) -> bytes:
    """Double every 0xFF byte in data."""
    return data.replace(b"\xff", b"\xff\xff")


def naws_bytes(cols: int, rows: int) -> bytes:
    """Build IAC SB NAWS cols_hi cols_lo rows_hi rows_lo IAC SE."""
    cols_hi = (cols >> 8) & 0xFF
    cols_lo = cols & 0xFF
    rows_hi = (rows >> 8) & 0xFF
    rows_lo = rows & 0xFF
    payload = bytes([cols_hi, cols_lo, rows_hi, rows_lo])
    # Double any 0xFF in payload
    payload = escape_iac(payload)
    return bytes([IAC, SB, NAWS]) + payload + bytes([IAC, SE])


def process_telnet_bytes(buf: bytes) -> tuple[bytes, bytes, bytes]:
    """Parse raw bytes received from a telnet server.

    Returns (data, replies, leftover).
    data = application bytes with all IAC sequences removed.
    replies = bytes to send back.
    leftover = incomplete trailing sequence.
    """
    data = bytearray()
    replies = bytearray()
    leftover = bytearray()
    i = 0
    n = len(buf)

    while i < n:
        if buf[i] != IAC:
            data.append(buf[i])
            i += 1
            continue

        # IAC found
        if i + 1 >= n:
            leftover.append(IAC)
            break

        cmd = buf[i + 1]

        if cmd == IAC:
            # IAC IAC -> single 0xFF data byte
            data.append(IAC)
            i += 2
            continue

        if cmd == SB:
            # Subnegotiation: IAC SB ... IAC SE
            j = i + 2
            if j >= n:
                leftover.extend(buf[i:])
                break
            # Find IAC SE
            found = False
            while j < n:
                if buf[j] == IAC:
                    if j + 1 < n and buf[j + 1] == SE:
                        found = True
                        j += 2
                        break
                    else:
                        # Incomplete
                        leftover.extend(buf[i:])
                        break
                j += 1
            if found:
                i = j
            else:
                leftover.extend(buf[i:])
                break
            continue

        if cmd in (DONT, WONT):
            # No reply needed
            if i + 2 >= n:
                leftover.extend(buf[i:])
                break
            i += 3
            continue

        if cmd == WILL:
            if i + 2 >= n:
                leftover.extend(buf[i:])
                break
            opt = buf[i + 2]
            if opt == ECHO or opt == SGA:
                replies.extend([IAC, DO, opt])
            else:
                replies.extend([IAC, DONT, opt])
            i += 3
            continue

        if cmd == DO:
            if i + 2 >= n:
                leftover.extend(buf[i:])
                break
            opt = buf[i + 2]
            if opt == NAWS:
                replies.extend([IAC, WILL, NAWS])
            else:
                replies.extend([IAC, WONT, opt])
            i += 3
            continue

        # Two-byte commands (NOP etc.) are skipped
        i += 2

    return bytes(data), bytes(replies), bytes(leftover)


class TelnetBackend(TerminalBackend):
    def __init__(
        self,
        host: str,
        port: int = 23,
        cols: int = 80,
        rows: int = 24,
        connect_timeout: float = 10.0,
    ) -> None:
        self._host = host
        self._port = port
        self._cols = cols
        self._rows = rows
        self._connect_timeout = connect_timeout
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._leftover: bytes = b""
        self._naws_agreed: bool = False
        self._closed: bool = False

    async def connect(self) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=self._connect_timeout,
            )
        except OSError as exc:
            raise ConnectFailed(str(exc)) from exc
        except TimeoutError as exc:
            raise ConnectFailed(str(exc)) from exc

    async def read(self) -> bytes:
        if self._reader is None:
            return b""

        while True:
            chunk = await self._reader.read(4096)
            if not chunk:
                return b""

            buf = self._leftover + chunk
            data, replies, leftover = process_telnet_bytes(buf)
            self._leftover = leftover

            if replies:
                if self._writer is not None:
                    self._writer.write(replies)
                    await self._writer.drain()

            # Check if we sent WILL NAWS in replies
            if b"\xff\xfa\x1f" in replies:
                self._naws_agreed = True
                # Send initial size right after agreeing to NAWS
                if self._writer is not None:
                    self._writer.write(naws_bytes(self._cols, self._rows))
                    await self._writer.drain()

            if data:
                return data

            # Control-only chunk, loop to get more data
            # But if leftover is empty and no data, we might be at EOF
            # The loop continues; if next read returns b"", we return b""

    async def write(self, data: bytes) -> None:
        if self._writer is None:
            return
        self._writer.write(escape_iac(data))
        await self._writer.drain()

    async def resize(self, cols: int, rows: int) -> None:
        self._cols = cols
        self._rows = rows
        if self._naws_agreed and self._writer is not None:
            self._writer.write(naws_bytes(cols, rows))
            await self._writer.drain()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass