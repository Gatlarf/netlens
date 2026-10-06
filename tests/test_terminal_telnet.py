import asyncio
import pytest
from app.terminal.telnet import (
    IAC, DONT, DO, WONT, WILL, SB, SE, ECHO, SGA, NAWS,
    escape_iac, naws_bytes, process_telnet_bytes, TelnetBackend,
)
from app.terminal.base import ConnectFailed


def test_process_telnet_plain_text():
    data = b"hello world"
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b"hello world"
    assert replies == b""
    assert leftover == b""


def test_process_telnet_iac_iac():
    data = bytes([IAC, IAC])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b"\xff"
    assert replies == b""
    assert leftover == b""


def test_process_telnet_will_echo():
    data = bytes([IAC, WILL, ECHO])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b""
    assert replies == bytes([IAC, DO, ECHO])
    assert leftover == b""


def test_process_telnet_will_unknown():
    data = bytes([IAC, WILL, 24])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b""
    assert replies == bytes([IAC, DONT, 24])
    assert leftover == b""


def test_process_telnet_do_naws():
    data = bytes([IAC, DO, NAWS])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b""
    assert replies == bytes([IAC, WILL, NAWS])
    assert leftover == b""


def test_process_telnet_do_unknown():
    data = bytes([IAC, DO, 24])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b""
    assert replies == bytes([IAC, WONT, 24])
    assert leftover == b""


def test_process_telnet_wont_no_reply():
    data = bytes([IAC, WONT, ECHO])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b""
    assert replies == b""
    assert leftover == b""


def test_process_telnet_dont_no_reply():
    data = bytes([IAC, DONT, ECHO])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b""
    assert replies == b""
    assert leftover == b""


def test_process_telnet_sb_naws_skipped():
    data = bytes([IAC, SB, NAWS, 0, 80, 0, 24, IAC, SE])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b""
    assert replies == b""
    assert leftover == b""


def test_process_telnet_text_around_control():
    data = b"before" + bytes([IAC, WILL, ECHO]) + b"after"
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b"beforeafter"
    assert replies == bytes([IAC, DO, ECHO])
    assert leftover == b""


def test_process_telnet_trailing_lone_iac():
    data = b"hello" + bytes([IAC])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b"hello"
    assert replies == b""
    assert leftover == bytes([IAC])


def test_process_telnet_trailing_iac_do():
    data = b"hello" + bytes([IAC, DO])
    out, replies, leftover = process_telnet_bytes(data)
    assert out == b"hello"
    assert replies == b""
    assert leftover == bytes([IAC, DO])


def test_process_telnet_empty():
    out, replies, leftover = process_telnet_bytes(b"")
    assert out == b""
    assert replies == b""
    assert leftover == b""


def test_naws_bytes():
    assert naws_bytes(80, 24) == bytes([255, 250, 31, 0, 80, 0, 24, 255, 240])


def test_naws_bytes_double_ff():
    assert naws_bytes(255, 24) == bytes([255, 250, 31, 0, 255, 255, 0, 24, 255, 240])


def test_escape_iac():
    assert escape_iac(b"a\xffb") == b"a\xff\xffb"


async def test_telnet_backend_basic_echo():
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"login: ")
        await writer.drain()
        line = await reader.readline()
        writer.write(b"got: " + line)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    backend = TelnetBackend("127.0.0.1", port)
    await backend.connect()

    data = await backend.read()
    assert data == b"login: "

    await backend.write(b"bob\r\n")

    data = await backend.read()
    assert b"got: bob" in data

    data = await backend.read()
    assert data == b""

    await backend.close()
    await backend.close()

    server.close()
    await server.wait_closed()


async def test_telnet_backend_will_echo():
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(bytes([IAC, WILL, ECHO]) + b"hi")
        await writer.drain()
        # Wait for the client to respond with IAC DO ECHO
        resp = await reader.read(3)
        assert resp == bytes([IAC, DO, ECHO])
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    backend = TelnetBackend("127.0.0.1", port)
    await backend.connect()

    data = await backend.read()
    assert data == b"hi"

    await backend.close()

    server.close()
    await server.wait_closed()


async def test_telnet_backend_connect_failed():
    backend = TelnetBackend("127.0.0.1", 1)
    with pytest.raises(ConnectFailed):
        await backend.connect()