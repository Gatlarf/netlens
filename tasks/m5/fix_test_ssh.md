Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
The file uses @pytest_asyncio.fixture but never imports it. Add 'import pytest_asyncio' at the top.

CURRENT FILE:
import asyncio
import pytest
import asyncssh
from app.terminal.ssh import SSHBackend
from app.terminal.base import AuthFailed, ConnectFailed, HostKeyMismatch


@pytest_asyncio.fixture
async def demo_server():
    key = asyncssh.generate_private_key("ssh-ed25519")
    fingerprint = key.get_fingerprint("sha256")

    class DemoServer(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            return username == "bob" and password == "secret"

    async def handle(process):
        process.stdout.write(b"welcome\r\n")
        while True:
            data = await process.stdin.read(1024)
            if not data:
                break
            process.stdout.write(b"echo:" + data)
        process.exit(0)

    server = await asyncssh.create_server(
        DemoServer,
        "127.0.0.1",
        0,
        server_host_keys=[key],
        process_factory=handle,
        encoding=None,
    )
    port = server.sockets[0].getsockname()[1]
    yield port, fingerprint
    server.close()
    await server.wait_closed()


async def read_until(backend, marker, timeout=5.0):
    data = b""
    while marker not in data:
        chunk = await asyncio.wait_for(backend.read(), timeout)
        if not chunk:
            break
        data += chunk
    return data


@pytest.mark.asyncio
async def test_connect_success(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
    )
    await backend.connect()
    assert backend.fingerprint == fingerprint
    assert backend.new_key is True
    await backend.close()


@pytest.mark.asyncio
async def test_read_welcome(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
    )
    await backend.connect()
    data = await read_until(backend, b"welcome")
    assert b"welcome" in data
    await backend.close()


@pytest.mark.asyncio
async def test_write_and_echo(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
    )
    await backend.connect()
    await read_until(backend, b"welcome")
    await backend.write(b"hi\n")
    data = await read_until(backend, b"echo:hi")
    assert b"echo:hi" in data
    await backend.close()


@pytest.mark.asyncio
async def test_resize(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
    )
    await backend.connect()
    await backend.resize(100, 40)
    await backend.close()


@pytest.mark.asyncio
async def test_close_twice(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
    )
    await backend.connect()
    await backend.close()
    await backend.close()
    data = await backend.read()
    assert data == b""


@pytest.mark.asyncio
async def test_wrong_password(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="wrong",
    )
    with pytest.raises(AuthFailed):
        await backend.connect()
    await backend.close()


@pytest.mark.asyncio
async def test_known_fingerprint_match(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
        known_fingerprint=fingerprint,
    )
    await backend.connect()
    assert backend.new_key is False
    await backend.close()


@pytest.mark.asyncio
async def test_host_key_mismatch(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
        known_fingerprint="SHA256:bogus",
    )
    with pytest.raises(HostKeyMismatch) as exc_info:
        await backend.connect()
    assert exc_info.value.expected == "SHA256:bogus"
    assert exc_info.value.actual == fingerprint
    await backend.close()


@pytest.mark.asyncio
async def test_connect_closed_port():
    backend = SSHBackend(
        host="127.0.0.1",
        port=1,
        username="bob",
        password="secret",
    )
    with pytest.raises(ConnectFailed):
        await backend.connect()
    await backend.close()


@pytest.mark.asyncio
async def test_connect_timeout(demo_server):
    port, fingerprint = demo_server
    # Start a server that never answers
    async def handler(reader, writer):
        await asyncio.sleep(10)
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    timeout_port = server.sockets[0].getsockname()[1]
    backend = SSHBackend(
        host="127.0.0.1",
        port=timeout_port,
        username="bob",
        password="secret",
        connect_timeout=0.2,
    )
    with pytest.raises(ConnectFailed):
        await backend.connect()
    await backend.close()
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_garbage_private_key(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
        private_key="garbage",
    )
    with pytest.raises(ConnectFailed):
        await backend.connect()
    await backend.close()


@pytest.mark.asyncio
async def test_error_messages_no_password(demo_server):
    port, fingerprint = demo_server
    backend = SSHBackend(
        host="127.0.0.1",
        port=port,
        username="bob",
        password="secret",
    )
    try:
        await backend.connect()
    except Exception as e:
        assert "secret" not in str(e)
    await backend.close()