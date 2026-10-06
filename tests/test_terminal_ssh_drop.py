import asyncio
import asyncssh
import pytest_asyncio
from app.terminal.ssh import SSHBackend


async def handle(process: asyncssh.SSHServerProcess) -> None:
    process.write(b"hi\r\n")
    process.channel.get_connection().abort()


class DemoServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == 'bob' and password == 'secret'


class TestSSHBackendDrop:
    @pytest_asyncio.fixture
    async def server(self):
        key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(
            DemoServer,
            "127.0.0.1",
            0,
            server_host_keys=[key],
            encoding=None,
            process_factory=handle,
        )
        yield server
        server.close()
        await server.wait_closed()

    async def test_read_after_abrupt_close(self, server):
        port = server.sockets[0].getsockname()[1]
        backend = SSHBackend("127.0.0.1", port, username="bob", password="secret")
        await backend.connect()

        data = b""
        while True:
            chunk = await asyncio.wait_for(backend.read(), 5)
            if chunk == b"":
                break
            data += chunk

        assert data in (b"", b"hi\r\n")

        chunk = await asyncio.wait_for(backend.read(), 5)
        assert chunk == b""

        await backend.close()