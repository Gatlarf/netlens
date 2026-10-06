import asyncio
import asyncssh
from app.terminal.base import TerminalBackend, AuthFailed, ConnectFailed, HostKeyMismatch


class SSHBackend(TerminalBackend):
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        password: str | None = None,
        private_key: str | None = None,
        passphrase: str | None = None,
        cols: int = 80,
        rows: int = 24,
        known_fingerprint: str | None = None,
        connect_timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.passphrase = passphrase
        self.cols = cols
        self.rows = rows
        self.known_fingerprint = known_fingerprint
        self.connect_timeout = connect_timeout
        self.fingerprint: str | None = None
        self.new_key = False
        self._conn: asyncssh.SSHClientConnection | None = None
        self._process: asyncssh.SSHClientProcess | None = None

    def _create_client_factory(self):
        backend = self

        class SSHClient(asyncssh.SSHClient):
            def validate_host_public_key(self, host, addr, port, key) -> bool:
                fp = key.get_fingerprint("sha256")
                backend.fingerprint = fp
                if backend.known_fingerprint is None:
                    backend.new_key = True
                    return True
                if fp == backend.known_fingerprint:
                    return True
                return False

        return SSHClient

    async def connect(self) -> None:
        client_factory = self._create_client_factory()

        client_keys = None
        if self.private_key:
            try:
                client_keys = [asyncssh.import_private_key(self.private_key, self.passphrase)]
            except Exception:
                raise ConnectFailed("invalid private key")

        try:
            self._conn = await asyncio.wait_for(
                asyncssh.connect(
                    self.host,
                    port=self.port,
                    client_factory=client_factory,
                    username=self.username,
                    password=self.password,
                    client_keys=client_keys,
                    known_hosts=(),
                    agent_path=None,
                    config=None,
                    login_timeout=self.connect_timeout,
                ),
                timeout=self.connect_timeout,
            )
        except asyncssh.PermissionDenied:
            raise AuthFailed("authentication failed")
        except asyncssh.HostKeyNotVerifiable as e:
            raise HostKeyMismatch(self.known_fingerprint, self.fingerprint) from e
        except asyncssh.Error as e:
            raise ConnectFailed("connection failed")
        except OSError as e:
            raise ConnectFailed("connection failed")
        except asyncio.TimeoutError:
            raise ConnectFailed("connection timed out")

        if self.known_fingerprint is not None and self.fingerprint != self.known_fingerprint:
            raise HostKeyMismatch(self.known_fingerprint, self.fingerprint)

        self._process = await self._conn.create_process(
            term_type="xterm-256color",
            term_size=(self.cols, self.rows),
            encoding=None,
        )

    async def read(self) -> bytes:
        if self._process is None:
            return b""
        data = await self._process.stdout.read(4096)
        return data or b""

    async def write(self, data: bytes) -> None:
        if self._process is None:
            return
        self._process.stdin.write(data)
        await self._process.stdin.drain()

    async def resize(self, cols: int, rows: int) -> None:
        if self._process is None:
            return
        self._process.change_terminal_size(cols, rows)

    async def close(self) -> None:
        if self._process is not None:
            try:
                self._process.stdin.close()
            except Exception:
                pass
            self._process = None

        if self._conn is not None:
            try:
                self._conn.close()
                await asyncio.wait_for(self._conn.wait_closed(), timeout=5.0)
            except Exception:
                pass
            self._conn = None