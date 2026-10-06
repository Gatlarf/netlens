import asyncio
from app.terminal.base import TerminalBackend


class FakeBackend(TerminalBackend):
    created: list[dict] = []
    resizes: list[tuple[int, int]] = []
    connect_error: Exception | None = None
    new_key_value: bool = True
    fingerprint_value: str = "SHA256:fake"

    @classmethod
    def reset(cls) -> None:
        cls.created.clear()
        cls.resizes.clear()
        cls.connect_error = None
        cls.new_key_value = True

    def __init__(self, **kwargs) -> None:
        FakeBackend.created.append(kwargs)
        self.kwargs = kwargs
        self.fingerprint = FakeBackend.fingerprint_value
        self.new_key = FakeBackend.new_key_value
        self.closed = False
        self._queue = asyncio.Queue()
        self._queue.put_nowait(b"welcome\r\n")

    async def connect(self) -> None:
        if FakeBackend.connect_error is not None:
            raise FakeBackend.connect_error

    async def read(self) -> bytes:
        item = await self._queue.get()
        if item is None:
            return b""
        return item

    async def write(self, data: bytes) -> None:
        await self._queue.put(b"echo:" + data)

    async def resize(self, cols: int, rows: int) -> None:
        FakeBackend.resizes.append((cols, rows))

    async def close(self) -> None:
        self.closed = True
        self._queue.put_nowait(None)