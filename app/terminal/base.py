"""Terminal backend base classes and exceptions."""

from __future__ import annotations


class TerminalError(Exception):
    """Base exception for terminal operations."""


class AuthFailed(TerminalError):
    """Authentication failed."""


class ConnectFailed(TerminalError):
    """Connection failed."""


class HostKeyMismatch(TerminalError):
    """Host key changed unexpectedly."""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"host key changed: expected {expected}, got {actual}")


class TerminalBackend:
    """Abstract base class for terminal backends."""

    fingerprint: str | None = None
    new_key: bool = False

    async def connect(self) -> None:
        raise NotImplementedError

    async def read(self) -> bytes:
        raise NotImplementedError

    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    async def resize(self, cols: int, rows: int) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError