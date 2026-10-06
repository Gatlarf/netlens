Create app/terminal/base.py (stdlib only).
- class TerminalError(Exception).
- class AuthFailed(TerminalError); class ConnectFailed(TerminalError).
- class HostKeyMismatch(TerminalError): __init__(self, expected: str, actual: str) storing .expected and .actual, message "host key changed: expected <expected>, got <actual>".
- class TerminalBackend: the interface (plain base class, methods raise NotImplementedError): async connect(self) -> None; async read(self) -> bytes (returns b"" at end of session); async write(self, data: bytes) -> None; async resize(self, cols: int, rows: int) -> None; async close(self) -> None (idempotent). Class attribute fingerprint: str | None = None (host key fingerprint after connect, SSH only) and new_key: bool = False.
