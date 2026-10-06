Create tests/fake_terminal.py (a helper module, not a test file). Import: asyncio; from app.terminal.base import TerminalBackend.
class FakeBackend(TerminalBackend): class attributes created = [] (kwargs of every instance), resizes = [], connect_error = None (an exception instance to raise from connect), new_key_value = True, fingerprint_value = "SHA256:fake". classmethod reset(cls): clear created and resizes, set connect_error = None and new_key_value = True.
__init__(self, **kwargs): FakeBackend.created.append(kwargs); self.kwargs = kwargs; self.fingerprint = FakeBackend.fingerprint_value; self.new_key = FakeBackend.new_key_value; self.closed = False; self._queue = asyncio.Queue(); self._queue.put_nowait(b"welcome\r\n").
async connect(self): if FakeBackend.connect_error is not None: raise it.
async read(self): item = await self._queue.get(); return item if item is not None else b"" (None means EOF). If self.closed and the queue is empty return b"".
async write(self, data: bytes): await self._queue.put(b"echo:" + data).
async resize(self, cols, rows): FakeBackend.resizes.append((cols, rows)).
async close(self): self.closed = True; self._queue.put_nowait(None).
