"""send_mail against a real (minimal) SMTP server speaking the protocol over a local socket."""

import socket
import threading
from email import message_from_bytes

import pytest

from app.notify.config import NotifyConfig
from app.notify.mail import MailError, send_mail


class MiniSMTP(threading.Thread):
    """Accepts one connection, records the envelope and message, answers like a plain SMTP server."""

    def __init__(self, reject_rcpt=False):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.reject_rcpt = reject_rcpt
        self.mail_from, self.rcpt_to, self.data = None, [], b""

    def run(self):
        conn, _ = self.sock.accept()
        f = conn.makefile("rwb")

        def send(line):
            f.write(line.encode() + b"\r\n")
            f.flush()

        send("220 mini ESMTP")
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode().strip()
            up = cmd.upper()
            if up.startswith("EHLO") or up.startswith("HELO"):
                send("250 mini")
            elif up.startswith("MAIL FROM"):
                self.mail_from = cmd.split(":", 1)[1].strip()
                send("250 ok")
            elif up.startswith("RCPT TO"):
                if self.reject_rcpt:
                    send("550 no such user")
                else:
                    self.rcpt_to.append(cmd.split(":", 1)[1].strip())
                    send("250 ok")
            elif up == "DATA":
                send("354 go ahead")
                chunks = []
                while True:
                    part = f.readline()
                    if part in (b".\r\n", b""):
                        break
                    chunks.append(part)
                self.data = b"".join(chunks)
                send("250 queued")
            elif up == "QUIT":
                send("221 bye")
                break
            else:
                send("250 ok")
        conn.close()
        self.sock.close()


def _cfg(port, **kw):
    return NotifyConfig(
        enabled=True, smtp_host="127.0.0.1", smtp_port=port, security="none",
        from_addr="netlens@test.io", to_addrs=["a@test.io", "b@test.io"], **kw,
    )


def test_message_is_delivered_with_correct_envelope_and_headers():
    server = MiniSMTP()
    server.start()
    send_mail(_cfg(server.port), "[Netlens] 1 new device", "New devices:\n  - web1 (10.0.0.64)\n", timeout=5)
    server.join(5)
    assert server.mail_from == "<netlens@test.io>"
    assert server.rcpt_to == ["<a@test.io>", "<b@test.io>"]
    msg = message_from_bytes(server.data)
    assert msg["Subject"] == "[Netlens] 1 new device"
    assert msg["From"] == "netlens@test.io" and msg["To"] == "a@test.io, b@test.io"
    assert msg["Date"] and msg["Message-ID"]
    assert "web1 (10.0.0.64)" in msg.get_payload()


def test_rejected_recipient_becomes_a_readable_error():
    server = MiniSMTP(reject_rcpt=True)
    server.start()
    with pytest.raises(MailError, match="recipient or sender refused"):
        send_mail(_cfg(server.port), "s", "b", timeout=5)


def test_connection_refused_is_explained():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens on this port any more
    with pytest.raises(MailError, match="refused"):
        send_mail(_cfg(port), "s", "b", timeout=5)
