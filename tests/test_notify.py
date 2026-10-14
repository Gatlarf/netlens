import json
import smtplib
import socket
from dataclasses import dataclass
from typing import Any

import pytest
from app.db import connect, init_db, get_or_create_device, add_event
from app.notify.config import NotifyConfig, load_config, save_config, is_configured, public_dict, parse_addresses
from app.notify.mail import MailError, send_mail


def test_config_defaults():
    conn = connect(":memory:")
    init_db(conn)
    cfg = load_config(conn)
    assert cfg.enabled is False
    assert cfg.smtp_host == ""
    assert cfg.smtp_port == 587
    assert cfg.security == "starttls"
    assert cfg.username == ""
    assert cfg.password == ""
    assert cfg.from_addr == ""
    assert cfg.to_addrs == []
    assert cfg.notify_new is True
    assert cfg.notify_offline is True
    assert cfg.last_event_id is None


def test_config_round_trip():
    conn = connect(":memory:")
    init_db(conn)
    cfg = NotifyConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        security="starttls",
        username="user",
        password="pass",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=7,
    )
    save_config(conn, cfg)
    loaded = load_config(conn)
    assert loaded.enabled is True
    assert loaded.smtp_host == "smtp.example.com"
    assert loaded.to_addrs == ["to@example.com"]
    assert loaded.last_event_id == 7


def test_config_garbage_json():
    conn = connect(":memory:")
    init_db(conn)
    from app.db import set_setting
    set_setting(conn, "notifications", "{not json")
    cfg = load_config(conn)
    assert cfg.enabled is False
    assert cfg.smtp_host == ""
    assert cfg.security == "starttls"


def test_config_security_fallback():
    conn = connect(":memory:")
    init_db(conn)
    from app.db import set_setting
    data = {"security": "weird"}
    set_setting(conn, "notifications", json.dumps(data))
    cfg = load_config(conn)
    assert cfg.security == "starttls"


def test_is_configured():
    conn = connect(":memory:")
    init_db(conn)
    cfg = load_config(conn)
    assert is_configured(cfg) is False
    cfg = NotifyConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        security="starttls",
        username="",
        password="",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=None,
    )
    assert is_configured(cfg) is True


def test_public_dict():
    conn = connect(":memory:")
    init_db(conn)
    cfg = NotifyConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        security="starttls",
        username="user",
        password="pass",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=None,
    )
    d = public_dict(cfg)
    assert "password" not in d
    assert d["password_set"] is True
    assert d["configured"] is True

    cfg_no_pass = NotifyConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        security="starttls",
        username="",
        password="",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=None,
    )
    d2 = public_dict(cfg_no_pass)
    assert d2["password_set"] is False
    assert d2["configured"] is True


def test_parse_addresses():
    assert parse_addresses("a@x.com, b@y.org; a@X.com  c@z.io") == ["a@x.com", "b@y.org", "c@z.io"]
    with pytest.raises(ValueError, match="invalid email address"):
        parse_addresses("not-an-address")
    assert parse_addresses(None) == []


def test_send_mail_starttls_sequence():
    conn = connect(":memory:")
    init_db(conn)
    cfg = NotifyConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        security="starttls",
        username="user",
        password="pass",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=None,
    )
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            self.host = host
            self.port = port
            self.timeout = timeout

        def ehlo(self):
            calls.append(("ehlo",))

        def starttls(self, context=None):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user, password))

        def send_message(self, msg):
            calls.append(("send_message", msg))

        def quit(self):
            calls.append(("quit",))

    fake = FakeSMTP("smtp.example.com", 587, 20.0)
    send_mail(cfg, "Subject", "Body", smtp_factory=lambda host, port, timeout: fake)
    assert calls == [
        ("ehlo",),
        ("starttls",),
        ("ehlo",),
        ("login", "user", "pass"),
        ("send_message", calls[4][1]),
        ("quit",),
    ]
    msg = calls[4][1]
    assert msg["Subject"] == "Subject"
    assert msg["To"] == "to@example.com"
    assert "Body" in msg.get_payload()


def test_send_mail_none_security():
    conn = connect(":memory:")
    init_db(conn)
    cfg = NotifyConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        security="none",
        username="",
        password="",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=None,
    )
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            self.host = host
            self.port = port
            self.timeout = timeout

        def ehlo(self):
            calls.append(("ehlo",))

        def starttls(self, context=None):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user, password))

        def send_message(self, msg):
            calls.append(("send_message", msg))

        def quit(self):
            calls.append(("quit",))

    fake = FakeSMTP("smtp.example.com", 587, 20.0)
    send_mail(cfg, "Subject", "Body", smtp_factory=lambda host, port, timeout: fake)
    assert ("starttls",) not in calls
    assert not any(c[0] == "login" for c in calls)
    assert calls == [("ehlo",), ("send_message", calls[1][1]), ("quit",)]


def test_send_mail_errors():
    conn = connect(":memory:")
    init_db(conn)
    cfg = NotifyConfig(
        enabled=True,
        smtp_host="",
        smtp_port=587,
        security="starttls",
        username="",
        password="",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=None,
    )
    with pytest.raises(MailError, match="SMTP host, sender and recipients must be set"):
        send_mail(cfg, "Subject", "Body", smtp_factory=lambda host, port, timeout: None)

    class FakeSMTPAuthError:
        def __init__(self, host, port, timeout):
            pass

        def ehlo(self):
            pass

        def starttls(self, context=None):
            pass

        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"bad")

        def send_message(self, msg):
            pass

        def quit(self):
            pass

    fake_auth = FakeSMTPAuthError("smtp.example.com", 587, 20.0)
    cfg2 = NotifyConfig(
        enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        security="starttls",
        username="user",
        password="pass",
        from_addr="from@example.com",
        to_addrs=["to@example.com"],
        notify_new=True,
        notify_offline=True,
        last_event_id=None,
    )
    with pytest.raises(MailError, match="authentication failed"):
        send_mail(cfg2, "Subject", "Body", smtp_factory=lambda host, port, timeout: fake_auth)

    def refusing_factory(host, port, timeout):
        raise ConnectionRefusedError()

    with pytest.raises(MailError, match="refused"):
        send_mail(cfg2, "Subject", "Body", smtp_factory=refusing_factory)

    def unresolvable_factory(host, port, timeout):
        raise socket.gaierror(-2, "Name or service not known")

    with pytest.raises(MailError, match="resolve"):
        send_mail(cfg2, "Subject", "Body", smtp_factory=unresolvable_factory)
