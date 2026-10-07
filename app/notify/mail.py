import smtplib
import ssl
import socket
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from app.notify.config import NotifyConfig


class MailError(Exception):
    pass


def send_mail(cfg: NotifyConfig, subject: str, body: str, *, smtp_factory=None, timeout: float = 20.0) -> None:
    if not cfg.smtp_host or not cfg.from_addr or not cfg.to_addrs:
        raise MailError("SMTP host, sender and recipients must be set")

    msg = EmailMessage()
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(cfg.to_addrs)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body)

    if smtp_factory is None:
        if cfg.security == "ssl":
            def default_factory(host, port, timeout):
                return smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
        else:
            def default_factory(host, port, timeout):
                return smtplib.SMTP(host, port, timeout=timeout)
        factory = default_factory
    else:
        factory = smtp_factory

    conn = None
    try:
        conn = factory(cfg.smtp_host, cfg.smtp_port, timeout)
        conn.ehlo()
        if cfg.security == "starttls":
            conn.starttls(context=ssl.create_default_context())
            conn.ehlo()
        if cfg.username:
            conn.login(cfg.username, cfg.password)
        conn.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError("authentication failed (check username and password)") from exc
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
        raise MailError("recipient or sender refused: " + str(exc)) from exc
    except smtplib.SMTPException as exc:
        raise MailError("SMTP error: " + str(exc)) from exc
    except (socket.timeout, TimeoutError) as exc:
        raise MailError("connection to SMTP server timed out") from exc
    except ConnectionRefusedError as exc:
        raise MailError("connection refused by SMTP server") from exc
    except socket.gaierror as exc:
        raise MailError("cannot resolve SMTP host") from exc
    except ssl.SSLError as exc:
        raise MailError("TLS error: " + str(exc)) from exc
    except OSError as exc:
        raise MailError("network error: " + str(exc)) from exc
    finally:
        if conn is not None:
            try:
                conn.quit()
            except Exception:
                pass