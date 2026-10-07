
TASK: write app/notify/mail.py (full file, under 90 lines). Imports allowed: smtplib, ssl, socket, email.message (EmailMessage), email.utils (formatdate, make_msgid), and `from app.notify.config import NotifyConfig`.

class MailError(Exception): raised with a short human-readable message when sending fails.

def send_mail(cfg: NotifyConfig, subject: str, body: str, *, smtp_factory=None, timeout: float = 20.0) -> None
  - BLOCKING function (it will be called through asyncio.to_thread by the caller).
  - Build an EmailMessage: From=cfg.from_addr, To=", ".join(cfg.to_addrs), Subject=subject, Date=formatdate(localtime=True), Message-ID=make_msgid(), plain-text body via set_content(body).
  - Connection: security "ssl" -> smtp_factory(host, port, timeout) where the default factory is smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context()); security "starttls" or "none" -> default factory smtplib.SMTP(host, port, timeout=timeout). `smtp_factory`, when given, is a callable (host: str, port: int, timeout: float) -> object and replaces the default factory for ALL security modes (used by tests).
  - Sequence on the object: ehlo(); if security == "starttls": starttls(context=ssl.create_default_context()) then ehlo() again; if cfg.username: login(cfg.username, cfg.password); send_message(msg); finally quit() (ignore errors from quit; always attempt it when the connection was opened).
  - Error translation to MailError (message text must contain the given words): smtplib.SMTPAuthenticationError -> "authentication failed (check username and password)"; smtplib.SMTPRecipientsRefused / SMTPSenderRefused -> "recipient or sender refused: " + str(exc); smtplib.SMTPException -> "SMTP error: " + str(exc); socket.timeout / TimeoutError -> "connection to SMTP server timed out"; ConnectionRefusedError -> "connection refused by SMTP server"; socket.gaierror -> "cannot resolve SMTP host"; ssl.SSLError -> "TLS error: " + str(exc); any other OSError -> "network error: " + str(exc).
  - Raise MailError("SMTP host, sender and recipients must be set") before connecting when cfg.smtp_host, cfg.from_addr or cfg.to_addrs is empty.
