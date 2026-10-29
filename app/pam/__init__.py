"""Using the customer's privileged-access system (PAM): Netlens asks it for a login when it needs one and keeps no copy.

A stored login of kind `pam` says *where* the secret lives (provider, address, path) and how Netlens signs in to the PAM, never the secret itself. When something needs
the login (a terminal, a remote desktop, a monitor, a probe run) `checkout()` fetches it, the caller uses it, and it is dropped:

  * no cache between uses, nothing written to the database, nothing in a log or a diagnostic (the audit line holds the lease id, never a secret);
  * fail closed: if the PAM cannot be reached or refuses, the use does not happen (there is no fall-back to a stored password);
  * every check-out is one audit line (who, host, entry, provider, purpose, reason, lease id) and carries a correlation id the PAM may log too;
  * an entry can require a reason (a ticket number or a sentence) for interactive use; background jobs cannot supply one and are refused.

A provider is a class in this package with `fetch(config, secrets, ctx) -> Fetched`. Another one is added with `register()`.
"""

from __future__ import annotations

import secrets as _secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

FIELDS = ("username", "password", "private_key", "passphrase", "domain")
MAX_REASON = 300


class PamError(Exception):
    """A sentence the user can act on. Never contains a secret."""


@dataclass
class Context:
    """What the provider may tell the PAM about this use."""

    purpose: str
    user: str
    reason: str = ""
    device: str = ""
    correlation: str = field(default_factory=lambda: "nl-" + _secrets.token_hex(8))


@dataclass
class Fetched:
    """The login, in memory only. `lease` is an id for the audit line (the PAM's own request or lease id where it has one)."""

    values: dict[str, str]
    lease: str = ""
    release: Callable[[], None] | None = None

    def done(self) -> None:
        if self.release is not None:
            try:
                self.release()
            except Exception:                    # noqa: BLE001 - a failed check-in must never break the use that already happened
                pass
            self.release = None


PROVIDERS: dict[str, Any] = {}
PROVIDER_NAMES: dict[str, str] = {}
_status: dict[str, dict] = {}
_lock = threading.Lock()


def register(name: str, provider: Any, title: str = "") -> None:
    PROVIDERS[name] = provider
    PROVIDER_NAMES[name] = title or name


def providers() -> dict[str, str]:
    return dict(PROVIDER_NAMES)


def clean_reason(reason: str | None) -> str:
    return " ".join(str(reason or "").split())[:MAX_REASON]


def last_status(cred_id: str) -> dict | None:
    """The outcome of the latest check-out of an entry (kept in memory, for the settings page); never holds a secret."""
    with _lock:
        item = _status.get(cred_id)
        return dict(item) if item else None


def _remember(cred_id: str, ok: bool, message: str, lease: str = "") -> None:
    with _lock:
        _status[cred_id] = {"ok": ok, "at": time.time(), "message": message[:200], "lease": lease}
        if len(_status) > 2000:
            for key in sorted(_status, key=lambda k: _status[k]["at"])[:500]:
                _status.pop(key, None)


def forget(cred_id: str) -> None:
    with _lock:
        _status.pop(cred_id, None)


def validate(entry: dict) -> None:
    """For create and update: complain early about an entry that could never work."""
    provider = PROVIDERS.get(str(entry.get("provider") or ""))
    if provider is None:
        raise PamError("choose a PAM system: " + ", ".join(sorted(PROVIDERS)))
    provider.validate(entry)


def checkout(entry: dict, ctx: Context, interactive: bool) -> Fetched:
    """Fetch the login of a `pam` entry for one use. Raises PamError (fail closed). The caller must call `.done()` when finished with the login."""
    cred_id = str(entry.get("id") or "")
    reason = clean_reason(ctx.reason)
    ctx.reason = reason
    try:
        if entry.get("reason_required"):
            if not interactive:
                raise PamError("this login needs a reason for every use, so it can only be used by a person (terminal or remote desktop), not by a monitor or a scheduled job")
            if len(reason) < 3:
                raise PamError("this login needs a reason (a ticket number or a few words) before it can be used")
        provider = PROVIDERS.get(str(entry.get("provider") or ""))
        if provider is None:
            raise PamError("the PAM system of this login is not available in this version")
        fetched = provider.fetch(entry, ctx)
    except PamError as exc:
        _remember(cred_id, False, str(exc))
        raise
    except Exception as exc:                      # noqa: BLE001 - a provider bug must fail closed with a sentence, not a trace that could hold a value
        _remember(cred_id, False, "the PAM system could not be used (" + type(exc).__name__ + ")")
        raise PamError("the PAM system could not be used (" + type(exc).__name__ + ")") from None
    _remember(cred_id, True, "checked out", fetched.lease)
    return fetched


def audit_line(entry: dict, ctx: Context, lease: str, ok: bool, error: str = "") -> str:
    """The text of the audit line for a check-out. Never contains a secret."""
    host = f" for {ctx.device}" if ctx.device else ""
    reason = f", reason: {ctx.reason}" if ctx.reason else ""
    state = f"checked out{host}" if ok else f"REFUSED{host} ({error[:120]})"
    return (f"PAM {entry.get('provider')}: login \"{str(entry.get('name'))[:40]}\" {state}; lease {lease or '-'}; correlation {ctx.correlation}; "
            f"purpose: {ctx.purpose[:60]}{reason}")


from app.pam import vaultkv  # noqa: E402,F401  (registers itself)
