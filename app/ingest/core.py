"""Agent ingest (Enterprise): hosts that cannot be reached from Netlens push their readings through a standard collector.

The record of a sender is an *agent*: it is identified by its client certificate (issued by the Netlens ingest CA from a CSR, or issued by the customer's own CA and
matched by an identity such as `dns:web01.example.com`) and may report for the devices it is linked to, nothing else. This module holds the rules; the network side is
in `app/ingest/server.py`.

What an agent can do: send allow-listed numbers about the devices it is linked to. What it cannot do: be told anything (Netlens never sends commands, settings or
updates), name a device, change a device, or put text anywhere. Everything that goes wrong is a counted rejection and, when it matters, an event.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import add_event, get_setting, insert_id, set_setting, utcnow
from app.ingest import pki

POLICY_KEY = "ingest.policy"
CA_KEY = "ingest.ca"                # {"cert", "key"}: encrypted at rest (app/vault.py)
CA_PREV_KEY = "ingest.ca_prev"      # {"cert", "key", "retired"} while a CA rotation runs (encrypted at rest)
SERVER_KEY = "ingest.server"        # {"cert", "key", "source", "names"}: encrypted at rest
BYO_KEY = "ingest.byo_ca"           # the customer's CA certificates (public)
TOKEN_HOURS = 24
ENROL_WINDOW_MIN, ENROL_WINDOW_MAX, ENROL_WINDOW_DEFAULT = 5, 240, 30
MIN_INTERVAL, MAX_INTERVAL, DEFAULT_INTERVAL = 10, 3600, 60
SILENT_FACTOR, SILENT_MIN_S = 3, 180
CA_WARN_DAYS = 365                  # the ingest CA lasts 10 years; it is reported in its last year
NEVER_SEEN_S = 3600                 # an agent that never sent anything is reported after an hour, not after three minutes
RENEW_EVERY_S = 3600
STAMP = "%Y-%m-%dT%H:%M:%SZ"
DEFAULTS = {"enabled": False, "bind": "0.0.0.0", "port": 4318, "enrol_port": 4319, "server_names": [], "enrol_until": None}
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,80}$")


class IngestError(ValueError):
    """A sentence the administrator can act on."""


def _parse(ts: str | None) -> float | None:
    try:
        return datetime.strptime(ts, STAMP).replace(tzinfo=timezone.utc).timestamp() if ts else None
    except ValueError:
        return None


def _stamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(STAMP)


# ----------------------------------------------------------------------------------------------- policy
def get_policy(conn) -> dict[str, Any]:
    out = dict(DEFAULTS)
    try:
        saved = json.loads(get_setting(conn, POLICY_KEY) or "{}")
    except ValueError:
        saved = {}
    if isinstance(saved, dict):
        out.update({k: saved[k] for k in DEFAULTS if k in saved})
    return out


def _port(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 1024 <= v <= 65535:
        raise IngestError(f"{what}: the port must be a number from 1024 to 65535")
    return v


def save_policy(conn, data: dict[str, Any]) -> dict[str, Any]:
    cur = get_policy(conn)
    new = dict(cur)
    if "bind" in data:
        import ipaddress

        try:
            new["bind"] = str(ipaddress.ip_address(str(data["bind"]).strip()))
        except ValueError:
            raise IngestError("the address to listen on must be an IP address (0.0.0.0 means every interface)") from None
    if "port" in data:
        new["port"] = _port(data["port"], "ingest")
    if "enrol_port" in data:
        new["enrol_port"] = _port(data["enrol_port"], "enrolment")
    if new["port"] == new["enrol_port"]:
        raise IngestError("the ingest port and the enrolment port must differ")
    if "server_names" in data:
        if not isinstance(data["server_names"], list):
            raise IngestError("server_names must be a list")
        try:
            new["server_names"] = pki.check_names([str(x) for x in data["server_names"]])
        except pki.PkiError as exc:
            raise IngestError(str(exc)) from None
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise IngestError("enabled must be true or false")
        new["enabled"] = data["enabled"]
    if new["enabled"]:
        if not new["server_names"] and not _uploaded(conn):
            raise IngestError("before switching on, enter the host name or IP address that the collectors will connect to (it goes into the server certificate)")
    set_setting(conn, POLICY_KEY, json.dumps({k: new[k] for k in DEFAULTS}))
    if new["server_names"] != cur["server_names"] and not _uploaded(conn):
        ensure_server(conn, rebuild=True) if new["server_names"] else None
    conn.commit()
    return new


def open_window(conn, minutes: int = ENROL_WINDOW_DEFAULT) -> str:
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not ENROL_WINDOW_MIN <= minutes <= ENROL_WINDOW_MAX:
        raise IngestError(f"an enrolment window lasts {ENROL_WINDOW_MIN} to {ENROL_WINDOW_MAX} minutes")
    policy = get_policy(conn)
    if not policy["enabled"]:
        raise IngestError("switch the ingest on first")
    until = _stamp(time.time() + minutes * 60)
    policy["enrol_until"] = until
    set_setting(conn, POLICY_KEY, json.dumps(policy))
    conn.commit()
    return until


def close_window(conn) -> None:
    policy = get_policy(conn)
    policy["enrol_until"] = None
    set_setting(conn, POLICY_KEY, json.dumps(policy))
    conn.commit()


def window_open(policy: dict[str, Any], now: float | None = None) -> bool:
    until = _parse(policy.get("enrol_until"))
    return bool(policy.get("enabled") and until and (now if now is not None else time.time()) < until)


# ----------------------------------------------------------------------------------------------- certificates
def _load(conn, key: str) -> dict[str, Any] | None:
    try:
        v = json.loads(get_setting(conn, key) or "null")
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def ensure_ca(conn) -> dict[str, str]:
    ca = _load(conn, CA_KEY)
    if not ca or "cert" not in ca or "key" not in ca:
        cert, key = pki.create_ca()
        ca = {"cert": cert, "key": key}
        set_setting(conn, CA_KEY, json.dumps(ca))
        conn.commit()
        _audit(conn, "Created the certificate authority for agent ingest", "/ingest/ca")
    return ca


def ca_id(cert_pem: str) -> str:
    return pki.fingerprint(pki.cert_der(cert_pem))


def _prev(conn) -> dict[str, str] | None:
    p = _load(conn, CA_PREV_KEY)
    return p if p and "cert" in p and "key" in p else None


def ca_certificate(conn) -> str:
    """What a host needs to trust Netlens: the current CA and, while a rotation runs, the old one as well."""
    cur = ensure_ca(conn)["cert"]
    prev = _prev(conn)
    return cur.strip() + "\n" + (prev["cert"].strip() + "\n" if prev else "")


def _issuer(conn) -> dict[str, str]:
    """The CA that signs the server certificate: the OLD one during a rotation (hosts still trust only that one), the current one otherwise."""
    return _prev(conn) or ensure_ca(conn)


def rotation(conn) -> dict[str, Any] | None:
    """None, or what a running rotation looks like: since when, and which agents still hold a certificate from the old CA."""
    prev = _prev(conn)
    if prev is None:
        return None
    cur = ca_id(ensure_ca(conn)["cert"])
    stale = [r["name"] for r in conn.execute("SELECT name, cert_ca FROM ingest_agents WHERE state = 'active' AND identity = '' AND cert_fp IS NOT NULL ORDER BY LOWER(name)") if r["cert_ca"] != cur]
    return {"since": prev.get("retired"), "old_ca_expires": pki.load_cert(prev["cert"]).not_valid_after_utc.strftime(STAMP), "agents_on_old_ca": stale}


def ca_info(conn) -> dict[str, Any]:
    ca = pki.load_cert(ensure_ca(conn)["cert"])
    return {"fingerprint": pki.fingerprint(ca.public_bytes(pki.serialization.Encoding.DER)), "expires": ca.not_valid_after_utc.strftime(STAMP), "rotation": rotation(conn)}


def rotate_ca(conn) -> None:
    """Start replacing the ingest CA. New certificates (enrolment and renewal) come from the new CA; the old one stays trusted, and keeps signing the server
    certificate, until `finish_rotation`, because the hosts only trust the old one until they have renewed (the renewal brings them the new CA)."""
    cur = ensure_ca(conn)
    if _prev(conn) is not None:
        raise IngestError("a rotation is already running: finish or cancel it first")
    cert, key = pki.create_ca()
    set_setting(conn, CA_PREV_KEY, json.dumps({"cert": cur["cert"], "key": cur["key"], "retired": utcnow()}))
    set_setting(conn, CA_KEY, json.dumps({"cert": cert, "key": key}))
    conn.commit()
    ensure_server(conn, rebuild=True)
    _audit(conn, "Started rotating the certificate authority for agent ingest (the old one stays trusted until the rotation is finished)", "/ingest/ca/rotate")


def finish_rotation(conn, force: bool = False) -> None:
    """Stop trusting the old CA. Refused while an agent still holds a certificate from it (it would be locked out), unless forced."""
    r = rotation(conn)
    if r is None:
        raise IngestError("no rotation is running")
    if r["agents_on_old_ca"] and not force:
        n = len(r["agents_on_old_ca"])
        raise IngestError(f"{n} agent{'s' if n != 1 else ''} still use{'' if n != 1 else 's'} a certificate from the old CA ({', '.join(r['agents_on_old_ca'][:5])}): they must renew first, or finish anyway to lock them out")
    set_setting(conn, CA_PREV_KEY, "")
    conn.commit()
    ensure_server(conn, rebuild=True)
    _audit(conn, "Finished rotating the certificate authority for agent ingest" + (f" (forced: {len(r['agents_on_old_ca'])} agents locked out)" if r["agents_on_old_ca"] else ""), "/ingest/ca/finish")


def cancel_rotation(conn) -> None:
    """Go back to the old CA, when no agent has a certificate from the new one yet."""
    prev = _prev(conn)
    if prev is None:
        raise IngestError("no rotation is running")
    cur = ca_id(ensure_ca(conn)["cert"])
    if conn.execute("SELECT 1 FROM ingest_agents WHERE cert_ca = ?", (cur,)).fetchone():
        raise IngestError("agents already received certificates from the new CA: finish the rotation instead")
    set_setting(conn, CA_KEY, json.dumps({"cert": prev["cert"], "key": prev["key"]}))
    set_setting(conn, CA_PREV_KEY, "")
    conn.commit()
    ensure_server(conn, rebuild=True)
    _audit(conn, "Cancelled the rotation of the certificate authority for agent ingest", "/ingest/ca/cancel")


def _uploaded(conn) -> bool:
    s = _load(conn, SERVER_KEY)
    return bool(s and s.get("source") == "uploaded")


def ensure_server(conn, rebuild: bool = False) -> dict[str, Any]:
    s = _load(conn, SERVER_KEY)
    names = get_policy(conn)["server_names"]
    if s and s.get("source") == "uploaded":
        return s
    issuer = _issuer(conn)
    iid = ca_id(issuer["cert"])
    if not s or rebuild or sorted(s.get("names", [])) != sorted(names) or s.get("issuer") != iid:
        cert, key = pki.issue_server(issuer["cert"], issuer["key"], names)
        s = {"cert": cert, "key": key, "source": "generated", "names": names, "issuer": iid}
        set_setting(conn, SERVER_KEY, json.dumps(s))
        conn.commit()
    return s


def upload_server(conn, cert_pem: str, key_pem: str) -> list[str]:
    try:
        names = pki.check_server_pair(cert_pem, key_pem)
    except pki.PkiError as exc:
        raise IngestError(str(exc)) from None
    set_setting(conn, SERVER_KEY, json.dumps({"cert": cert_pem.strip() + "\n", "key": key_pem.strip() + "\n", "source": "uploaded", "names": names}))
    conn.commit()
    return names


def use_generated_server(conn) -> None:
    set_setting(conn, SERVER_KEY, "")
    conn.commit()


def byo_bundle(conn) -> str:
    return get_setting(conn, BYO_KEY) or ""


def save_byo(conn, text: str) -> int:
    text = (text or "").strip()
    if not text:
        set_setting(conn, BYO_KEY, "")
        conn.commit()
        return 0
    try:
        certs = pki.parse_bundle(text)
    except pki.PkiError as exc:
        raise IngestError(str(exc)) from None
    set_setting(conn, BYO_KEY, "\n".join(pki.pem(c) for c in certs))
    conn.commit()
    return len(certs)


def trust_bundle(conn) -> str:
    """The CA certificates a client certificate may chain to: the Netlens ingest CA and, when set, the customer's."""
    return ca_certificate(conn) + "\n" + byo_bundle(conn)


# ----------------------------------------------------------------------------------------------- agents
def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _targets(conn, targets: Any, agent_id: int | None = None) -> list[tuple[int, str]]:
    if not isinstance(targets, list) or not 1 <= len(targets) <= 200:
        raise IngestError("link the agent to at least one device")
    out: list[tuple[int, str]] = []
    for t in targets:
        did = t.get("device_id") if isinstance(t, dict) else t
        host = str(t.get("host_name", "") if isinstance(t, dict) else "").strip().lower()
        if isinstance(did, bool) or not isinstance(did, int) or conn.execute("SELECT 1 FROM devices WHERE id = ?", (did,)).fetchone() is None:
            raise IngestError("a linked device does not exist")
        if host and not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,252}", host):
            raise IngestError("a host name in the data may contain letters, digits, dot, dash and underscore only")
        if any(d == did for d, _h in out):
            raise IngestError("a device can be linked once per agent")
        out.append((did, host))
    if len(out) > 1 and any(not h for _d, h in out):
        raise IngestError("an agent that reports for several devices needs, for each device, the host name it uses in its data")
    if len({h for _d, h in out}) != len(out):
        raise IngestError("two devices have the same host name")
    for did, _h in out:
        row = conn.execute("SELECT method FROM host_monitors WHERE device_id = ?", (did,)).fetchone()
        if row is not None and row["method"] != "agent":
            raise IngestError("a linked device is already monitored another way (Settings → Hosts); remove that monitor first so the two do not mix")
        other = conn.execute("SELECT agent_id FROM ingest_targets WHERE device_id = ? AND agent_id != ?", (did, agent_id or 0)).fetchone()
        if other is not None:
            raise IngestError("a linked device already has an agent")
    return out


def create_agent(conn, name: str, targets: Any, identity: str = "", interval_s: int = DEFAULT_INTERVAL) -> tuple[dict[str, Any], str | None]:
    """(agent, one-time token). A customer-issued certificate needs no token (the identity is matched); the token is None then."""
    name = str(name or "").strip()
    if not NAME_RE.match(name):
        raise IngestError("give the agent a name (up to 80 characters)")
    if isinstance(interval_s, bool) or not isinstance(interval_s, int) or not MIN_INTERVAL <= interval_s <= MAX_INTERVAL:
        raise IngestError(f"the sending interval is {MIN_INTERVAL} to {MAX_INTERVAL} seconds")
    ident = ""
    if identity:
        try:
            ident = pki.valid_identity(identity)
        except pki.PkiError as exc:
            raise IngestError(str(exc)) from None
        if not byo_bundle(conn):
            raise IngestError("upload your CA certificate first (Trust your own CA); the identity is matched on certificates it issued")
        if conn.execute("SELECT 1 FROM ingest_agents WHERE identity = ?", (ident,)).fetchone():
            raise IngestError("another agent already uses that identity")
    tg = _targets(conn, targets)
    token = None if ident else "nlt_" + secrets.token_urlsafe(32)
    aid = insert_id(
        conn, "INSERT INTO ingest_agents (name, identity, state, token_hash, token_expires, interval_s, created) VALUES (?,?,?,?,?,?,?)",
        (name, ident, "active" if ident else "pending", _hash(token) if token else None, _stamp(time.time() + TOKEN_HOURS * 3600) if token else None, interval_s, utcnow()))
    conn.executemany("INSERT INTO ingest_targets (agent_id, device_id, host_name) VALUES (?,?,?)", [(aid, d, h) for d, h in tg])
    conn.commit()
    return get_agent(conn, aid), token


def update_agent(conn, agent_id: int, data: dict[str, Any]) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM ingest_agents WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise IngestError("no such agent")
    if "name" in data:
        name = str(data["name"]).strip()
        if not NAME_RE.match(name):
            raise IngestError("give the agent a name (up to 80 characters)")
        conn.execute("UPDATE ingest_agents SET name = ? WHERE id = ?", (name, agent_id))
    if "interval_s" in data:
        v = data["interval_s"]
        if isinstance(v, bool) or not isinstance(v, int) or not MIN_INTERVAL <= v <= MAX_INTERVAL:
            raise IngestError(f"the sending interval is {MIN_INTERVAL} to {MAX_INTERVAL} seconds")
        conn.execute("UPDATE ingest_agents SET interval_s = ? WHERE id = ?", (v, agent_id))
    if "targets" in data:
        tg = _targets(conn, data["targets"], agent_id)
        conn.execute("DELETE FROM ingest_targets WHERE agent_id = ?", (agent_id,))
        conn.executemany("INSERT INTO ingest_targets (agent_id, device_id, host_name) VALUES (?,?,?)", [(agent_id, d, h) for d, h in tg])
        _drop_monitors(conn, agent_id, {d for d, _h in tg})                        # a device that is no longer linked stops being an agent monitor
    conn.commit()
    return get_agent(conn, agent_id)


def new_token(conn, agent_id: int) -> str:
    """Enrol again (lost host, expired certificate): the old certificate stops working at once and a new one-time token is made."""
    row = conn.execute("SELECT * FROM ingest_agents WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise IngestError("no such agent")
    if row["identity"]:
        raise IngestError("this agent uses a certificate from your own CA; there is nothing to enrol again (issue a new certificate there)")
    token = "nlt_" + secrets.token_urlsafe(32)
    conn.execute("UPDATE ingest_agents SET state = 'pending', token_hash = ?, token_expires = ?, cert_fp = NULL, cert_expires = NULL, prev_fp = NULL, prev_expires = NULL, silent = 0 WHERE id = ?",
                 (_hash(token), _stamp(time.time() + TOKEN_HOURS * 3600), agent_id))
    conn.commit()
    return token


def revoke(conn, agent_id: int) -> None:
    """The certificate is refused from the next connection on; the agent record and its history stay."""
    cur = conn.execute("UPDATE ingest_agents SET state = 'revoked', token_hash = NULL, token_expires = NULL, cert_fp = NULL, prev_fp = NULL, silent = 0 WHERE id = ?", (agent_id,))
    if not cur.rowcount:
        raise IngestError("no such agent")
    conn.commit()


def reinstate(conn, agent_id: int) -> None:
    row = conn.execute("SELECT * FROM ingest_agents WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise IngestError("no such agent")
    if not row["identity"]:
        raise IngestError("a revoked agent that uses a Netlens certificate must enrol again (make a new token)")
    conn.execute("UPDATE ingest_agents SET state = 'active' WHERE id = ?", (agent_id,))
    conn.commit()


def _drop_monitors(conn, agent_id: int, keep: set[int] | None = None) -> None:
    """The monitors this agent created go away with it (or with the link to the device): an agent monitor that nobody feeds anymore cannot be edited by hand."""
    for m in conn.execute("SELECT id, device_id FROM host_monitors WHERE method = 'agent' AND source = ?", (f"agent:{agent_id}",)).fetchall():
        if keep is not None and m["device_id"] in keep:
            continue
        conn.execute("DELETE FROM metric_state WHERE monitor_id = ?", (m["id"],))
        conn.execute("DELETE FROM host_monitors WHERE id = ?", (m["id"],))
        _STATES.pop((agent_id, m["device_id"]), None)


def delete_agent(conn, agent_id: int) -> None:
    if conn.execute("SELECT 1 FROM ingest_agents WHERE id = ?", (agent_id,)).fetchone() is None:
        raise IngestError("no such agent")
    _drop_monitors(conn, agent_id)
    conn.execute("DELETE FROM ingest_agents WHERE id = ?", (agent_id,))
    conn.commit()


def get_agent(conn, agent_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM ingest_agents WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise IngestError("no such agent")
    return public(conn, row)


def public(conn, row) -> dict[str, Any]:
    """The agent as the API shows it: never the token hash or a fingerprint secret, only what the administrator needs."""
    targets = [{"device_id": t["device_id"], "host_name": t["host_name"], "name": t["name"]} for t in conn.execute(
        "SELECT t.device_id, t.host_name, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name FROM ingest_targets t JOIN devices d ON d.id = t.device_id "
        "WHERE t.agent_id = ? ORDER BY name", (row["id"],))]
    now = time.time()
    exp = _parse(row["cert_expires"])
    tok = _parse(row["token_expires"])
    return {"id": row["id"], "name": row["name"], "identity": row["identity"] or None, "mode": "own_ca" if row["identity"] else "netlens_ca", "state": row["state"],
            "interval_s": row["interval_s"], "targets": targets, "last_seen": row["last_seen"], "last_ip": row["last_ip"], "accepted": row["accepted"],
            "dropped": row["dropped"], "rejected": row["rejected"], "silent": bool(row["silent"]), "cert_expires": row["cert_expires"],
            "cert_days_left": None if exp is None else int((exp - now) // 86400), "token_pending": bool(row["token_hash"] and tok and tok > now),
            "token_expires": row["token_expires"] if row["token_hash"] else None, "created": row["created"]}


def list_agents(conn) -> list[dict[str, Any]]:
    return [public(conn, r) for r in conn.execute("SELECT * FROM ingest_agents ORDER BY LOWER(name)")]


# ----------------------------------------------------------------------------------------------- enrolment and renewal
_REFUSED = "enrolment refused"


def enrol(conn, token: str, csr_pem: str, ip: str = "") -> str:
    """The certificate (with the CA certificate behind it) for a valid one-time token and a CSR. One generic refusal for every reason: it must not tell which part was wrong."""
    if not re.fullmatch(r"nlt_[A-Za-z0-9_-]{20,80}", token or ""):
        raise IngestError(_REFUSED)
    row = conn.execute("SELECT * FROM ingest_agents WHERE token_hash = ? AND state = 'pending'", (_hash(token),)).fetchone()
    if row is None or not hmac.compare_digest(row["token_hash"] or "", _hash(token)) or (_parse(row["token_expires"]) or 0) < time.time():
        raise IngestError(_REFUSED)
    try:
        ca = ensure_ca(conn)
        cert, fp, end = pki.sign_csr(ca["cert"], ca["key"], csr_pem, f"netlens-agent-{row['id']}")
    except pki.PkiError as exc:
        raise IngestError(str(exc)) from None                                    # the token is NOT used up by a bad request
    conn.execute("UPDATE ingest_agents SET state = 'active', token_hash = NULL, token_expires = NULL, cert_fp = ?, cert_expires = ?, prev_fp = NULL, prev_expires = NULL, "
                 "renewed = ?, silent = 0, cert_ca = ? WHERE id = ?", (fp, end, utcnow(), ca_id(ca["cert"]), row["id"]))
    conn.commit()
    _audit(conn, f"Issued a certificate to agent '{row['name']}' (enrolment from {ip or 'unknown'}), valid until {end}", "/ingest/enrol")
    add_event(conn, "ingest_enrolled", f"Agent '{row['name']}' enrolled and received a certificate", subject=f"ingest:{row['id']}")
    return cert + ca_certificate(conn)


def renew(conn, agent_row, csr_pem: str) -> str:
    """A new certificate for an agent that presented its current one. The old one keeps working until it would have expired (at most a week) so a failed hand-over does not lose the agent."""
    if agent_row["identity"]:
        raise IngestError("certificates from your own CA are renewed there")
    last = _parse(agent_row["renewed"]) or 0
    if time.time() - last < RENEW_EVERY_S:
        raise IngestError("renewed a moment ago; try again later")
    try:
        ca = ensure_ca(conn)
        cert, fp, end = pki.sign_csr(ca["cert"], ca["key"], csr_pem, f"netlens-agent-{agent_row['id']}")
    except pki.PkiError as exc:
        raise IngestError(str(exc)) from None
    keep = min(_parse(agent_row["cert_expires"]) or 0, time.time() + 7 * 86400)
    conn.execute("UPDATE ingest_agents SET prev_fp = cert_fp, prev_expires = ?, cert_fp = ?, cert_expires = ?, renewed = ?, cert_ca = ? WHERE id = ?",
                 (_stamp(keep), fp, end, utcnow(), ca_id(ca["cert"]), agent_row["id"]))
    conn.commit()
    _audit(conn, f"Renewed the certificate of agent '{agent_row['name']}', valid until {end}", "/ingest/renew")
    return cert + ca_certificate(conn)


# ----------------------------------------------------------------------------------------------- who is this connection
def find_agent(conn, der: bytes):
    """(agent row or None, reason) for a client certificate that the TLS layer already verified against the trusted CAs."""
    fp = pki.fingerprint(der)
    now = time.time()
    row = conn.execute("SELECT * FROM ingest_agents WHERE cert_fp = ? AND identity = ''", (fp,)).fetchone()
    if row is None:
        row = conn.execute("SELECT * FROM ingest_agents WHERE prev_fp = ? AND identity = ''", (fp,)).fetchone()
        if row is not None and (_parse(row["prev_expires"]) or 0) < now:
            row = None
    if row is None:
        try:
            ids = pki.identities(der)
        except ValueError:
            return None, "unreadable certificate"
        for ident in ids:
            hit = conn.execute("SELECT * FROM ingest_agents WHERE identity = ?", (ident,)).fetchone()
            if hit is not None:
                row = hit
                break
    if row is None:
        return None, "certificate not known to any agent"
    if row["state"] != "active":
        return None, f"agent is {row['state']}"
    return row, ""


def pick_targets(conn, agent_id: int, host: str) -> list[int]:
    """The devices the data may be recorded for. One linked device: every payload is for it (the host name in the data is ignored). Several (a gateway): the
    host name in the data must be one of the names that were entered; anything else is dropped."""
    rows = conn.execute("SELECT device_id, host_name FROM ingest_targets WHERE agent_id = ?", (agent_id,)).fetchall()
    if len(rows) == 1:
        return [rows[0]["device_id"]]
    return [r["device_id"] for r in rows if host and r["host_name"] == host]


# ----------------------------------------------------------------------------------------------- readings
_STATES: dict[tuple[int, int], dict] = {}          # (agent, device) -> counters of the last request


def state_for(agent_id: int, device_id: int) -> dict:
    return _STATES.setdefault((agent_id, device_id), {})


def accept(conn, agent_row, device_id: int, points: list[tuple], stamp: float) -> bool:
    """Store the readings of one device like any other host monitor and run the usual limits. False when the device is monitored another way."""
    from app.hostmetrics import service as hm

    row = hm.get_monitor(conn, device_id)
    now = utcnow()
    if row is None:
        conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created, source) VALUES (?, 'agent', '', 0, '', ?, '[]', 1, 1, ?, ?)",
                     (device_id, agent_row["interval_s"], now, f"agent:{agent_row['id']}"))
        row = hm.get_monitor(conn, device_id)
    elif row["method"] != "agent" or row["source"] != f"agent:{agent_row['id']}":
        return False
    name_row = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (device_id,)).fetchone()
    if points:
        hm.record(conn, device_id, points, stamp)
        conn.execute("UPDATE host_monitors SET last_ts = ?, last_ok = 1, last_error = NULL, since = COALESCE(since, ?) WHERE id = ?", (now, now, row["id"]))
        if row["alerts"]:
            hm.evaluate(conn, row["id"], device_id, name_row["n"] if name_row else f"device {device_id}", points, now)
    conn.commit()
    return True


def note(conn, agent_row, accepted: int, dropped: int, ip: str) -> None:
    """Counters and 'last seen' after a request; also ends a silence."""
    conn.execute("UPDATE ingest_agents SET accepted = accepted + ?, dropped = dropped + ?, last_seen = ?, last_ip = ?, silent = 0 WHERE id = ?",
                 (accepted, dropped, utcnow(), (ip or "")[:60], agent_row["id"]))
    if agent_row["silent"]:
        for t in conn.execute("SELECT device_id FROM ingest_targets WHERE agent_id = ?", (agent_row["id"],)):
            add_event(conn, "agent_back", f"Agent '{agent_row['name']}' is sending again", device_id=t["device_id"], subject=f"agent:{agent_row['id']}")
    conn.commit()


def note_cert(conn, agent_id: int, expires: str) -> None:
    conn.execute("UPDATE ingest_agents SET cert_expires = ? WHERE id = ? AND (cert_expires IS NULL OR cert_expires != ?)", (expires, agent_id, expires))
    conn.commit()


def note_rejected(conn, agent_id: int | None) -> None:
    if agent_id is not None:
        conn.execute("UPDATE ingest_agents SET rejected = rejected + 1 WHERE id = ?", (agent_id,))
        conn.commit()


# ----------------------------------------------------------------------------------------------- silence and expiry
def check_silence(conn, now: float | None = None) -> list[str]:
    """Raise `agent_silent` for agents that stopped sending (once), and `ingest_cert_expiring` for certificates that end within 7 days (once a day).
    Silence is not the same as the host being down: the network or the collector may be the cause, so the wording says only what is known."""
    now = now if now is not None else time.time()
    raised: list[str] = []
    for r in conn.execute("SELECT * FROM ingest_agents WHERE state = 'active'").fetchall():
        limit = max(SILENT_FACTOR * r["interval_s"], SILENT_MIN_S)
        if r["last_seen"] is None:
            limit = max(limit, NEVER_SEEN_S)               # an agent that was just set up has not had time to be installed on the host yet
        ref = _parse(r["last_seen"]) or _parse(r["renewed"]) or _parse(r["created"]) or now
        if not r["silent"] and now - ref > limit:
            conn.execute("UPDATE ingest_agents SET silent = 1 WHERE id = ?", (r["id"],))
            for t in conn.execute("SELECT device_id FROM ingest_targets WHERE agent_id = ?", (r["id"],)):
                add_event(conn, "agent_silent", f"Agent '{r['name']}' has not sent data for {int((now - ref) // 60)} minutes (the host, the network or the collector may be the cause)",
                          device_id=t["device_id"], subject=f"agent:{r['id']}")
            raised.append("agent_silent")
        exp = _parse(r["cert_expires"])
        if exp is not None and exp - now < 7 * 86400:
            mark = f"agent '{r['name']}'"
            recent = any(mark in (e["detail"] or "") for e in conn.execute("SELECT detail FROM events WHERE kind = 'ingest_cert_expiring' AND ts >= ?", (_stamp(now - 86400),)))
            if not recent:
                left = int((exp - now) // 86400)
                add_event(conn, "ingest_cert_expiring",
                          f"The certificate of agent '{r['name']}' " + (f"ends in {left} day{'s' if left != 1 else ''}" if exp > now else "has expired"), subject=f"ingest:{r['id']}")
                raised.append("ingest_cert_expiring")
    ca = pki.load_cert(ensure_ca(conn)["cert"]) if _load(conn, CA_KEY) else None
    if ca is not None and (ca.not_valid_after_utc.timestamp() - now) < CA_WARN_DAYS * 86400:
        recent = any(e for e in conn.execute("SELECT 1 FROM events WHERE kind = 'ingest_ca_expiring' AND ts >= ?", (_stamp(now - 7 * 86400),)))
        if not recent and rotation(conn) is None:
            left = int((ca.not_valid_after_utc.timestamp() - now) // 86400)
            add_event(conn, "ingest_ca_expiring", f"The certificate authority for host agents ends in {left} days: rotate it (Settings → Host agents)", subject="ingest:ca")
            raised.append("ingest_ca_expiring")
    conn.commit()
    return raised


def problems(conn) -> list[dict[str, Any]]:
    """For the dashboard and the AI: silent agents and certificates that are about to end (the same list everywhere)."""
    out = []
    now = time.time()
    if _load(conn, CA_KEY) and rotation(conn) is None:
        left = (pki.load_cert(ensure_ca(conn)["cert"]).not_valid_after_utc.timestamp() - now) / 86400
        if left < CA_WARN_DAYS:
            out.append({"agent_id": 0, "name": "CA", "kind": "ca", "since": None, "text": f"The certificate authority for host agents ends in {int(left)} days: rotate it (Settings → Host agents)"})
    for r in conn.execute("SELECT * FROM ingest_agents WHERE state = 'active'"):
        exp = _parse(r["cert_expires"])
        if r["silent"]:
            out.append({"agent_id": r["id"], "name": r["name"], "kind": "silent", "since": r["last_seen"],
                        "text": f"Agent '{r['name']}' is silent" + (f" since {r['last_seen']}" if r["last_seen"] else " (never sent data)")})
        if exp is not None and exp - now < 7 * 86400:
            out.append({"agent_id": r["id"], "name": r["name"], "kind": "certificate", "since": None,
                        "text": f"The certificate of agent '{r['name']}' " + ("has expired" if exp <= now else f"ends in {int((exp - now) // 86400)} days")})
    return out


def _audit(conn, action: str, path: str, status: int = 200) -> None:
    from app import audit

    audit.record_system(conn, action[:300], path, status)


def status_summary(conn) -> dict[str, Any]:
    """What an assistant, a report or a viewer may know: which hosts report through an agent and whether they are healthy. No tokens, certificates or addresses."""
    from app import licence

    policy = get_policy(conn)
    agents = []
    for a in list_agents(conn):
        agents.append({"name": a["name"], "state": a["state"], "silent": a["silent"], "last_seen": a["last_seen"], "certificate_days_left": a["cert_days_left"],
                       "devices": [t["name"] for t in a["targets"]], "accepted_points": a["accepted"], "dropped_points": a["dropped"], "refused_requests": a["rejected"]})
    return {"available": licence.allows(conn, "agents"), "enabled": bool(policy["enabled"]), "agents": agents, "problems": [p["text"] for p in problems(conn)]}
