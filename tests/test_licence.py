import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app import licence, probes, tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

pytestmark = pytest.mark.real_licence
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
PRIVATE = Ed25519PrivateKey.generate()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def key(edition="business", expires="2027-11-01", sites="default", **extra):
    payload = {"v": 1, "id": "abc", "edition": edition, "holder": "Acme", "email": "a@b.c", "issued": "2026-11-01", "expires": expires, **extra}
    if sites != "default":
        payload["sites"] = sites
    body = b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return f"NLK1.{body}.{b64(PRIVATE.sign(body.encode()))}"


@pytest.fixture(autouse=True)
def public_key(monkeypatch):
    monkeypatch.setattr(licence, "PUBLIC_KEY", b64(PRIVATE.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()
    tsdb.forget_all()


def test_free_by_default(conn):
    st = licence.status(conn, NOW)
    assert st["state"] == "free" and st["sites"] == 1 and st["trial_available"] and st["edition"] == "free"


def test_keys_are_checked(conn):
    assert licence.parse(key())["edition"] == "business"
    with pytest.raises(licence.LicenceError):
        licence.parse(key()[:-3] + "AAA")
    with pytest.raises(licence.LicenceError):
        licence.parse(key().replace("NLK1", "NLK2"))
    other = Ed25519PrivateKey.generate()
    body = b64(b'{"edition":"enterprise"}')
    with pytest.raises(licence.LicenceError):
        licence.parse(f"NLK1.{body}.{b64(other.sign(body.encode()))}")
    with pytest.raises(licence.LicenceError):
        licence.parse("garbage")
    tampered = key().split(".")
    tampered[1] = b64(json.dumps({"edition": "enterprise", "expires": None}).encode())
    with pytest.raises(licence.LicenceError):
        licence.parse(".".join(tampered))


def test_editions_and_site_counts(conn):
    assert licence.install(conn, key("business"), NOW)["sites"] == 10
    assert licence.install(conn, key("enterprise"), NOW)["sites"] is None
    assert licence.install(conn, key("supporter"), NOW)["sites"] == 3
    assert licence.install(conn, key("business", sites=25), NOW)["sites"] == 25


def test_a_key_without_an_end_date_never_ends(conn):
    licence.install(conn, key("enterprise", expires=None), NOW)
    st = licence.status(conn, NOW + timedelta(days=5000))
    assert st["state"] == "active" and st["expires"] is None and st["name"] == "Enterprise"


def test_supporter_is_a_yearly_key_with_a_grace_period(conn):
    licence.install(conn, key("supporter", expires="2027-11-01"), NOW)
    assert licence.status(conn, NOW)["name"] == "Supporter" and licence.status(conn, NOW)["state"] == "active"
    assert licence.status(conn, NOW + timedelta(days=370))["state"] == "grace"
    assert licence.status(conn, NOW + timedelta(days=420))["edition"] == "free"


def test_supporter_has_the_business_features_except_the_ones_for_organisations(conn):
    licence.install(conn, key("supporter"), NOW)
    for feature in ("remediation", "engineer", "insights", "vulnerabilities", "oncall"):
        assert licence.allows(conn, feature, NOW), feature
    for feature in ("sso", "siem", "teams", "schedules", "agents"):
        assert not licence.allows(conn, feature, NOW), feature
    licence.install(conn, key("business"), NOW)
    assert all(licence.allows(conn, f, NOW) for f in licence.PAID_FEATURES if f not in licence.ENTERPRISE_ONLY)
    assert not licence.allows(conn, "agents", NOW)                              # host agents (locked-down hosts) are Enterprise only
    licence.install(conn, key("enterprise"), NOW)
    assert all(licence.allows(conn, f, NOW) for f in licence.PAID_FEATURES)


def test_the_free_trial_has_every_feature_and_community_none(conn):
    assert not any(licence.allows(conn, f, NOW) for f in licence.PAID_FEATURES)
    licence.start_trial(conn, NOW)
    assert all(licence.allows(conn, f, NOW) for f in licence.PAID_FEATURES)


def test_warning_grace_and_end(conn):
    licence.install(conn, key(expires="2026-11-20"), NOW)
    st = licence.status(conn, NOW)
    assert st["state"] == "active" and st["days_left"] == 19 and "19 days" in st["message"]
    assert licence.status(conn, NOW + timedelta(days=19))["state"] == "active"
    grace = licence.status(conn, NOW + timedelta(days=30))
    assert grace["state"] == "grace" and grace["sites"] == 10
    ended = licence.status(conn, NOW + timedelta(days=60))
    assert ended["state"] == "expired" and ended["sites"] == 1 and ended["edition"] == "free"


def test_install_refuses_a_long_expired_key(conn):
    with pytest.raises(licence.LicenceError):
        licence.install(conn, key(expires="2026-01-01"), NOW)


def test_remove(conn):
    licence.install(conn, key(), NOW)
    assert licence.remove(conn)["sites"] == 1


def test_trial_runs_once_for_thirty_days(conn):
    st = licence.start_trial(conn, NOW)
    assert st["state"] == "trial" and st["sites"] is None and st["days_left"] == 30 and not st["trial_available"]
    with pytest.raises(licence.LicenceError):
        licence.start_trial(conn, NOW)
    assert licence.status(conn, NOW + timedelta(days=29))["state"] == "trial"
    over = licence.status(conn, NOW + timedelta(days=31))
    assert over["state"] == "trial_over" and over["sites"] == 1 and not over["trial_available"]


def test_restoring_a_backup_does_not_renew_the_trial(conn, tmp_path):
    licence.start_trial(conn, NOW)
    conn.execute("DELETE FROM settings WHERE key LIKE 'licence.%'")       # a backup from before the trial
    conn.commit()
    assert (tmp_path / licence.MARKER).exists()
    st = licence.status(conn, NOW + timedelta(days=40))
    assert st["state"] == "trial_over" and not st["trial_available"]
    with pytest.raises(licence.LicenceError):
        licence.start_trial(conn, NOW + timedelta(days=40))


def test_setting_the_clock_back_does_not_extend_anything(conn):
    licence.start_trial(conn, NOW + timedelta(days=20))
    later = NOW + timedelta(days=60)
    assert licence.status(conn, later)["state"] == "trial_over"      # remembers that time has reached day 60
    st = licence.status(conn, NOW)                                    # the clock is turned back to the start
    assert st["state"] == "trial_over" and st["clock_warning"]


def test_events_for_the_end_of_a_licence(conn):
    licence.install(conn, key(expires="2026-11-20"), NOW)
    assert licence.notify(conn, NOW)
    assert licence.notify(conn, NOW) is None                          # once per step
    assert licence.notify(conn, NOW + timedelta(days=6))              # the 14 day step
    assert licence.notify(conn, NOW + timedelta(days=40))             # the grace period
    kinds = [r["kind"] for r in conn.execute("SELECT kind FROM events")]
    assert kinds.count("licence_expiring") == 3


def test_free_edition_takes_one_remote_site_and_freezes_the_rest(conn):
    first, _ = probes.create(conn, "First")
    with pytest.raises(probes.LicenceLimit):
        probes.create(conn, "Second")
    licence.install(conn, key(), NOW)
    second, _ = probes.create(conn, "Second")
    third, _ = probes.create(conn, "Third")
    assert probes.locked_ids(conn) == set()
    licence.remove(conn)
    assert probes.locked_ids(conn) == {second["id"], third["id"]}     # the oldest site stays
    assert not conn.execute("SELECT 1 FROM probes WHERE id = ?", (first["id"],)).fetchone() is None


def test_api(tmp_path):
    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        assert client.get("/api/licence", headers=h).json()["sites"] == 1
        assert client.post("/api/probes", json={"name": "A"}, headers=h).status_code == 201
        refused = client.post("/api/probes", json={"name": "B"}, headers=h)
        assert refused.status_code == 402 and "licence" in refused.json()["detail"].lower()
        assert client.put("/api/licence", json={"key": "nonsense"}, headers=h).status_code == 422
        assert client.put("/api/licence", json={"key": key()}, headers=h).json()["state"] == "active"
        assert client.post("/api/probes", json={"name": "B"}, headers=h).status_code == 201
        token = client.post("/api/probes", json={"name": "C"}, headers=h).json()["token"]
        client.delete("/api/licence", headers=h)
        locked = client.post("/api/probe/push", json={}, headers={"Authorization": f"Bearer {token}"})
        assert locked.status_code == 402
        assert client.post("/api/licence/trial", headers=h).status_code == 200
        assert client.post("/api/licence/trial", headers=h).status_code == 409
        assert client.post("/api/probe/push", json={}, headers={"Authorization": f"Bearer {token}"}).status_code == 200     # the trial thaws it
    tsdb.forget_all()
