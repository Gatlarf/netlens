"""The wider set of questions of "Ask your network": every tool with its sentence, and the words that pick it without a language model."""

import json
from datetime import datetime, timezone

import pytest

from app import ask, hierarchy, licence, tsdb
from app.db import add_event, connect, init_db

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "m.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    rows = [  # id, name, ip, vendor, os, type, online, trusted
        (1, "nas", "192.168.1.20", "Synology Inc.", "Linux 5.10", "nas", 1, 1), (2, "hp-laserjet", "192.168.1.30", "HP", None, "printer", 0, 1), (3, "voordeur", "192.168.1.31", "Hikvision", None, "camera", 1, 1),
        (4, "iphone-bert", "192.168.1.50", "Apple, Inc.", "iOS 17", "phone", 0, 1), (5, "macbook", "192.168.1.51", "Apple, Inc.", "macOS 14", "pc", 1, 1), (6, "desktop-1", "192.168.1.60", "Dell", "Windows 11", "pc", 1, 0),
        (7, "sw-garden", "192.168.1.2", "TP-Link", None, "switch", 1, 1)]
    for i, name, ip, vendor, os_name, typ, online, trusted in rows:
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, vendor, os_name, device_type, online, trusted, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '2026-10-31T00:00:00Z', '2026-11-01T11:00:00Z')",
                  (i, f"aa:bb:cc:dd:ee:0{i}", ip, name, vendor, os_name, typ, online, trusted))
    for dev, port, proto, svc in [(1, 22, "tcp", "ssh"), (1, 445, "tcp", "microsoft-ds"), (6, 3389, "tcp", "ms-wbt-server"), (3, 554, "tcp", "rtsp"), (5, 22, "tcp", "ssh")]:
        c.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, ?, ?, 'open', ?, 'x')", (dev, proto, port, svc))
    for guest, name, kind, status, details in [("100", "BlueIris", "qemu", "running", "{}"), ("101", "vm-old", "qemu", "stopped", "{}"), ("c1", "whoiswho", "container", "restarting", '{"restarts": 50, "health": "unhealthy"}')]:
        c.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, updated, details) VALUES ('proxmox', ?, ?, ?, 'nuc', ?, 'x', ?)", (guest, name, kind, status, details))
    c.execute("INSERT INTO service_checks (id, name, kind, host, port, enabled, last_up, created) VALUES (1, 'Website', 'http', 'example.org', 443, 1, 1, 'x')")
    c.execute("INSERT INTO speedtests (ts, kind, target, down_mbps, up_mbps, latency_ms, ok) VALUES ('2026-10-30T10:00:00Z', 'internet', 'x', 480.0, 50.0, 12.0, 1), ('2026-10-31T10:00:00Z', 'internet', 'x', 320.0, 48.0, 15.0, 1)")
    c.execute("INSERT INTO inventory_devices (plugin_id, dev_id, server_id, name, area, available, battery, battery_low, update_available) VALUES ('homeassistant', 'a', 's', 'Hall sensor', 'Hall', 1, 8, 1, 0), ('homeassistant', 'b', 's', 'Lamp', 'Hall', 0, NULL, 0, 1)")
    c.execute("INSERT INTO dhcp_servers (ip, trusted, first_seen, last_seen, router, dns) VALUES ('192.168.1.1', 1, 'x', '2026-11-01T10:00:00Z', '192.168.1.1', '[\"192.168.1.1\"]'), ('192.168.1.99', 0, 'x', '2026-11-01T10:00:00Z', NULL, '[]')")
    c.execute("INSERT INTO audit_log (ts, user, method, path, status, action) VALUES ('2026-10-30T09:00:00Z', 'bert', 'PUT', '/api/x', 200, 'Changed the weekly report settings')")
    c.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi) VALUES (4, '2026-11-01T11:30:00Z', 'AP-hall', '5GHz', -78), (5, '2026-11-01T11:30:00Z', 'AP-hall', '5GHz', -50)")
    c.execute("INSERT INTO scans (kind, status, started, finished, hosts_found) VALUES ('quick', 'done', '2026-11-01T11:45:00Z', '2026-11-01T11:46:00Z', 7)")
    c.commit()
    add_event(c, "login_failed", "3 failed logins from 10.0.0.9", now="2026-10-31T20:00:00Z")
    tsdb.for_conn(c).record([("service", 1, "cert_days", 12.0, "", "days")], ts=int(NOW.timestamp()))
    yield c
    c.close()
    tsdb.forget_all()


def tool_for(conn, q):
    names = [r["hostname"] for r in conn.execute("SELECT hostname FROM devices")]
    return ask.route(q, names, conn)


@pytest.mark.parametrize("question,tool", [
    ("How many devices do I have per type?", "counts"), ("what kinds of devices are there", "counts"), ("how many devices per manufacturer", "counts"),
    ("Which devices run Windows?", "search_devices"), ("any android or ios devices?", "search_devices"), ("Which Apple devices are offline?", "search_devices"), ("show me all the dell machines", "search_devices"),
    ("Which devices have SSH open?", "ports"), ("who has port 3389 open", "ports"), ("which ports does the nas have open?", "ports"), ("is rdp exposed on any machine", "ports"),
    ("Which virtual machines are stopped?", "guests"), ("how many containers are running", "guests"), ("which docker containers are unhealthy", "guests"), ("what is running on proxmox", "guests"),
    ("Are my backups healthy?", "backups"), ("which vms have no backup", "backups"),
    ("when do my certificates expire", "certificates"), ("is any ssl certificate about to expire", "certificates"),
    ("How fast is my internet?", "speedtest"), ("what was my last speedtest", "speedtest"),
    ("Is there anything suspicious on the network?", "security"), ("any rogue dhcp server?", "security"), ("were there failed logins", "security"),
    ("which smart home batteries are low", "smart_home"), ("any home assistant device unavailable", "smart_home"),
    ("what is the nas connected to?", "connections"), ("what depends on sw-garden", "connections"),
    ("which devices have a weak wifi signal", "wifi"), ("who changed settings this week", "audit"),
    ("is a maintenance window planned", "maintenance"), ("which version of netlens is this", "system"), ("when was the last scan", "system"),
    ("are there updates available", "updates"), ("which remote sites are online", "remote_sites"), ("which devices have ipv6", "ipv6"),
    ("which dhcp servers are there", "network_services"),
])
def test_the_words_pick_the_right_question(conn, question, tool):
    assert tool_for(conn, question)[0] == tool


def test_the_answers_come_from_the_data(conn):
    a = lambda q: ask.answer(conn, q, NOW, mode="rules")["answer"]   # noqa: E731
    assert "7 devices" in a("How many devices do I have per type?") and "nas: 1" in a("How many devices do I have per type?")
    win = a("Which devices run Windows?")
    assert win.startswith("1 device") and "desktop-1" in win
    assert "iphone-bert" in a("Which Apple devices are offline?") and "macbook" not in a("Which Apple devices are offline?")
    assert "nas" in a("Which devices have SSH open?") and "macbook" in a("Which devices have SSH open?")
    assert "desktop-1" in a("who has port 3389 open")
    assert "22/tcp (ssh)" in a("which ports does the nas have open?")
    g = a("Which virtual machines are stopped?")
    assert "vm-old" in g and "BlueIris" not in g and "3 guests" in g
    assert "whoiswho" in a("which containers are unhealthy")
    assert "No backup plugin" in a("Are my backups healthy?")
    assert "Website: 12 days left" in a("when do my certificates expire")
    s = a("how fast is my internet?")
    assert "400.0 Mbit/s down" in s and "320.0" in s
    sec = a("is there anything suspicious?")
    assert "1× login failed" in sec and "192.168.1.99" in sec and "1 device(s) are not marked as trusted" in sec
    sm = a("which smart home batteries are low?")
    assert "Hall sensor (8%)" in sm and "Lamp" in sm
    assert "iphone-bert: -78 dBm" in a("which devices have a weak wifi signal")
    assert "bert: Changed the weekly report settings" in a("who changed settings this week") or "Changed the weekly report settings" in a("who changed settings this week")
    assert "quick done" in a("when was the last scan")
    assert "192.168.1.99" in a("which dhcp servers are there") and "NOT marked trusted" in a("which dhcp servers are there")


def test_what_a_device_is_connected_to(conn, monkeypatch):
    devices, _ = hierarchy.load_hierarchy(conn)
    tree = {1: hierarchy.Parent(7, "manual", "t"), 3: hierarchy.Parent(7, "manual", "t"), 2: hierarchy.Parent(1, "manual", "t")}
    monkeypatch.setattr(hierarchy, "load_hierarchy", lambda c: (devices, tree))
    assert "plugged into sw-garden" in ask.answer(conn, "what is the nas connected to?", NOW, mode="rules")["answer"]
    sw = ask.answer(conn, "what depends on sw-garden", NOW, mode="rules")["answer"]
    assert "2 device(s) are connected directly" in sw and "3 depend on it in total" in sw and "hp-laserjet" in sw


def test_a_question_without_a_match_lists_what_it_can_do(conn):
    a = ask.answer(conn, "Tell me a joke about penguins", NOW, mode="rules")
    assert a["understood"] is False and "who changed what" in a["answer"]


def test_the_switch_between_the_model_and_the_built_in_logic(conn, monkeypatch):
    from app import insights

    asked = []
    monkeypatch.setattr(insights, "llm_ready", lambda c: True)
    monkeypatch.setattr(ask.engineer, "chat", lambda c, m, timeout=90.0: asked.append(1) or json.dumps({"answer": "From the model."}))
    assert ask.answer(conn, "How many devices do I have per type?", NOW, mode="rules")["source"] == "rules" and not asked      # the switch: built-in logic only
    asked.clear()
    monkeypatch.setattr(ask.engineer, "chat", lambda c, m, timeout=90.0: asked.append(1) or json.dumps({"tool": "counts", "args": {"by": "type"}}) if len(asked) == 0 else json.dumps({"answer": "From the model."}))
    assert ask.answer(conn, "How many devices do I have per type?", NOW, mode="model")["source"] == "model"
    monkeypatch.setattr(insights, "llm_ready", lambda c: False)
    off = ask.answer(conn, "How many devices?", NOW, mode="model")
    assert off["source"] == "rules" and "No language model" in off["answer"]
    assert ask.answer(conn, "How many devices do I have per type?", NOW, mode="auto")["source"] == "rules"


def test_loosely_worded_questions_still_find_the_device_or_the_kind(conn):
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, vendor, device_type, online, trusted, first_seen, last_seen) VALUES (8, 'aa:bb:cc:dd:ee:08', '192.168.1.21', 'truenas.home.example.com', 'iXsystems', 'nas', 1, 1, 'x', 'x')")
    conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (8, 'tcp', 2049, 'open', 'nfs', 'x')")
    conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, updated) VALUES ('docker', 'x1', 'old-job', 'container', 'h', 'exited', 'x')")
    conn.commit()
    a = lambda q: ask.answer(conn, q, NOW, mode="rules")   # noqa: E731
    assert "2049/tcp (nfs)" in a("Which ports does the storage box truenas have open?")["answer"]
    assert "2049/tcp (nfs)" in a("what ports does the truenas have open")["answer"]
    cams = a("Which cameras are online?")
    assert cams["tools"] == ["search_devices"] and "voordeur" in cams["answer"] and "hp-laserjet" not in cams["answer"]
    assert a("How many iphones are there?")["answer"].startswith("1 device")
    stopped = a("Which virtual machines or containers are stopped?")["answer"]
    assert "vm-old" in stopped and "old-job" in stopped
    assert a("Which devices are not trusted?")["answer"].splitlines()[1].startswith("desktop-1")
    assert a("Which smart home batteries are low?")["answer"].startswith("Low batteries: Hall sensor (8%)")


def test_a_word_that_is_not_a_kind_is_looked_for_in_the_names(conn):
    from app import ask_more

    found = ask_more.t_search_devices(conn, {"type": "iphone"}, NOW)
    assert found["count"] == 1 and found["devices"][0]["name"] == "iphone-bert"
    assert ask_more.t_search_devices(conn, {"type": "printers"}, NOW)["count"] == 1               # a plural kind still works


def test_the_version_answer_does_not_claim_an_update_status_it_does_not_have(conn):
    from app import updates
    from app.db import set_setting

    sentence = lambda: ask.answer(conn, "Which version of Netlens is this and is there an update?", NOW, mode="rules")["answer"]   # noqa: E731
    set_setting(conn, updates.SETTINGS_KEY, json.dumps({"enabled": False}))
    set_setting(conn, updates.CACHE_KEY, json.dumps({"latest": "0.4.2", "checked": "2026-10-15T08:16:59Z", "current": "0.4.2"}))
    off = sentence()
    assert "switched off" in off and "0.4.2" in off and "newest published" not in off
    set_setting(conn, updates.SETTINGS_KEY, json.dumps({"enabled": True}))
    assert "not been able to check" in sentence()                                       # on, but the last answer is old
    set_setting(conn, updates.CACHE_KEY, json.dumps({"latest": "9.9.9", "checked": "2026-11-01T08:00:00Z", "current": "0.4.2"}))
    assert "A newer version, 9.9.9, is available" in sentence()
    set_setting(conn, updates.CACHE_KEY, json.dumps({"latest": "0.0.1", "checked": "2026-11-01T08:00:00Z", "current": "0.0.1"}))
    assert "newest published version" in sentence()


def test_scope_leaves_out_phones_by_default(conn):
    conn.execute("UPDATE devices SET online = 0 WHERE id = 5")      # the macbook (a pc) and the iphone (id 4) are offline
    both = ask.answer(conn, "what is offline?", NOW, mode="rules", scope="all")["answer"]
    core = ask.answer(conn, "what is offline?", NOW, mode="rules", scope="important")["answer"]
    assert "iphone-bert" in both and "macbook" in both
    assert "iphone-bert" not in core and "macbook" not in core and "hp-laserjet" in core
    by_name = ask.answer(conn, "is iphone-bert online?", NOW, mode="rules", scope="important")["answer"]
    assert "iphone-bert" in by_name                                  # asking for a device by name always works


def test_scope_without_marked_devices_counts_everything(conn):
    conn.execute("UPDATE devices SET device_type = 'phone', always_on = 0")
    assert "iphone-bert" in ask.answer(conn, "what is offline?", NOW, mode="rules", scope="important")["answer"]
