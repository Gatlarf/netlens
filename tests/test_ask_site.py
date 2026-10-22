"""Insights: why is a website offline? The reverse proxy may have it switched off."""

import json

import pytest

from app import ask
from app.db import init_db
import sqlite3

NOW = "2026-03-10T10:00:00Z"


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, custom_name, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'proxy', 1, ?, ?)", (NOW, NOW))
    c.execute("INSERT INTO service_checks (name, kind, host, port, path, expect, interval_s, timeout_s, enabled, created, last_up, last_detail) "
              "VALUES ('Site biekes.be', 'https', 'biekes.be', 443, '/', '', 300, 10, 1, ?, 0, 'SSL error: TLSV1_UNRECOGNIZED_NAME')", (NOW,))
    c.execute("INSERT INTO proxy_sites (plugin_id, site_id, proxy_id, proxy_name, proxy_device_id, type, domains, enabled, scheme, forward_host, forward_port, updated) "
              "VALUES ('npm', '7', 'p', 'NPM', 1, 'proxy', ?, 0, 'http', '10.0.0.9', 80, ?)", (json.dumps(["biekes.be", "www.biekes.be"]), NOW))
    c.commit()
    return c


def test_the_site_tool_says_the_site_is_disabled_on_the_proxy(conn):
    got = ask.TOOLS["site"][0](conn, {"name": "biekes. be"})            # a space after the dot, as typed
    assert got["proxy_sites"][0]["enabled_on_the_proxy"] is False and "DISABLED on the reverse proxy NPM" in got["reasons_found"][0]
    assert got["services"][0]["state"] == "down"
    assert "DISABLED on the reverse proxy NPM" in ask.render("site", got)


def test_a_question_about_the_domain_without_a_model_finds_it(conn):
    got = ask.answer(conn, "Why is biekes.be offline?", mode="rules")
    assert got["tools"] == ["site"] and "DISABLED" in got["answer"]


def test_the_device_tool_falls_back_to_the_site(conn):
    got = ask.TOOLS["device"][0](conn, {"name": "biekes.be"})
    assert "proxy_sites" in got and "DISABLED" in ask.render("device", got)


def test_an_unknown_domain_is_not_invented(conn):
    assert "error" in ask.TOOLS["site"][0](conn, {"name": "nothing.example"})
