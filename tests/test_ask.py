import json
from datetime import datetime, timezone

import pytest

from app import ask, licence
from app.db import add_event, connect, init_db

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    c = connect(tmp_path / "ask.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    for i, (name, ip, online) in enumerate([("nas", "192.168.1.20", 1), ("printer", "192.168.1.30", 0), ("cam1", "192.168.1.31", 1)], 1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, '2026-10-31T00:00:00Z', '2026-11-01T11:00:00Z')", (i, f"aa:bb:cc:dd:ee:0{i}", ip, name, online))
    c.commit()
    add_event(c, "device_offline", "printer is offline", device_id=2, now="2026-11-01T10:00:00Z")
    yield c
    c.close()


def test_without_a_model_questions_are_matched_by_their_words(conn):
    a = ask.answer(conn, "What is wrong right now?", NOW)
    assert a["source"] == "rules" and a["tools"] == ["overview"] and "2 of 3 devices are online" in a["answer"] and "printer" in a["answer"]
    assert ask.answer(conn, "which new devices appeared this week", NOW)["tools"] == ["new_devices"]
    assert ask.answer(conn, "any disks filling up?", NOW)["tools"] == ["disks"]
    assert ask.answer(conn, "", NOW)["tools"] == []


def test_a_question_it_does_not_understand_is_not_answered_with_something_else(conn):
    a = ask.answer(conn, "Which colour is the sky above the garden?", NOW)
    assert a["understood"] is False and a["tools"] == [] and "language model" in a["answer"] and "online" not in a["answer"]


def test_response_times_come_from_the_checks(conn):
    for i, (dev, ms) in enumerate([(1, 2.0), (1, 4.0), (1, 3.0), (3, 40.0), (3, 60.0), (3, 50.0), (2, 1.0)]):
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, 1, ?)", (dev, f"2026-10-31T10:0{i}:00Z", ms))
    conn.commit()
    a = ask.answer(conn, "Which device has the highest average response time?", NOW)
    assert a["tools"] == ["response_times"] and a["answer"].splitlines()[1].startswith("cam1: 50.0 ms") and "printer" not in a["answer"]       # three measurements are needed
    b = ask.answer(conn, "which device is the fastest to respond?", NOW)
    assert b["answer"].splitlines()[1].startswith("nas: 3.0 ms")


def test_a_device_name_wins_over_keywords(conn):
    a = ask.answer(conn, "is the printer down?", NOW)
    assert a["tools"] == ["device"] and a["answer"].startswith("printer is offline")


def test_the_model_chooses_tools_sees_placeholders_and_the_answer_gets_the_real_names_back(conn):
    sent = []

    def model(messages):
        sent.append(messages[-1]["content"])
        if len(sent) == 1:
            assert "printer" not in messages[1]["content"]                       # the question reached the model without the name
            return json.dumps({"tool": "device", "args": {"name": "<device1>"}})
        return json.dumps({"answer": "<device1> is offline since 10:00."})

    a = ask.answer(conn, "what is up with the printer?", NOW, ask=model)
    assert a["source"] == "model" and a["tools"] == ["device"] and a["answer"] == "printer is offline since 10:00."
    assert "192.168.1.30" not in sent[1] and "printer" not in sent[1]            # the tool result was anonymised as well


def test_a_confused_or_failing_model_falls_back_to_the_plain_answer(conn):
    assert ask.answer(conn, "what is wrong?", NOW, ask=lambda m: "I think so")["source"] == "rules"

    def broken(m):
        raise RuntimeError("down")

    assert ask.answer(conn, "what is wrong?", NOW, ask=broken)["source"] == "rules"
    assert ask.answer(conn, "what is wrong?", NOW, ask=lambda m: json.dumps({"tool": "rm -rf", "args": {}}))["source"] == "rules"


def test_the_model_cannot_loop_forever(conn):
    calls = []

    def endless(m):
        calls.append(1)
        return json.dumps({"tool": "overview", "args": {}})

    assert ask.answer(conn, "what is wrong?", NOW, ask=endless)["source"] == "rules"
    assert len(calls) <= ask.MAX_STEPS + 1
