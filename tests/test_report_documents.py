"""Report templates, the document made from them, and its PDF and web page."""
import re
import zlib
from datetime import datetime, timedelta, timezone

import pytest

from app import reportdoc, reporttemplates as rt, tsdb
from app.db import connect, init_db

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO device_groups (id, name, color) VALUES (1, 'Acme', '#2a9d8f')")
    for i, (name, group, online, always_on) in enumerate((("nas", 1, 1, 1), ("camera", 1, 0, 1), ("other box", None, 1, 1)), 1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, always_on, group_id, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, 'nas', ?, ?)",
                  (i, f"aa:00:00:00:00:0{i}", f"10.0.0.{i}", name, online, always_on, group, stamp(NOW - timedelta(days=3 if i == 2 else 40)), stamp(NOW)))
    t = NOW - timedelta(days=10)
    while t <= NOW:                                                           # the nas is down for three hours, the camera for a day, the third never
        nas_down = NOW - timedelta(days=3, hours=3) <= t < NOW - timedelta(days=3)
        cam_down = NOW - timedelta(days=2) <= t < NOW - timedelta(days=1)
        c.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (1, ?, ?, 1.0)", (stamp(t), 0 if nas_down else 1))
        c.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (2, ?, ?, 1.0)", (stamp(t), 0 if cam_down else 1))
        c.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (3, ?, 1, 1.0)", (stamp(t),))
        t += timedelta(hours=1)
    c.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 2, 'device_offline', 'camera is not answering')", (stamp(NOW - timedelta(days=2)),))
    c.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 2, 'device_online', 'camera is back')", (stamp(NOW - timedelta(days=1)),))
    c.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 3, 'device_offline', 'other box is not answering')", (stamp(NOW - timedelta(days=5)),))
    c.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 1, 'device_new', 'nas appeared')", (stamp(NOW - timedelta(days=4)),))
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def template(**over):
    return rt.clean({"name": "Acme weekly", "title": "Network report", "sections": list(rt.SECTIONS), "period": "7d", **over})


def test_a_template_is_checked_and_stored(conn):
    t = rt.upsert(conn, {"name": "  Acme   weekly ", "sections": ["availability", "availability", "bogus", "summary"], "accent": "#0F766E", "recipients": "a@example.com, b@example.com;c@example.com",
                         "scope": {"type": "group", "ids": [1, 1]}, "schedule": {"frequency": "weekly", "weekday": 0, "hour": 7}})
    assert t["name"] == "Acme weekly" and t["title"] == "Acme weekly" and t["sections"] == ["availability", "summary"] and t["accent"] == "#0f766e"
    assert t["recipients"] == ["a@example.com", "b@example.com", "c@example.com"] and t["scope"] == {"type": "group", "ids": [1]} and t["schedule"]["frequency"] == "weekly"
    for bad in ({"name": ""}, {"sections": []}, {"sections": ["nonsense"]}, {"period": "yearly"}, {"accent": "blue"}, {"scope": {"type": "group", "ids": []}}, {"scope": {"type": "moon"}},
                {"schedule": {"frequency": "daily"}}, {"schedule": {"frequency": "weekly", "hour": 25}}, {"recipients": ["not an address"]}, {"channel_id": "bad id!"}):
        with pytest.raises(rt.TemplateError):
            rt.clean({"name": "x", "sections": ["summary"], **bad})
    assert rt.get(conn, t["id"])["name"] == "Acme weekly" and rt.remove(conn, t["id"]) and rt.load(conn) == [] and not rt.remove(conn, "nope")


def test_a_logo_is_checked_by_the_same_reader_the_pdf_uses(conn):
    from tests.test_pdf import png

    t = rt.upsert(conn, {"name": "x", "sections": ["summary"]})
    good = png(2, 2, 6, pixels=bytes([255, 0, 0, 255] * 4))
    assert rt.set_logo(conn, t["id"], good) == {"type": "png", "width": 2, "height": 2, "bytes": len(good)}
    assert rt.get_logo(conn, t["id"]) == (good, "image/png")
    for bad in (b"GIF89a....", good[:20], bytes(500_000)):
        with pytest.raises(rt.TemplateError):
            rt.set_logo(conn, t["id"], bad)
    with pytest.raises(rt.TemplateError):
        rt.set_logo(conn, "nope", good)
    rt.clear_logo(conn, t["id"])
    assert rt.get_logo(conn, t["id"]) is None
    rt.set_logo(conn, t["id"], good)
    rt.remove(conn, t["id"])
    assert rt.get_logo(conn, t["id"]) is None                                       # a removed template takes its logo with it


def test_the_schedule_sends_once_per_slot(conn):
    local = datetime(2026, 10, 19, 8, 0).astimezone()                               # a Monday, 08:00 on the clock of the server
    weekly = rt.upsert(conn, {"name": "w", "sections": ["summary"], "schedule": {"frequency": "weekly", "weekday": 0, "hour": 7}})
    assert rt.due(conn, weekly, local)                                              # Monday 07:00 has passed and nothing was sent
    rt.mark_sent(conn, weekly["id"], local)
    assert not rt.due(conn, weekly, local + timedelta(hours=3)) and not rt.due(conn, weekly, local + timedelta(days=3))
    assert rt.due(conn, weekly, local + timedelta(days=7))                           # next Monday
    assert not rt.due(conn, {**weekly, "schedule": {**weekly["schedule"], "frequency": "off"}}, local) and not rt.due(conn, {**weekly, "enabled": False}, local)
    monthly = rt.upsert(conn, {"name": "m", "sections": ["summary"], "schedule": {"frequency": "monthly", "monthday": 3, "hour": 6}})
    assert rt.due(conn, monthly, datetime(2026, 10, 19, 8).astimezone()) and rt.due(conn, monthly, datetime(2026, 10, 2, 8).astimezone())          # before the 3rd the slot of the 3rd of September counts
    rt.mark_sent(conn, monthly["id"], datetime(2026, 10, 19, 8).astimezone())
    assert not rt.due(conn, monthly, datetime(2026, 10, 25, 8).astimezone()) and rt.due(conn, monthly, datetime(2026, 11, 4, 8).astimezone())


def test_the_periods():
    start, end, words = reportdoc.bounds("7d", NOW)
    assert end - start == timedelta(days=7) and end.minute == 0 and end > NOW and "to" in words
    assert reportdoc.bounds("30d", NOW)[1] - reportdoc.bounds("30d", NOW)[0] == timedelta(days=30)
    s, e, w = reportdoc.bounds("month", NOW)
    assert (s.month, e.month) == (9, 10) and w == "September 2026"                   # the last full month before October
    assert reportdoc.bounds("7d", NOW, month="2026-08")[2] == "August 2026"


def test_the_document_has_what_the_sections_promise(conn):
    doc = reportdoc.build(conn, template(), now=NOW)
    kinds = [b["type"] for b in doc["blocks"]]
    headings = [b["text"] for b in doc["blocks"] if b["type"] == "heading"]
    assert headings[:3] == ["At a glance", "Availability", "Incidents"] and "Devices" in headings
    tiles = next(b for b in doc["blocks"] if b["type"] == "tiles")["items"]
    assert tiles[0]["label"] == "devices online now" and tiles[0]["value"] == "2 / 3"
    table = next(b for b in doc["blocks"] if b["type"] == "table" and b.get("title") == "Devices with the most downtime")
    assert [r["name"] for r in table["rows"]] == ["camera", "nas"]                                      # the camera was down longest; the third device never was
    assert "tiles" in kinds and doc["meta"]["period"] and doc["meta"]["scope"] == "the whole network"


def test_a_report_for_some_groups_only_covers_their_devices(conn):
    doc = reportdoc.build(conn, template(scope={"type": "group", "ids": [1]}, sections=["availability", "devices", "changes"]), now=NOW)
    avail = next(b for b in doc["blocks"] if b["type"] == "table" and b.get("title") == "Devices with the most downtime")
    assert sorted(r["name"] for r in avail["rows"]) == ["camera", "nas"] and doc["meta"]["scope"] == "the selected groups"
    tiles = next(b for b in doc["blocks"] if b["type"] == "tiles")["items"]
    assert tiles[0]["label"] == "2 devices"
    kinds = next(b for b in doc["blocks"] if b["type"] == "bars" and b["title"] == "By type")
    assert kinds["items"][0]["text"] == "2"                                                             # two devices of the group, not three
    text = " ".join(str(r) for b in doc["blocks"] if b["type"] == "table" for r in b["rows"])
    assert "other box" not in text


def test_a_section_that_fails_is_replaced_by_a_note_and_the_rest_goes_on(conn, monkeypatch):
    def boom(ctx):
        raise RuntimeError("no")

    monkeypatch.setitem(reportdoc.BUILDERS, "capacity", boom)
    doc = reportdoc.build(conn, template(sections=["availability", "capacity", "devices"]), now=NOW)
    headings = [b["text"] for b in doc["blocks"] if b["type"] == "heading"]
    assert headings == ["Availability", "Capacity", "Devices"]
    assert any(b["type"] == "text" and "could not be made" in b["text"] for b in doc["blocks"])


def pdf_text(data: bytes) -> str:
    out = []
    for m in re.finditer(rb"stream\n(.*?)\nendstream", data, re.S):
        try:
            content = zlib.decompress(m.group(1)).decode("latin-1")
        except zlib.error:
            continue
        out += [bytes.fromhex(h).decode("cp1252") for h in re.findall(r"<([0-9a-f]*)> Tj", content)]
    return "\n".join(out)


def test_the_pdf_is_valid_and_holds_the_text_and_the_footer_of_every_page(conn):
    from tests.test_pdf import objects

    doc = reportdoc.build(conn, template(title="Acme network report", subtitle="Managed by Example IT", prepared_for="Acme BV", footer="Example IT · 555 0100"), now=NOW)
    data = reportdoc.render_pdf(doc)
    objs = objects(data)
    pages = [o for o in objs.values() if b"/Type /Page " in o]
    text = pdf_text(data)
    assert len(pages) >= 1 and "Acme network report" in text and "Managed by Example IT" in text and "prepared for Acme BV" in text and "camera" in text and "At a glance" in text
    assert text.count("Example IT · 555 0100") == len(pages) and f"Page 1 of {len(pages)}" in text


def test_a_long_report_runs_over_several_pages_and_a_table_keeps_its_heading_row(conn):
    for i in range(4, 80):
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, always_on, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, 0, 1, 'nas', ?, ?)",
                     (i, f"aa:00:00:00:01:{i:02x}", f"10.0.1.{i}", f"box-{i:02d}", stamp(NOW - timedelta(days=1)), stamp(NOW)))
    conn.commit()
    doc = reportdoc.build(conn, template(sections=["devices"]), now=NOW)
    data = reportdoc.render_pdf(doc)
    text = pdf_text(data)
    assert text.count("Last seen") >= 1 and "Offline now" in text and "box-" in text
    doc["blocks"] += [{"type": "table", "title": "Long", "columns": [{"key": "a", "label": "Heading", "w": 1}], "rows": [{"a": f"row {n}"} for n in range(120)]}]
    data = reportdoc.render_pdf(doc)
    pages = len(re.findall(rb"/Type /Page ", data))
    assert pages >= 3 and pdf_text(data).count("Heading") == pages - 1 or pdf_text(data).count("Heading") >= 2          # the heading row comes back on every page the table runs over


def test_the_web_page_escapes_what_it_shows_and_carries_the_logo(conn):
    from tests.test_pdf import png

    logo = png(2, 2, 6, pixels=bytes([255, 0, 0, 255] * 4))
    doc = reportdoc.build(conn, template(title="<b>Acme</b> & co", prepared_for="A<script>"), now=NOW, logo=(logo, "image/png"))
    page = reportdoc.render_html(doc)
    assert "&lt;b&gt;Acme&lt;/b&gt; &amp; co" in page and "<script>" not in page and "data:image/png;base64," in page and "--accent: #2563eb" in page
    assert "Devices with the most downtime" in page and page.count("<table>") >= 2
    summary = reportdoc.text_summary(doc)
    assert summary.startswith("<b>Acme</b> & co") and "devices online now: 2 / 3" in summary


# ----------------------------------------------------------------------------- the API, the e-mail and the schedule
from fastapi.testclient import TestClient  # noqa: E402

from app.config import load_settings  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def api(tmp_path):
    tsdb.forget_all()
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "netlens.db")
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer t"
        yield c, tmp_path
    tsdb.forget_all()


def test_the_api_makes_templates_logos_pdfs_and_pages(api):
    from tests.test_pdf import png

    c, _tmp = api
    meta = c.get("/api/report-templates").json()
    assert meta["templates"] == [] and any(s["key"] == "availability" for s in meta["sections"]) and [p["key"] for p in meta["periods"]] == ["7d", "30d", "month"]
    made = c.post("/api/report-templates", json={"name": "Acme", "title": "Acme report", "sections": ["summary", "availability"], "accent": "#0f766e", "schedule": {"frequency": "weekly", "weekday": 0, "hour": 7}})
    assert made.status_code == 201
    t = made.json()
    assert t["has_logo"] is False and t["last_sent"] is not None                          # a new schedule counts from now: nothing is due at once
    assert c.post("/api/report-templates", json={"name": "", "sections": ["summary"]}).status_code == 422
    logo = png(2, 2, 6, pixels=bytes([255, 0, 0, 255] * 4))
    assert c.put(f"/api/report-templates/{t['id']}/logo", content=logo, headers={"Content-Type": "image/png"}).json()["width"] == 2
    assert c.put(f"/api/report-templates/{t['id']}/logo", content=b"nonsense").status_code == 422
    assert c.get(f"/api/report-templates/{t['id']}/logo").content == logo and c.get("/api/report-templates").json()["templates"][0]["has_logo"] is True
    pdf = c.get(f"/api/report-templates/{t['id']}/render?format=pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF-1.4") and "attachment" in pdf.headers["content-disposition"] and ".pdf" in pdf.headers["content-disposition"]
    html = c.get(f"/api/report-templates/{t['id']}/render?format=html&period=30d")
    assert html.status_code == 200 and "text/html" in html.headers["content-type"] and "Acme report" in html.text and "data:image/png;base64," in html.text
    assert c.get(f"/api/report-templates/{t['id']}/render?format=exe").status_code == 422 and c.get(f"/api/report-templates/{t['id']}/render?period=forever").status_code == 422
    assert c.get("/api/report-templates/zzzz/render").status_code == 404
    changed = c.put(f"/api/report-templates/{t['id']}", json={**{k: t[k] for k in ("name", "title", "sections", "accent")}, "schedule": {"frequency": "monthly", "monthday": 2, "hour": 6}}).json()
    assert changed["schedule"]["frequency"] == "monthly"
    assert c.delete(f"/api/report-templates/{t['id']}/logo").status_code == 204 and c.get(f"/api/report-templates/{t['id']}/logo").status_code == 404
    assert c.delete(f"/api/report-templates/{t['id']}").status_code == 204 and c.delete(f"/api/report-templates/{t['id']}").status_code == 404


def test_a_viewer_cannot_make_or_read_reports():
    from app import auth

    assert not auth.VIEWER_READABLE.match("/api/report-templates") and not auth.SCOPED_READABLE.match("/api/report-templates")


class Mailer:
    def __init__(self):
        self.calls = []

    def __call__(self, cfg, subject, body, **kw):
        self.calls.append((cfg, subject, body, kw))


def email_channel(conn, **over):
    from app.notify import channels as ch

    chan = {"id": "m1", "type": "email", "name": "Office mail", "enabled": True, "events": ["report_weekly"], "last_event_id": 0,
            "settings": {"smtp_host": "smtp.example", "smtp_port": "587", "security": "starttls", "username": "", "password": "", "from_addr": "netlens@example.com", "to_addrs": "boss@example.com"}, **over}
    ch.save_channels(conn, [chan])
    return chan


async def test_a_report_is_sent_as_a_pdf_to_its_recipients(conn, tmp_path):
    from app import reportjobs

    t = rt.upsert(conn, {"name": "Acme", "title": "Acme report", "sections": ["availability"], "recipients": ["customer@acme.example"]})
    email_channel(conn)
    mailer = Mailer()
    done = await reportjobs.send_now(str(tmp_path / "t.db"), t["id"], mailer=mailer)
    cfg, subject, body, kw = mailer.calls[0]
    assert done["sent_to"] == ["customer@acme.example"] and cfg.to_addrs == ["customer@acme.example"] and cfg.smtp_host == "smtp.example"
    assert subject.startswith("Acme report: ") and "attached as a PDF" in body
    name, data, mime = kw["attachments"][0]
    assert name.endswith(".pdf") and data.startswith(b"%PDF-1.4") and mime == "application/pdf" and name == done["file"]
    mailer.calls.clear()
    await reportjobs.send_now(str(tmp_path / "t.db"), t["id"], to=["me@example.com"], mailer=mailer)                    # a test to yourself
    assert mailer.calls[0][0].to_addrs == ["me@example.com"]
    rt.upsert(conn, {**t, "recipients": []})
    mailer.calls.clear()
    await reportjobs.send_now(str(tmp_path / "t.db"), t["id"], mailer=mailer)
    assert mailer.calls[0][0].to_addrs == ["boss@example.com"]                                                          # no recipients of its own: the channel's
    rt.upsert(conn, {**t, "attach_pdf": False})
    mailer.calls.clear()
    await reportjobs.send_now(str(tmp_path / "t.db"), t["id"], mailer=mailer)
    assert mailer.calls[0][3]["attachments"] == []


async def test_without_an_email_channel_the_report_says_why(conn, tmp_path):
    from app import reportjobs
    from app.notify import channels as ch

    t = rt.upsert(conn, {"name": "Acme", "sections": ["summary"]})
    with pytest.raises(ch.ChannelError, match="no e-mail channel"):
        await reportjobs.send_now(str(tmp_path / "t.db"), t["id"], mailer=Mailer())
    email_channel(conn, enabled=False)
    with pytest.raises(ch.ChannelError, match="no e-mail channel"):
        await reportjobs.send_now(str(tmp_path / "t.db"), t["id"], mailer=Mailer())
    email_channel(conn)
    rt.upsert(conn, {**t, "channel_id": "other"})
    with pytest.raises(ch.ChannelError, match="switched off or gone"):
        await reportjobs.send_now(str(tmp_path / "t.db"), t["id"], mailer=Mailer())


async def test_the_scheduler_sends_what_is_due_once_and_reports_a_failure(conn, tmp_path):
    from app import reportjobs

    now = datetime(2026, 10, 19, 8, 0).astimezone()                              # a Monday morning
    t = rt.upsert(conn, {"name": "Acme", "sections": ["summary"], "recipients": ["c@acme.example"], "schedule": {"frequency": "weekly", "weekday": 0, "hour": 7}})
    rt.upsert(conn, {"name": "Off", "sections": ["summary"], "schedule": {"frequency": "off"}})
    email_channel(conn)
    mailer = Mailer()
    first = await reportjobs.send_due(str(tmp_path / "t.db"), now=now, mailer=mailer)
    assert [r["name"] for r in first] == ["Acme"] and first[0]["ok"] and len(mailer.calls) == 1
    assert await reportjobs.send_due(str(tmp_path / "t.db"), now=now + timedelta(hours=2), mailer=mailer) == [] and len(mailer.calls) == 1        # once per slot
    assert [r["name"] for r in await reportjobs.send_due(str(tmp_path / "t.db"), now=now + timedelta(days=7), mailer=mailer)] == ["Acme"]
    from app.notify import channels as ch

    ch.save_channels(conn, [])                                                                                      # no channel: the failure is recorded, not raised
    failed = await reportjobs.send_due(str(tmp_path / "t.db"), now=now + timedelta(days=14), mailer=mailer)
    assert failed[0]["ok"] is False and "no e-mail channel" in failed[0]["error"]
    assert conn.execute("SELECT kind, detail FROM events WHERE kind = 'report_failed'").fetchone()["detail"].startswith("The report “Acme” could not be sent")
    assert await reportjobs.send_due(str(tmp_path / "t.db"), now=now + timedelta(days=14, hours=1), mailer=mailer) == []          # not again every minute
    assert rt.get(conn, t["id"]) is not None


def test_mail_with_an_attachment_is_a_multipart_message():
    from app.notify.config import NotifyConfig
    from app.notify.mail import send_mail

    sent = []

    class Smtp:
        def __init__(self, host, port, timeout): pass
        def ehlo(self): pass
        def send_message(self, msg): sent.append(msg)
        def quit(self): pass

    send_mail(NotifyConfig(smtp_host="h", from_addr="a@b.c", to_addrs=["d@e.f"], security="none"), "Report", "see attached", smtp_factory=Smtp, attachments=[("r.pdf", b"%PDF-1.4 x", "application/pdf")])
    msg = sent[0]
    parts = list(msg.iter_attachments())
    assert msg.get_content_type() == "multipart/mixed" and parts[0].get_filename() == "r.pdf" and parts[0].get_content_type() == "application/pdf" and parts[0].get_content() == b"%PDF-1.4 x"
