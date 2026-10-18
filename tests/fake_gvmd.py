"""A gvmd (Greenbone) that speaks GMP over TLS and replays answers recorded from a real Greenbone Community 22.7 on 2026-10-18 (tests/fixtures/gvmd_*.xml)."""

import re
import ssl
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer

from tests.fake_pbs import make_certificate

FIX = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIX / f"gvmd_{name}.xml").read_text()


def results_from_fixture(scan_time: datetime) -> list[ET.Element]:
    """The five recorded results, with their times moved to `scan_time` (the recording is of one day, the tests must not age)."""
    stamp = scan_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    text = re.sub(r"<creation_time>[^<]*</creation_time>", f"<creation_time>{stamp}</creation_time>", fixture("get_results"))
    return list(ET.fromstring(text).findall("result"))


class FakeGvmd:
    def __init__(self, folder: Path, user="netlens", password="secret", results=None, last_report=True, version_text=None, tasks=True):
        self.user, self.password, self.seen = user, password, []
        self.results = results if results is not None else results_from_fixture(datetime.now(timezone.utc) - timedelta(hours=2))
        self.last_report = last_report
        self.tasks = tasks
        self.version_text = version_text
        outer = self
        cert, key, self.fingerprint = make_certificate(folder)

        class Handler(BaseRequestHandler):
            def handle(self):
                parser, depth, authed = ET.XMLPullParser(events=("start", "end")), 0, False
                while True:
                    data = self.request.recv(65536)
                    if not data:
                        return
                    parser.feed(data)
                    for event, el in parser.read_events():
                        depth += 1 if event == "start" else -1
                        if event == "end" and depth == 0:
                            answer, authed = outer.answer(el, authed)
                            self.request.sendall(answer.encode())
                            parser, depth = ET.XMLPullParser(events=("start", "end")), 0          # the next command is a new document
                            break

        class Server(ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.address = f"127.0.0.1:{self.server.server_address[1]}"

    def answer(self, el: ET.Element, authed: bool) -> tuple[str, bool]:
        self.seen.append((el.tag, dict(el.attrib)))
        if el.tag == "get_version":
            return self.version_text or fixture("get_version"), authed
        if el.tag == "authenticate":
            ok = el.findtext("credentials/username") == self.user and el.findtext("credentials/password") == self.password
            return ('<authenticate_response status="200" status_text="OK"/>' if ok else '<authenticate_response status="400" status_text="Authentication failed"/>'), ok
        if not authed:
            return f'<{el.tag}_response status="401" status_text="Authentication required"/>', authed
        if el.tag == "get_tasks":
            if not self.tasks:
                return '<get_tasks_response status="200" status_text="OK"><apply_overrides>0</apply_overrides></get_tasks_response>', authed
            text = fixture("get_tasks")
            if self.last_report:
                when = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                text = text.replace("</task>", f'<last_report><report id="r1"><timestamp>{when}</timestamp></report></last_report></task>', 1)
            return text, authed
        if el.tag == "get_results":
            flt = el.get("filter", "")
            self.seen[-1][1]["filter"] = flt
            first = int((re.search(r"first=(\d+)", flt) or [0, 1])[1])
            rows = int((re.search(r"rows=(-?\d+)", flt) or [0, 500])[1])
            page = self.results[first - 1:first - 1 + (rows if rows > 0 else len(self.results))]
            return '<get_results_response status="200" status_text="OK">' + "".join(ET.tostring(r, encoding="unicode") for r in page) + f"<result_count>{len(self.results)}</result_count></get_results_response>", authed
        return f'<{el.tag}_response status="400" status_text="Unknown command"/>', authed

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
