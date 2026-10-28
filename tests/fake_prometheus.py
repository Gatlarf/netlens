"""A simulated Prometheus-compatible store (an in-process transport for the plugin). It replays answers recorded from a real Prometheus 3.15.1 scraping a real
node_exporter (tests/fixtures/prometheus/node_exporter.json, host and address anonymised); `windows=True` adds a Windows host whose answers are SYNTHETIC
(written from the windows_exporter documentation: no Windows host was available)."""

import json
import urllib.parse
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "prometheus" / "node_exporter.json"
TS = 1793220000


def series_of(body):
    """Canonical [{labels, values}] from a recorded instant or range answer."""
    out = []
    for item in body["data"]["result"]:
        values = item.get("values") or ([item["value"]] if item.get("value") else [])
        out.append({"labels": item["metric"], "values": [(float(t), v) for t, v in values]})
    return out


class FakeProm:
    def __init__(self, token=None, basic=None, windows=False, status=200, html=False, error=None, nan=False):
        self.token, self.basic, self.status, self.html, self.error, self.nan = token, basic, status, html, error, nan
        self.requests = []                      # (method, path, query text)
        self.headers_seen = []
        self.answers = {}                       # query text -> [series]
        for rec in json.loads(FIXTURE.read_text())["requests"]:
            if rec["path"].endswith("/query") or rec["path"].endswith("/query_range"):
                self.answers[rec["query"]] = series_of(rec["body"])
        if windows:
            self._windows()

    def _windows(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("prom_plugin_for_fake", Path(__file__).resolve().parents[1] / "plugins" / "prometheus" / "plugin.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        inst = "10.0.0.20:9182"

        def s(labels, *vals):
            return {"labels": {"instance": inst, "job": "windows", **labels}, "values": [(TS + i * 60, str(v)) for i, v in enumerate(vals)]}

        data = {"cpu_pct": [s({}, 30, 31)], "mem_pct": [s({}, 55, 56)], "disk_pct": [s({"volume": "C:"}, 70, 70), s({"volume": "D:"}, 20, 20)],
                "disk_free_b": [s({"volume": "C:"}, 30e9, 30e9)], "net_rx_bps": [s({"nic": "Ethernet0"}, 1000, 2000)], "net_tx_bps": [s({"nic": "Ethernet0"}, 500, 600)],
                "uptime_s": [s({}, 86400, 86460)]}
        for metric, label_key, template in plugin.QUERIES:
            if "windows_" in template and metric in data:
                self.answers[plugin.build_query(template, "")] = [{"labels": x["labels"], "values": [(t, float(v)) for t, v in x["values"]]} for x in data[metric]]
        self.answers[plugin.build_query("windows_cs_hostname{@K@}", "")] = [{"labels": {"instance": inst, "hostname": "WIN-APP01"}, "values": [(TS, 1.0)]}]

    def factory(self, verify_tls, timeout, label, fingerprint=""):
        def send(method, url, headers, data):
            self.headers_seen.append(dict(headers))
            parts = urllib.parse.urlsplit(url)
            q = urllib.parse.parse_qs(parts.query)
            query = (q.get("query") or [""])[0]
            self.requests.append((method, parts.path, query))
            auth = headers.get("Authorization", "")
            if self.token and auth != f"Bearer {self.token}":
                return 401, b'{"status":"error","error":"unauthorized"}'
            if self.basic and auth != "Basic " + __import__("base64").b64encode(self.basic.encode()).decode():
                return 401, b'{"status":"error","error":"unauthorized"}'
            if self.html:
                return 200, b"<html>login</html>"
            if self.error:
                return self.status, json.dumps({"status": "error", "errorType": "bad_data", "error": self.error}).encode()
            if parts.path.endswith("/status/buildinfo"):
                return 200, b'{"status":"success","data":{"version":"3.15.1"}}'
            ranged = parts.path.endswith("/query_range")
            if query == "vector(1)":
                return 200, b'{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1793220000,"1"]}]}}'
            result = []
            for x in self.answers.get(query, []):
                if self.nan:
                    vals = [[t, "NaN"] for t, _v in x["values"]]
                else:
                    vals = [[t, str(v)] for t, v in x["values"]]
                result.append({"metric": x["labels"], **({"values": vals} if ranged else {"value": vals[-1]})})
            return 200, json.dumps({"status": "success", "data": {"resultType": "matrix" if ranged else "vector", "result": result}}).encode()

        return send
