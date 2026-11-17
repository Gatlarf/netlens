"""The pure parts of the graph and table scripts, run with node (skipped when node is not installed)."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

JS = Path(__file__).resolve().parent.parent / "app" / "static" / "js"
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def run(module: str, code: str):
    """Import a script as an ES module and evaluate `code` (which may use `m`, the module); the result comes back as JSON."""
    script = f"import * as m from {json.dumps((JS / module).as_uri())};\nconst out = await (async () => {{ {code} }})();\nconsole.log(JSON.stringify(out));"
    result = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


NOW = 1_800_000_000


def test_windows_zoom_pan_and_stay_inside_what_can_be_asked_for():
    out = run("graphmath.js", f"""
      const now = {NOW};
      const win = {{ start: now - 7200, end: now - 3600 }};
      return {{
        zoomIn: m.zoomWindow(win, 0.5, now), zoomOut: m.zoomWindow(win, 2, now),
        tooSmall: m.zoomWindow(win, 0.01, now), panLater: m.panWindow(win, 1, now), panPastNow: m.panWindow(win, 5, now),
        huge: m.clampWindow({{ start: 0, end: now }}, now),
      }};""")
    mid = NOW - 5400
    assert out["zoomIn"] == {"start": mid - 900, "end": mid + 900}
    assert out["zoomOut"] == {"start": mid - 3600, "end": mid + 3600}
    assert out["tooSmall"]["end"] - out["tooSmall"]["start"] == 600                       # never below ten minutes
    assert out["panLater"] == {"start": NOW - 3600, "end": NOW}
    assert out["panPastNow"]["end"] == NOW and out["panPastNow"]["end"] - out["panPastNow"]["start"] == 3600      # the period keeps its length, the future is not shown
    assert out["huge"]["end"] == NOW and out["huge"]["end"] - out["huge"]["start"] == 366 * 86400


def test_a_drag_becomes_a_window_and_a_click_does_not():
    out = run("graphmath.js", f"""
      const plot = {{ left: 64, width: 568 }}, win = {{ start: {NOW - 86400}, end: {NOW} }};
      return {{ half: m.selectionToWindow(64, 348, plot, win, {NOW}), reversed: m.selectionToWindow(348, 64, plot, win, {NOW}),
                click: m.selectionToWindow(100, 103, plot, win, {NOW}), outside: m.selectionToWindow(0, 700, plot, win, {NOW}) }};""")
    assert out["half"] == {"start": NOW - 86400, "end": NOW - 43200}
    assert out["reversed"] == out["half"]                                                 # dragging right to left is the same period
    assert out["click"] is None
    assert out["outside"] == {"start": NOW - 86400, "end": NOW}                           # a drag past the edges is held to the plot


def test_nearest_point_respects_its_reach():
    out = run("graphmath.js", """
      const pts = [[100, 1, 1, 1], [200, 2, 2, 2], [400, 4, 4, 4]];
      return [m.nearestPoint(pts, 120)[0], m.nearestPoint(pts, 160)[0], m.nearestPoint(pts, 390)[0], m.nearestPoint(pts, 1000, 50), m.nearestPoint([], 5)];""")
    assert out == [100, 200, 400, None, None]


def test_axes_a_second_unit_gets_the_right_hand_scale_and_only_one():
    out = run("graphmath.js", """
      const o = (unit) => ({ unit });
      return { split: m.splitAxes('%', [o('%'), o('ms'), o('ms'), o('B')]),
               can: [m.canOverlay('%', [], 'ms'), m.canOverlay('%', [o('ms')], 'B'), m.canOverlay('%', [o('ms')], 'ms'), m.canOverlay('%', [o('ms')], '%'), m.canOverlay('%', [o('%'), o('%'), o('%')], '%')] };""")
    assert [len(out["split"]["left"]), len(out["split"]["right"]), out["split"]["rightUnit"]] == [1, 2, "ms"]
    assert out["can"] == [True, False, True, True, False]


def test_correlation_in_words_and_scales_and_csv():
    out = run("graphmath.js", """
      const [min, max, ticks] = m.niceScale(3, 47);
      return { words: [0.9, 0.5, -0.7, 0.05, null].map(m.describeCorrelation), scale: [min, max, ticks], flat: m.niceScale(5, 5),
               csv: m.toCsv([{ name: 'CPU, main', unit: '%', points: [[1700000000, 10, 8, 12], [1700000060, 20, 18, 22]] }, { name: 'Rtt', unit: 'ms', points: [[1700000000, 5, 5, 5]] }]) };""")
    assert out["words"][0].startswith("A very strong") and "rise" in out["words"][0] and "fall" in out["words"][2] and out["words"][3] == "No clear relationship."
    assert out["scale"][0] <= 3 and out["scale"][1] >= 47 and out["scale"][2][0] == out["scale"][0] and out["scale"][2][-1] == out["scale"][1]
    assert out["flat"][0] < 5 < out["flat"][1]
    lines = out["csv"].splitlines()
    assert lines[0] == 'time (UTC),"CPU, main average (%)","CPU, main lowest","CPU, main highest",Rtt (ms)'          # a name with a comma is quoted
    assert lines[1].endswith(",10,8,12,5") and lines[2].endswith(",20,18,22,")             # a second series with no reading at that time leaves the cell empty


def test_table_views_hold_to_what_the_table_offers_and_move_columns_safely():
    out = run("tableviewmath.js", """
      const known = ['status', 'name', 'ip', 'mac', 'vendor', 'type'], locked = ['status', 'name'];
      const v = m.normalise({ columns: ['mac', 'bogus', 'mac', 'ip'], widths: { mac: 200, ip: 10, bogus: 100, vendor: 100 }, sort: { key: 'ip', dir: 'desc' }, filters: { type: 'ap', q: '' } }, known, locked);
      const cols = ['status', 'name', 'ip', 'mac', 'vendor'];
      return { v,
        same: m.sameView({ columns: ['ip'] }, { columns: ['name', 'ip', 'status'] }, known, locked), differ: m.sameView({ columns: ['ip'] }, { columns: ['mac'] }, known, locked),
        left: m.moveColumn(cols, 'mac', -1, locked), blocked: m.moveColumn(cols, 'ip', -1, locked), lockedStays: m.moveColumn(cols, 'name', 1, locked), edge: m.moveColumn(cols, 'vendor', 1, locked),
        drop: m.dropColumn(cols, 'vendor', 'ip', locked), dropFront: m.dropColumn(cols, 'vendor', 'status', locked), dropEnd: m.dropColumn(cols, 'ip', null, locked),
        show: m.toggleColumn(cols, 'type', true, locked), hide: m.toggleColumn(cols, 'mac', false, locked), hideLocked: m.toggleColumn(cols, 'name', false, locked) };""")
    assert out["v"] == {"columns": ["status", "name", "mac", "ip"], "widths": {"mac": 200}, "sort": {"key": "ip", "dir": "desc"}, "filters": {"type": "ap"}}
    assert out["same"] is True and out["differ"] is False
    assert out["left"] == ["status", "name", "mac", "ip", "vendor"] and out["blocked"] == out["lockedStays"] == out["edge"] == ["status", "name", "ip", "mac", "vendor"]
    assert out["drop"] == ["status", "name", "vendor", "ip", "mac"] and out["dropFront"] == ["status", "name", "vendor", "ip", "mac"] and out["dropEnd"] == ["status", "name", "mac", "vendor", "ip"]
    assert out["show"][-1] == "type" and "mac" not in out["hide"] and "name" in out["hideLocked"]


def test_sorting_puts_missing_values_last_and_csv_quotes_what_it_must():
    out = run("tableviewmath.js", """
      const rows = [{ n: 'b', v: 10 }, { n: 'a', v: null }, { n: 'c', v: 2 }, { n: 'a10', v: 5 }, { n: 'a9', v: 7 }];
      const val = (r, k) => r[k];
      return { asc: m.sortRows(rows, { key: 'v', dir: 'asc' }, val).map((r) => r.n), desc: m.sortRows(rows, { key: 'v', dir: 'desc' }, val).map((r) => r.n),
               natural: m.sortRows(rows, { key: 'n', dir: 'asc' }, val).map((r) => r.n), none: m.sortRows(rows, null, val).map((r) => r.n),
               csv: m.tableCsv([{ n: 'x, y', v: 1 }, { n: 'say "hi"', v: null }], ['n', 'v'], (r, k) => r[k], (k) => k.toUpperCase()) };""")
    assert out["asc"] == ["c", "a10", "a9", "b", "a"] and out["desc"] == ["b", "a9", "a10", "c", "a"]      # no value: last either way
    assert out["natural"] == ["a", "a9", "a10", "b", "c"]                                                    # a9 before a10
    assert out["none"] == ["b", "a", "c", "a10", "a9"]
    assert out["csv"] == 'N,V\r\n"x, y",1\r\n"say ""hi""",\r\n'


def test_a_dashboard_is_exported_with_its_own_cards_and_imported_without_clashes():
    out = run("dashboard_io.js", """
      const own = { id: 'c-aaaa11', type: 'value', title: 'Latency', source: 'speed.ping' };
      const shared = { id: 'c-bbbb22', type: 'notes', title: 'Runbook', text: 'x', links: [] };
      const doc = m.buildExport({ order: ['attention', 'c-aaaa11', 'c-bbbb22', 'devices'], sizes: { attention: 'w', gone: 'f' }, cardOf: (id) => ({ 'c-aaaa11': own, 'c-bbbb22': shared })[id] || null, name: 'Site A', appVersion: '0.4.450', now: new Date('2026-11-17T10:00:00.123Z') });
      let n = 0; const newId = () => 'c-new' + (++n);
      const known = new Set(['attention', 'devices', 'uptime']);
      const back = m.parseImport(JSON.stringify(doc), { known, newId });
      const odd = JSON.parse(JSON.stringify(doc));
      odd.layout.order.push('plugin-card', 'c-missing'); odd.custom.push({ id: 'c-dev', type: 'device', device_id: 7, title: 'Printer' }); odd.layout.order.push('c-dev');
      return { doc, back, odd: m.parseImport(JSON.stringify(odd), { known, newId }), file: m.exportFileName(new Date('2026-11-17T10:00:00Z')),
               bad: [m.parseImport('nope', { known, newId }), m.parseImport('{"format":"other"}', { known, newId }), m.parseImport(JSON.stringify({ ...doc, version: 9 }), { known, newId }),
                     m.parseImport(JSON.stringify({ ...doc, layout: { order: ['zzz'] }, custom: [] }), { known, newId }), m.parseImport('x'.repeat(600000), { known, newId })].map((r) => [r.ok, r.error]) };""")
    doc = out["doc"]
    assert doc["format"] == "netlens-dashboard" and doc["version"] == 1 and doc["exported"] == "2026-11-17T10:00:00Z" and doc["layout"]["sizes"] == {"attention": "w"}
    assert [c["id"] for c in doc["custom"]] == ["c-aaaa11", "c-bbbb22"] and out["file"] == "netlens-dashboard-2026-11-17.json"      # a shared card is carried along as a card of its own
    back = out["back"]
    assert back["ok"] and back["order"] == ["attention", "c-new1", "c-new2", "devices"] and back["sizes"] == {"attention": "w"}
    assert [c["id"] for c in back["custom"]] == ["c-new1", "c-new2"] and back["skipped"] == []                                   # imported cards get new ids: they cannot replace one of yours
    odd = out["odd"]
    assert odd["ok"] and sorted(s["id"] for s in odd["skipped"]) == ["c-dev", "c-missing", "plugin-card"] and odd["counts"]["skipped"] == 3
    assert any("number here" in s["why"] for s in odd["skipped"] if s["id"] == "c-dev")                                           # a card that names one device means nothing elsewhere
    assert [r[0] for r in out["bad"]] == [False] * 5 and "valid JSON" in out["bad"][0][1] and "newer" in out["bad"][2][1] and "None of the cards" in out["bad"][3][1] and "too large" in out["bad"][4][1]


def test_a_rule_reads_as_a_sentence():
    out = run("alert_rules_text.js", """
      const ctx = { kindName: (k) => ({ device_offline: 'device offline', service_down: 'service down' })[k] || k, groupName: (id) => ({ 1: 'Garden', 2: 'Office' })[id], deviceName: (id) => ({ 3: 'Garden AP', 4: 'NAS' })[id] };
      const base = { kinds: ['device_offline'], scope: { type: 'all' }, when: null, keep_critical: true };
      return { days: [[0,1,2,3,4], [5,6], [0,1,2,3,4,5,6], [0,2,3,4,6], [1]].map(m.describeDays),
        mute: m.describeRule({ ...base, type: 'mute', kinds: ['device_offline', 'service_down'], scope: { type: 'group', ids: [1, 2] }, when: { days: [0,1,2,3,4], from: '22:00', to: '07:00' } }, ctx),
        down: m.describeRule({ ...base, type: 'while_down', device_id: 4, scope: { type: 'below', device_id: 3 } }, ctx),
        repeat: m.describeRule({ ...base, type: 'repeat', count: 3, minutes: 10, per: 'device', keep_critical: false }, ctx),
        all: m.describeRule({ ...base, type: 'mute', kinds: ['*'] }, ctx), none: m.listOf([], 'nothing') };""")
    assert out["days"] == ["Monday to Friday", "at the weekend", "every day", "Mon, Wed–Fri, Sun", "Tue"]
    assert out["mute"] == "Ignore device offline and service down for devices in Garden and Office, Monday to Friday 22:00–07:00."
    assert out["down"] == "Ignore device offline for everything behind Garden AP while NAS is offline."
    assert out["repeat"] == "After 3 device offline events within 10 minutes for the same device, ignore the rest and tell me once (critical events too)."
    assert out["all"] == "Ignore any event for every device." and out["none"] == "nothing"


def test_the_kind_of_a_device_decides_which_cards_it_gets():
    out = run("devicekinds.js", """
      const kinds = ['pc', 'server', 'nas', 'vm', 'unknown', 'switch', 'router', 'ap', 'phone', 'tablet', 'tv', 'camera', 'iot', 'printer', 'speaker', 'console', 'appliance', 'container', 'app'];
      return { host: kinds.filter((k) => m.isHost({ device_type: k })), gear: kinds.filter((k) => m.isGear({ device_type: k })),
               override: m.typeOf({ device_type: 'unknown', type_override: 'switch' }), hosted: [...m.HOSTED],
               unmonitored: kinds.filter((k) => !m.canMonitor({ device_type: k })) };""")
    assert out["unmonitored"] == ["phone", "tablet", "tv", "speaker", "console"]
    assert out["host"] == ["pc", "server", "nas", "vm", "unknown"]
    assert out["gear"] == ["switch", "router", "ap"]
    assert out["override"] == "switch" and set(out["hosted"]) == {"vm", "container", "app"}
