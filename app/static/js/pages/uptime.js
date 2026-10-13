import { get } from "../api.js";
import { h, clear, toast, statusDot, shortName } from "../util.js";
import { heartbeatBar, responseLine, rangeTabs, savedRange, RANGES, uptimeText, uptimeClass } from "../heartbeat.js";

const PCT = { "24h": "up_24h", "7d": "up_7d", "30d": "up_30d" };
const SORTS = [["name", "Name"], ["worst", "Least reliable first"], ["slow", "Slowest first"]];

const mean = (list) => (list.length ? list.reduce((a, b) => a + b, 0) / list.length : null);
const avgResponse = (item) => mean((item.bars || []).filter((b) => typeof b === "object" && typeof b.rtt_ms === "number").map((b) => b.rtt_ms));
const fmtMs = (v) => (v === null || v === undefined ? "–" : `${v >= 100 ? Math.round(v) : Math.round(v * 10) / 10} ms`);
const tone = (pct) => (pct === null || pct === undefined ? "off" : pct >= 99 ? "" : pct >= 95 ? "warn" : "bad");

export async function render(container) {
  let disposed = false, inFlight = false, timer = null;
  let range = savedRange(), sort = "name", filterText = "", onlyProblems = false, data = null;

  const phone = () => window.matchMedia("(max-width: 700px)").matches;
  const slots = () => (phone() ? 30 : 60);

  const tiles = h("div", { class: "up-tiles" });
  const list = h("div", { class: "up-list" });
  const periodLabel = () => RANGES.find(([k]) => k === range)[1];

  function drawTiles() {
    clear(tiles);
    if (!data || !data.length) return;
    const withData = data.filter((d) => d[PCT[range]] !== null && d[PCT[range]] !== undefined);
    const avg = mean(withData.map((d) => d[PCT[range]]));
    const online = data.filter((d) => d.online).length;
    const withDowntime = data.filter((d) => (d.bars || []).some((b) => typeof b === "object" && !b.up)).length;
    const rt = mean(data.map(avgResponse).filter((v) => v !== null));
    const tile = (title, value, sub, kind) => h("section", { class: `dcard ${kind ? `tone-${kind}` : ""}` }, h("h2", { class: "d-title" }, title),
      h("div", { class: "d-body" }, h("div", { class: "d-value" }, value), h("div", { class: "d-sub" }, sub)));
    tiles.append(
      tile("Online now", `${online} / ${data.length}`, online === data.length ? "every device answers" : `${data.length - online} not answering`, online === data.length ? "ok" : "warn"),
      tile("Availability", uptimeText(avg), `average over ${periodLabel().toLowerCase()}`, avg === null ? "" : avg >= 99 ? "ok" : avg >= 95 ? "warn" : "bad"),
      tile("With downtime", String(withDowntime), withDowntime ? `devices missed a check in ${periodLabel().toLowerCase()}` : `no device missed a check in ${periodLabel().toLowerCase()}`, withDowntime ? "warn" : "ok"),
      tile("Response time", fmtMs(rt), `average over ${periodLabel().toLowerCase()}`, ""));
  }

  function row(item) {
    const pct = item[PCT[range]];
    const n = slots();
    const resp = avgResponse(item);
    const num = (key, label) => h("div", { class: `up-num ${key === range ? "picked" : ""}` }, h("small", {}, label), h("strong", { class: uptimeClass(item[PCT[key]]) }, uptimeText(item[PCT[key]])));
    return h("div", { class: `up-row ${tone(pct)}`, dataset: { search: `${(item.name || "").toLowerCase()} ${(item.ip || "").toLowerCase()}` } },
      h("div", { class: "up-who" },
        h("div", { class: "up-state" }, statusDot(item.online), h("a", { href: `#/device/${item.id}`, title: item.name || null }, shortName(item.name) || "")),
        item.ip && item.ip !== item.name ? h("div", { class: "mono hint" }, item.ip) : null),
      h("div", { class: "up-avail" }, h("span", { class: "up-graph-label" }, "Availability"), heartbeatBar(item.bars || [], n)),
      h("div", { class: "up-resp" }, h("span", { class: "up-graph-label" }, `Response time · average ${fmtMs(resp)}`), responseLine(item.bars || [], n, { height: 34 })),
      h("div", { class: "up-nums" }, num("24h", "24 h"), num("7d", "7 days"), num("30d", "30 days")));
  }

  function drawList() {
    clear(list);
    if (!data) return;
    if (!data.length) { list.append(h("div", { class: "up-empty" }, "No devices yet. Run a scan first.")); return; }
    const q = filterText.trim().toLowerCase();
    let items = data.filter((d) => (!q || `${(d.name || "").toLowerCase()} ${(d.ip || "").toLowerCase()}`.includes(q))
      && (!onlyProblems || (d.bars || []).some((b) => typeof b === "object" && !b.up) || !d.online));
    const key = PCT[range];
    if (sort === "worst") items = [...items].sort((a, b) => (a[key] ?? 101) - (b[key] ?? 101) || (a.name || "").localeCompare(b.name || ""));
    if (sort === "slow") items = [...items].sort((a, b) => (avgResponse(b) ?? -1) - (avgResponse(a) ?? -1));
    if (!items.length) { list.append(h("div", { class: "up-empty" }, onlyProblems && !q ? "No device had a problem in this period." : "No device matches.")); return; }
    for (const item of items) list.append(row(item));
  }

  function draw() { drawTiles(); drawList(); }

  async function load() {
    if (disposed || inFlight) return;
    inFlight = true;
    try {
      const result = await get(`/api/uptime?range=${range}&bars=${slots()}`);
      if (disposed) return;
      data = result;
      draw();
    } catch (err) {
      if (!disposed) toast("Failed to load uptime", "error");
    } finally {
      inFlight = false;
    }
  }

  clear(container);
  container.append(
    h("div", { class: "up-head" },
      h("div", {}, h("h1", {}, "Uptime"),
        h("p", { class: "hint" }, "Every scan records whether each device answered and how fast. Green = up, red = down. Point at a bar or the line for the time and the response time; the newest is on the right.")),
      rangeTabs(range, (key) => { range = key; data = null; clear(list); list.append(h("p", { class: "hint" }, "Loading…")); load(); })),
    tiles,
    h("div", { class: "up-tools" },
      h("input", { type: "text", placeholder: "Filter by name or IP", "aria-label": "Filter by name or IP", oninput: (e) => { filterText = e.target.value; drawList(); } }),
      h("select", { "aria-label": "Sort", onchange: (e) => { sort = e.target.value; drawList(); } }, SORTS.map(([k, label]) => h("option", { value: k }, label))),
      h("label", {}, h("input", { type: "checkbox", onchange: (e) => { onlyProblems = e.target.checked; drawList(); } }), "Only devices with a problem")),
    list);
  list.append(h("p", { class: "hint" }, "Loading…"));

  load();
  timer = setInterval(load, 30000);

  return function cleanup() {
    disposed = true;
    if (timer) clearInterval(timer);
  };
}
