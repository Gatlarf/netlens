import { get, put } from "../api.js";
import { h, clear, patch, toast, statusDot, shortName } from "../util.js";
import { pageHead } from "../ui.js";
import { buildPerformanceCard } from "../cards/performance.js";
import { heartbeatBar, responseLine, rangeTabs, savedRange, RANGES, uptimeText, uptimeClass } from "../heartbeat.js";

const PCT = { "24h": "up_24h", "7d": "up_7d", "30d": "up_30d" };
const SCOPE_KEY = "netlens.uptime.scope";
const savedScope = () => { try { return localStorage.getItem(SCOPE_KEY) === "core" ? "core" : "all"; } catch (e) { return "all"; } };
const DENSE_KEY = "netlens.uptime.graphs";
const savedGraphs = () => { try { return localStorage.getItem(DENSE_KEY) === "on"; } catch (e) { return false; } };
const SORTS = [["name", "Name"], ["worst", "Least reliable first"], ["slow", "Slowest first"]];

const mean = (list) => (list.length ? list.reduce((a, b) => a + b, 0) / list.length : null);
const avgResponse = (item) => mean((item.bars || []).filter((b) => typeof b === "object" && typeof b.rtt_ms === "number").map((b) => b.rtt_ms));
const fmtMs = (v) => (v === null || v === undefined ? "–" : `${v >= 100 ? Math.round(v) : Math.round(v * 10) / 10} ms`);
const tone = (pct) => (pct === null || pct === undefined ? "off" : pct >= 99 ? "" : pct >= 95 ? "warn" : "bad");

export async function render(container) {
  let disposed = false, inFlight = false, timer = null;
  const openGraphs = new Set();      // devices whose history graph is open (kept when the list is redrawn)
  let range = savedRange(), scope = savedScope(), sort = "worst", filterText = "", onlyProblems = false, data = null;

  const phone = () => window.matchMedia("(max-width: 700px)").matches;
  const slots = () => (phone() ? 30 : 60);

  const tiles = h("div", { class: "up-tiles" });
  const chooser = h("div", {});
  const pool = () => (data ? (scope === "core" ? data.filter((d) => d.always_on) : data) : []);
  const scopeLabel = () => (scope === "core" ? "core devices" : "all devices");
  let graphs = savedGraphs();      // the response-time line of every device: off by default, one line per device is enough to scan
  const list = h("div", { class: `up-list${graphs ? "" : " up-compact"}` });
  const periodLabel = () => RANGES.find(([k]) => k === range)[1];

  function drawTiles() {
    const data_ = pool();
    if (!data_.length) return clear(tiles);
    const withData = data_.filter((d) => d[PCT[range]] !== null && d[PCT[range]] !== undefined);
    const avg = mean(withData.map((d) => d[PCT[range]]));
    const online = data_.filter((d) => d.online).length;
    const withDowntime = data_.filter((d) => (d.bars || []).some((b) => typeof b === "object" && !b.up)).length;
    const rt = mean(data_.map(avgResponse).filter((v) => v !== null));
    const tile = (title, value, sub, kind) => h("section", { class: `dcard ${kind ? `tone-${kind}` : ""}` }, h("h2", { class: "d-title" }, title),
      h("div", { class: "d-body" }, h("div", { class: "d-value" }, value), h("div", { class: "d-sub" }, sub)));
    patch(tiles,
      tile("Online now", `${online} / ${data_.length}`, online === data_.length ? "every device answers" : `${data_.length - online} not answering`, online === data_.length ? "ok" : "warn"),
      tile("Availability", uptimeText(avg), `${scopeLabel()}, average over ${periodLabel().toLowerCase()}`, avg === null ? "" : avg >= 99 ? "ok" : avg >= 95 ? "warn" : "bad"),
      tile("With downtime", String(withDowntime), withDowntime ? `devices missed a check in ${periodLabel().toLowerCase()}` : `no device missed a check in ${periodLabel().toLowerCase()}`, withDowntime ? "warn" : "ok"),
      tile("Response time", fmtMs(rt), `average over ${periodLabel().toLowerCase()}`, ""));
  }

  function row(item) {
    const pct = item[PCT[range]];
    const n = slots();
    const resp = avgResponse(item);
    const num = (key, label) => h("div", { class: `up-num ${key === range ? "picked" : ""}` }, h("small", {}, label), h("strong", { class: uptimeClass(item[PCT[key]]) }, uptimeText(item[PCT[key]])));
    const detail = h("div", { class: "up-detail", "data-live": "", hidden: !openGraphs.has(item.id) });
    const fill = async () => {
      if (detail.firstChild) return;
      const card = await buildPerformanceCard("device", item.id, { title: `${shortName(item.name) || item.ip}: history`, only: ["up", "rtt_ms"] });
      detail.appendChild(card || h("p", { class: "hint" }, "No measurements yet."));
    };
    if (openGraphs.has(item.id)) fill();
    const rowEl = h("div", { class: `up-row ${tone(pct)}`, dataset: { search: `${(item.name || "").toLowerCase()} ${(item.ip || "").toLowerCase()}` } },
      h("div", { class: "up-who" },
        h("div", { class: "up-state" }, statusDot(item.online), h("a", { href: `#/device/${item.id}`, title: item.name || null }, shortName(item.name) || ""),
          item.behind ? h("span", { class: "tag unknown-tag", title: `${item.behind} is offline: this device cannot be reached through it` }, `unreachable · behind ${shortName(item.behind)}`) : null),
        item.ip && item.ip !== item.name ? h("div", { class: "mono hint" }, item.ip) : null),
      h("div", { class: "up-avail" }, h("span", { class: "up-graph-label" }, "Availability"), heartbeatBar(item.bars || [], n)),
      h("div", { class: "up-resp" }, h("span", { class: "up-graph-label" }, `Response time · average ${fmtMs(resp)}`), responseLine(item.bars || [], n, { height: 34 })),
      h("div", { class: "up-nums" }, num("24h", "24 h"), num("7d", "7 days"), num("30d", "30 days")), detail);
    // a click on the row opens the graph, except on the device link and the bars (they show their own details)
    rowEl.addEventListener("click", (e) => {
      if (e.target.closest("a, button, .hb-bar, .rl, .up-detail")) return;
      detail.hidden = !detail.hidden;
      if (detail.hidden) openGraphs.delete(item.id); else { openGraphs.add(item.id); fill(); }
    });
    return rowEl;
  }

  function drawList() {
    if (!data) return clear(list);
    if (!data.length) return patch(list, h("div", { class: "up-empty" }, "No devices yet. Run a scan first."));
    if (scope === "core" && !pool().length) {
      return patch(list, h("div", { class: "up-empty" }, "No device is marked as always-on yet. ", h("button", { class: "btn primary admin-only", type: "button", onclick: openChooser }, "Choose always-on devices"),
        h("p", { class: "hint" }, "Always-on devices are the ones that should be online all the time, such as the router, switches, servers and cameras. You can also tick \u201cAlways-on device\u201d on a device's page.")));
    }
    const q = filterText.trim().toLowerCase();
    let items = pool().filter((d) => (!q || `${(d.name || "").toLowerCase()} ${(d.ip || "").toLowerCase()}`.includes(q))
      && (!onlyProblems || (d.bars || []).some((b) => typeof b === "object" && !b.up) || !d.online));
    const key = PCT[range];
    if (sort === "worst") items = [...items].sort((a, b) => (a[key] ?? 101) - (b[key] ?? 101) || (a.name || "").localeCompare(b.name || ""));
    if (sort === "slow") items = [...items].sort((a, b) => (avgResponse(b) ?? -1) - (avgResponse(a) ?? -1));
    if (!items.length) return patch(list, h("div", { class: "up-empty" }, onlyProblems && !q ? "No device had a problem in this period." : "No device matches."));
    patch(list, items.map(row));
  }

  function draw() { drawTiles(); drawList(); }


  // the panel to choose which devices are always-on
  async function openChooser() {
    let rows;
    try {
      rows = (await get("/api/uptime/core")).devices;
    } catch (err) {
      toast(err.message || "Could not load the devices", "error");
      return;
    }
    const picked = new Set(rows.filter((r) => r.always_on).map((r) => r.id));
    const suggested = rows.filter((r) => r.suggested);
    let q = "";
    const body = h("div", { class: "up-choose-list" });
    const count = h("strong", {});
    const redraw = () => {
      clear(body);
      count.textContent = `${picked.size} selected`;
      for (const r of rows.filter((r) => !q || `${r.name} ${r.ip || ""} ${r.type}`.toLowerCase().includes(q))) {
        body.append(h("label", { class: "up-choose-row" },
          h("input", { type: "checkbox", checked: picked.has(r.id), onchange: (e) => { if (e.target.checked) picked.add(r.id); else picked.delete(r.id); count.textContent = `${picked.size} selected`; } }),
          h("span", { class: "up-choose-name" }, shortName(r.name), r.ip ? h("span", { class: "mono hint" }, ` ${r.ip}`) : null),
          h("span", { class: "hint" }, r.type),
          r.suggested ? h("span", { class: "badge up-suggest", title: "Up almost all the time over 30 days and the kind of device that runs all day" }, "suggested") : null,
          h("span", { class: `up-choose-pct ${uptimeClass(r.up_30d)}` }, uptimeText(r.up_30d))));
      }
      if (!body.children.length) body.append(h("p", { class: "hint" }, "No device matches."));
    };
    redraw();
    const close = () => clear(chooser);
    clear(chooser);
    chooser.append(h("div", { class: "card up-choose" },
      h("h2", {}, "Always-on devices"),
      h("p", { class: "hint" }, "Tick the devices that should be online all the time. They are then shown apart from the rest here (the Always-on switch), on the dashboard and in Statistics."),
      h("div", { class: "up-tools" },
        h("input", { type: "text", placeholder: "Search", "aria-label": "Search devices", oninput: (e) => { q = e.target.value.trim().toLowerCase(); redraw(); } }),
        suggested.length ? h("button", { class: "btn", type: "button", onclick: () => { for (const r of suggested) picked.add(r.id); redraw(); } }, `Select the ${suggested.length} suggested`) : h("span", { class: "hint" }, "No suggestions right now."),
        count),
      body,
      h("div", { class: "up-tools" },
        h("button", { class: "btn primary", type: "button", onclick: async (e) => {
          e.target.disabled = true;
          try {
            await put("/api/uptime/core", { device_ids: [...picked] });
            toast("Saved", "success");
            close();
            await load(true);
          } catch (err) {
            toast(err.message || "Could not save", "error");
            e.target.disabled = false;
          }
        } }, "Save"),
        h("button", { class: "btn", type: "button", onclick: close }, "Cancel"))));
    chooser.scrollIntoView({ block: "nearest" });
  }

  async function load(force = false) {
    if (disposed || (inFlight && !force)) return;
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

  function scopeTabs() {
    const wrap = h("div", { class: "range-tabs", role: "group", "aria-label": "Which devices" });
    for (const [key, label, title] of [["all", "All devices", "Every device, including phones and tablets that come and go"], ["core", "Always-on", "Only the devices marked as always-on (router, switches, servers ...)"]]) {
      wrap.append(h("button", { type: "button", title, "aria-pressed": String(key === scope), onclick: (e) => {
        scope = key;
        try { localStorage.setItem(SCOPE_KEY, key); } catch (err) { /* only this page remembers it */ }
        for (const b of wrap.children) b.setAttribute("aria-pressed", String(b === e.currentTarget));
        draw();
      } }, label));
    }
    return wrap;
  }

  clear(container);
  container.append(
    pageHead("Uptime", "Every scan, and a quick check every minute for the always-on devices, records whether a device answered and how fast. A bar is green when every check in it passed, red when none did, and in between (yellow, orange) when some were missed. Point at a bar for the time, the number of missed checks and the response time; the newest is on the right.",
      h("div", { class: "up-pickers" },
        scopeTabs(),
        rangeTabs(range, (key) => { range = key; data = null; clear(list); list.append(h("p", { class: "hint" }, "Loading…")); load(); }))),
    chooser,
    tiles,
    h("div", { class: "up-tools" },
      h("input", { type: "text", placeholder: "Filter by name or IP", "aria-label": "Filter by name or IP", oninput: (e) => { filterText = e.target.value; drawList(); } }),
      h("select", { "aria-label": "Sort", onchange: (e) => { sort = e.target.value; drawList(); } }, SORTS.map(([k, label]) => h("option", { value: k, selected: k === sort }, label))),
      h("label", {}, h("input", { type: "checkbox", onchange: (e) => { onlyProblems = e.target.checked; drawList(); } }), "Only devices with a problem"),
      h("label", {}, h("input", { type: "checkbox", checked: graphs, onchange: (e) => { graphs = e.target.checked; list.classList.toggle("up-compact", !graphs); try { localStorage.setItem(DENSE_KEY, graphs ? "on" : "off"); } catch (err) { /* only this page remembers it */ } } }), "Response-time graphs"),
      h("button", { class: "btn admin-only", type: "button", onclick: openChooser }, "Choose always-on devices")),
    list);
  list.append(h("p", { class: "hint" }, "Loading…"));

  load();
  timer = setInterval(() => { if (!document.hidden) load(); }, 30000);

  return function cleanup() {
    disposed = true;
    if (timer) clearInterval(timer);
  };
}
