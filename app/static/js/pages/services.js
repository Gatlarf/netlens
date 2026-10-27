import { get, post, patch, del } from "../api.js";
import { h, clear, patch as patchDom, toast, timeAgo, shortName } from "../util.js";
import { pageHead, rowMenu, emptyState, tile } from "../ui.js";
import { heartbeatBar, uptimeText, uptimeClass } from "../heartbeat.js";
import { buildServiceForm } from "../cards/service_form.js";
import { buildPerformanceCard } from "../cards/performance.js";

const STATE_LABEL = { up: "Up", down: "Down", null: "Waiting" };

export function stateDot(check) {
  const cls = !check.enabled ? "paused" : check.state === "up" ? "up" : check.state === "down" ? "down" : "unknown";
  return h("span", { class: `svc-dot svc-${cls}`, title: !check.enabled ? "Paused" : STATE_LABEL[check.state] }, "");
}

async function heartbeats(check) {
  try {
    const rows = await get(`/api/service-checks/${check.id}/results?bars=60&hours=24`);     // the last day in 60 slices: a slice with failures is coloured by how many
    return heartbeatBar(rows.map((r) => ({ ts: r.ts, end: r.end, n: r.n, down: r.down, up: r.up, rtt_ms: r.ms, rtt_max: r.ms_max })), 60);
  } catch (err) {
    return h("span", {});
  }
}

// The plugins that are switched on, as lines of the same table: how their syncs went, how long they took, and the same graph when you click a line.
// A plugin that cannot reach its system shows up here as red bars, which tells a slow or unreachable system from a plugin that is broken.
function pluginRows(plugins, openGraphs) {
  if (!plugins.length) return [];
  const rows = [h("tr", { class: "svc-sep" }, h("td", { colspan: 8 }, h("strong", {}, "Plugins"), " ", h("span", { class: "hint" }, "how their syncs went; a red bar is a sync that failed, often because the system it talks to did not answer")))];
  for (const p of plugins) {
    const hb = h("td", {});
    hb.appendChild(heartbeatBar(p.beats.map((r) => ({ ts: r.ts, up: r.up, rtt_ms: r.ms })), 60));
    const graphRow = h("tr", { class: "svc-graph-row", hidden: !openGraphs.has(p.id) }, h("td", { colspan: 8 }));
    const showGraph = async () => {
      const cell = graphRow.firstChild;
      if (cell.firstChild) return;
      const card = await buildPerformanceCard("plugin", p.series_id, { title: `${p.name}: syncs` });
      cell.appendChild(card || h("p", { class: "hint" }, "No measurements yet. They appear after the first syncs."));
    };
    if (openGraphs.has(p.id)) showGraph();
    const dot = h("span", { class: `svc-dot svc-${p.state === "up" ? "up" : p.state === "down" ? "down" : "unknown"}`, title: p.state === "up" ? "Last sync went well" : p.state === "down" ? "Last sync failed" : "Waiting" }, "");
    const line = h("tr", { class: "svc-line", title: "Click for the history graph" },
      h("td", {}, dot), h("td", {}, p.name, p.state === "down" && p.last_detail ? h("div", { class: "hint" }, p.last_detail) : null),
      h("td", {}, h("a", { href: "#/settings/plugins", title: "Plugin settings" }, `plugin (${p.kind || ""})`)), hb, h("td", { class: uptimeClass(p.uptime_24h) }, uptimeText(p.uptime_24h)),
      h("td", {}, p.last_ms === null ? "–" : p.last_ms >= 1000 ? `${(p.last_ms / 1000).toFixed(1)} s` : `${Math.round(p.last_ms)} ms`), h("td", {}, p.last_ts ? timeAgo(p.last_ts) : "never"), h("td", {}));
    line.addEventListener("click", (e) => {
      if (e.target.closest("a, button, .hb-bar, .rl")) return;
      graphRow.hidden = !graphRow.hidden;
      if (graphRow.hidden) openGraphs.delete(p.id); else { openGraphs.add(p.id); showGraph(); }
    });
    rows.push(line, graphRow);
  }
  return rows;
}

export async function render(container) {
  let destroyed = false;
  const openGraphs = new Set();      // checks whose graph is open (kept when the table is redrawn)
  const openPlugins = new Set();
  const addBtn = h("button", { class: "btn primary admin-only", type: "button" }, "Add check");
  const top = pageHead("Services", "HTTP pages, TCP ports, DNS lookups, certificates and processes, checked at the interval you choose.", addBtn);
  const formSlot = h("div", {});
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  const tiles = h("div", { class: "up-tiles" });
  container.append(top, tiles, formSlot, body);

  // the same three tiles as Health: how many checks work, how many fail, how reliable they were over the last day
  function drawTiles(checks) {
    if (!checks.length) return clear(tiles);
    const active = checks.filter((c) => c.enabled);
    const down = active.filter((c) => c.state === "down");
    const up = active.filter((c) => c.state === "up").length;
    const rated = active.map((c) => c.uptime_24h).filter((v) => typeof v === "number");
    const avg = rated.length ? rated.reduce((a, b) => a + b, 0) / rated.length : null;
    patchDom(tiles,
      tile("Checks up", `${up} / ${active.length}`, checks.length > active.length ? `${checks.length - active.length} paused.` : "Every check is switched on.", down.length ? "warn" : "ok"),
      tile("Down", String(down.length), down.length ? `Failing now: ${down.slice(0, 5).map((c) => c.name).join(", ")}${down.length > 5 ? " …" : ""}.` : "Nothing is failing.", down.length ? "bad" : "ok"),
      tile("Availability, 24 h", uptimeText(avg), "Average over the checks that are switched on.", avg === null ? "" : avg >= 99 ? "ok" : avg >= 95 ? "warn" : "bad"));
  }

  async function showForm(check = null) {
    clear(formSlot);
    const card = h("div", { class: "card" }, h("h2", {}, check ? "Edit check" : "New check"));
    card.appendChild(await buildServiceForm({ check, onDone: (changed) => { clear(formSlot); if (changed) load(); } }));
    formSlot.appendChild(card);
    card.scrollIntoView({ block: "nearest" });
  }
  addBtn.addEventListener("click", () => showForm());

  let table = null, tbody = null, wrap = null;       // built once; a refresh only changes the rows that changed
  async function load() {
    let checks;
    try {
      checks = await get("/api/service-checks");
    } catch (err) {
      if (!destroyed) body.replaceChildren(h("p", { class: "error" }, err.message || "Failed to load"));
      return;
    }
    let plugins = [];
    try { plugins = await get("/api/plugin-runs"); } catch (err) { /* the plugins are an extra; the checks still show */ }
    if (destroyed) return;
    drawTiles(checks);
    const plugRows = pluginRows(plugins, openPlugins);
    if (!checks.length) {
      body.replaceChildren(...[emptyState("No checks yet", "Add one to watch a web page, a port or a DNS server. Typical examples: your router's web page (HTTP), your NAS on port 445 (TCP), your DNS server resolving example.com (DNS).", h("button", { class: "btn primary admin-only", type: "button", onclick: () => addBtn.click() }, "Add check")), plugRows.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("tbody", {}, ...plugRows))) : null].filter(Boolean));
      return;
    }
    // the history bars are fetched first and built into the rows, so a refresh that changed nothing leaves the rows exactly as they are
    const bars = await Promise.all(checks.map(heartbeats));
    if (destroyed) return;
    if (!table) {
      table = h("table", { class: "data" });
      table.appendChild(h("thead", {}, h("tr", {}, ["", "Name", "Device", "History", "24 h", "Resp.", "Checked", ""].map((t) => h("th", {}, t)))));
      tbody = h("tbody");
      table.appendChild(tbody);
    }
    const lines = [];
    for (const [i, c] of checks.entries()) {
      const hb = h("td", {}, bars[i]);
      const run = h("button", { class: "btn admin-only", type: "button" }, "Run");
      run.title = "Run the check now";
      run.addEventListener("click", async () => {
        run.disabled = true;
        try {
          const res = await post(`/api/service-checks/${c.id}/run`, {});
          toast(`${c.name}: ${res.up ? "up" : "down"} (${res.detail})`, res.up ? "success" : "error");
        } catch (err) {
          toast(err.message || "Check failed", "error");
        }
        load();
      });
      const doEdit = () => showForm(c);
      const doPause = async () => { await patch(`/api/service-checks/${c.id}`, { enabled: !c.enabled }); load(); };
      const doRemove = async () => {
        if (!window.confirm(`Delete the check "${c.name}" and its history?`)) return;
        try {
          await del(`/api/service-checks/${c.id}`);
          toast("Check deleted", "success");
        } catch (err) {
          toast(err.message || "Could not delete", "error");
        }
        load();
      };
      const more = rowMenu([{ label: "Edit", onclick: doEdit }, { label: c.enabled ? "Pause" : "Resume", onclick: doPause }, { label: "Delete", onclick: doRemove, danger: true }], { cls: "admin-only" });
      const graphBtn = h("button", { class: "btn", type: "button", "aria-expanded": String(openGraphs.has(c.id)) }, "Graph");
      const graphRow = h("tr", { class: "svc-graph-row", hidden: !openGraphs.has(c.id) }, h("td", { colspan: 8, "data-live": "" }));
      const showGraph = async () => {
        const cell = graphRow.firstChild;
        if (cell.firstChild) return;
        const card = await buildPerformanceCard("service", c.id, { title: `${c.name}: history` });
        cell.appendChild(card || h("p", { class: "hint" }, "No measurements yet. They appear after the first checks."));
      };
      if (openGraphs.has(c.id)) showGraph();
      graphBtn.addEventListener("click", () => {
        const open = graphRow.hidden;
        graphRow.hidden = !open;
        graphBtn.setAttribute("aria-expanded", String(open));
        if (open) { openGraphs.add(c.id); showGraph(); } else openGraphs.delete(c.id);
      });
      const line = h("tr", { class: "svc-line", title: "Click for the history graph" },
        h("td", {}, stateDot(c)), h("td", { title: c.target || null }, c.name, c.state === "down" && c.last_detail ? h("div", { class: "hint" }, c.last_detail) : null),
        h("td", {}, c.device_id ? h("a", { href: `#/device/${c.device_id}`, title: c.device_name || null }, shortName(c.device_name) || `device ${c.device_id}`) : ""),
        hb, h("td", { class: uptimeClass(c.uptime_24h) }, uptimeText(c.uptime_24h)), h("td", {}, c.last_ms === null ? "–" : `${Math.round(c.last_ms)} ms`),
        h("td", {}, c.last_ts ? timeAgo(c.last_ts) : "never"), h("td", { class: "actions" }, run, graphBtn, more));
      // a click on the line opens the graph, except on a link, a button or the heartbeat bar (those have their own meaning)
      line.addEventListener("click", (e) => { if (!e.target.closest("a, button, input, select, .hb-bar, .rl, .row-menu, .actions")) graphBtn.click(); });
      lines.push(line, graphRow);
    }
    patchDom(tbody, lines, plugRows);
    if (!wrap) wrap = h("div", { class: "table-wrap" }, table);
    patchDom(body, wrap);
  }

  await load();
  const timer = setInterval(() => { if (!destroyed && !document.hidden && !formSlot.firstChild) load(); }, 15000);
  return () => { destroyed = true; clearInterval(timer); };
}
