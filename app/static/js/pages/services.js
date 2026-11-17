import { get, post, patch, del } from "../api.js";
import { h, clear, patch as patchDom, toast, timeAgo, shortName } from "../util.js";
import { pageHead, rowMenu, emptyState, tile } from "../ui.js";
import { heartbeatBar, uptimeText, uptimeClass } from "../heartbeat.js";
import { buildServiceForm } from "../cards/service_form.js";
import { buildPerformanceCard } from "../cards/performance.js";
import { createTableViews } from "../tableview.js";
import { CATALOG, BUILTIN_VIEWS } from "../tables/services.js";

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

export async function render(container) {
  let destroyed = false;
  const openGraphs = new Set();      // checks whose graph is open (kept when the table is redrawn)
  const openPlugins = new Set();
  const tv = await createTableViews({ table: "services", catalog: CATALOG, builtins: BUILTIN_VIEWS, locked: ["status", "name"], trailing: true, onChange: () => draw() });
  const addBtn = h("button", { class: "btn primary admin-only", type: "button" }, "Add check");
  const top = pageHead("Services", "HTTP pages, TCP ports, DNS lookups, certificates and processes, checked at the interval you choose.", tv.controls, addBtn);
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

  let items = [], wrap = null;
  tv.useRows(() => items);

  function draw() {
    if (destroyed || !items.length) return;
    const lines = tv.lines(items, {
      actions: (c) => {
        const graphBtn = h("button", { class: "btn", type: "button", "aria-expanded": String(openGraphs.has(c.id)), "data-graph": "" }, "Graph");
        if (c.plugin) return [graphBtn];
        const run = h("button", { class: "btn admin-only", type: "button", title: "Run the check now" }, "Run");
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
        const doPause = async () => { await patch(`/api/service-checks/${c.id}`, { enabled: !c.enabled }); load(); };
        const doRemove = async () => {
          const made = c.source && !String(c.source).startsWith("central:");         // a plugin made it for a site: it stays deleted until restored
          if (!window.confirm(`Delete the check "${c.name}" and its history?${made ? " It was made by a plugin for a site; it stays deleted (you can restore it from the site's list)." : ""}`)) return;
          try {
            await del(`/api/service-checks/${c.id}`);
            toast("Check deleted", "success");
          } catch (err) {
            toast(err.message || "Could not delete", "error");
          }
          load();
        };
        const more = rowMenu([{ label: "Edit", onclick: () => showForm(c) }, { label: c.enabled ? "Pause" : "Resume", onclick: doPause }, { label: "Delete", onclick: doRemove, danger: true }], { cls: "admin-only" });
        return [run, graphBtn, more];
      },
      detail: (c, span) => {
        const graphRow = h("tr", { class: "svc-graph-row", hidden: !openGraphs.has(c.id) }, h("td", { colspan: span, "data-live": "" }));
        const showGraph = async () => {
          const cell = graphRow.firstChild;
          if (cell.firstChild) return;
          const card = c.plugin ? await buildPerformanceCard("plugin", c.series_id, { title: `${c.name}: syncs` }) : await buildPerformanceCard("service", c.id, { title: `${c.name}: history` });
          cell.appendChild(card || h("p", { class: "hint" }, "No measurements yet. They appear after the first checks."));
        };
        if (openGraphs.has(c.id)) showGraph();
        c._toggle = () => {
          const open = graphRow.hidden;
          graphRow.hidden = !open;
          if (open) { openGraphs.add(c.id); showGraph(); } else openGraphs.delete(c.id);
          return open;
        };
        return graphRow;
      },
      line: (c, tr) => {
        tr.classList.add("svc-line");
        tr.title = "Click for the history graph";
        const btn = tr.querySelector("[data-graph]");
        btn.addEventListener("click", () => btn.setAttribute("aria-expanded", String(c._toggle())));
        // a click on the line opens the graph, except on a link, a button or the heartbeat bar (those have their own meaning)
        tr.addEventListener("click", (e) => { if (!e.target.closest("a, button, input, select, .hb-bar, .rl, .row-menu, .actions")) btn.click(); });
      },
    });
    if (!wrap) wrap = h("div", { class: "table-wrap" }, tv.table);
    patchDom(tv.tbody, lines);
    patchDom(body, wrap);
  }

  async function load() {
    let checks;
    try {
      checks = (await get("/api/service-checks")).sort((a, b) => (b.enabled && b.state === "down") - (a.enabled && a.state === "down"));          // the checks that fail come first
    } catch (err) {
      if (!destroyed) body.replaceChildren(h("p", { class: "error" }, err.message || "Failed to load"));
      return;
    }
    let plugins = [];
    try { plugins = await get("/api/plugin-runs"); } catch (err) { /* the plugins are an extra; the checks still show */ }
    if (destroyed) return;
    drawTiles(checks);
    if (!checks.length && !plugins.length) {
      items = [];
      wrap = null;
      body.replaceChildren(emptyState("No checks yet", "Add one to watch a web page, a port or a DNS server. Typical examples: your router's web page (HTTP), your NAS on port 445 (TCP), your DNS server resolving example.com (DNS).", h("button", { class: "btn primary admin-only", type: "button", onclick: () => addBtn.click() }, "Add check")));
      return;
    }
    // the history bars are fetched first and built into the rows, so a refresh that changed nothing leaves the rows exactly as they are
    const bars = await Promise.all(checks.map(heartbeats));
    if (destroyed) return;
    const plugs = plugins.map((p) => ({ plugin: true, id: `p${p.id}`, series_id: p.series_id, enabled: true, state: p.state, name: p.name, last_detail: p.last_detail, kind: p.kind || "", target: "", uptime_24h: p.uptime_24h,
      last_ms: p.last_ms, last_ts: p.last_ts, bars: heartbeatBar(p.beats.map((r) => ({ ts: r.ts, up: r.up, rtt_ms: r.ms })), 60) }));
    items = [...checks.map((c, i) => ({ ...c, bars: bars[i] })), ...plugs];
    draw();
  }

  await load();
  const timer = setInterval(() => { if (!destroyed && !document.hidden && !formSlot.firstChild) load(); }, 15000);
  return () => { destroyed = true; clearInterval(timer); };
}
