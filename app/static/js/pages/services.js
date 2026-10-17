import { get, post, patch, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";
import { pageHead, rowMenu } from "../ui.js";
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
    const rows = await get(`/api/service-checks/${check.id}/results?limit=60`);
    return heartbeatBar(rows.map((r) => ({ ts: r.ts, up: r.up, rtt_ms: r.ms })), 60);
  } catch (err) {
    return h("span", {});
  }
}

export async function render(container) {
  let destroyed = false;
  const openGraphs = new Set();      // checks whose graph is open (kept when the table is redrawn)
  const addBtn = h("button", { class: "btn primary admin-only", type: "button" }, "Add check");
  const top = pageHead("Services", "HTTP pages, TCP ports, DNS lookups, certificates and processes, checked at the interval you choose.", addBtn);
  const formSlot = h("div", {});
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(top, formSlot, body);

  async function showForm(check = null) {
    clear(formSlot);
    const card = h("div", { class: "card" }, h("h2", {}, check ? "Edit check" : "New check"));
    card.appendChild(await buildServiceForm({ check, onDone: (changed) => { clear(formSlot); if (changed) load(); } }));
    formSlot.appendChild(card);
    card.scrollIntoView({ block: "nearest" });
  }
  addBtn.addEventListener("click", () => showForm());

  async function load() {
    let checks;
    try {
      checks = await get("/api/service-checks");
    } catch (err) {
      if (!destroyed) body.replaceChildren(h("p", { class: "error" }, err.message || "Failed to load"));
      return;
    }
    if (destroyed) return;
    if (!checks.length) {
      body.replaceChildren(h("div", { class: "card" }, h("p", {}, "No checks yet. Add one to watch a web page, a port or a DNS server."),
        h("p", { class: "hint" }, "Typical examples: your router's web page (HTTP), your NAS on port 445 (TCP), your DNS server resolving example.com (DNS).")));
      return;
    }
    const table = h("table", { class: "data" });
    table.appendChild(h("thead", {}, h("tr", {}, ["", "Name", "Target", "Device", "History", "24 h", "Response", "Checked", ""].map((t) => h("th", {}, t)))));
    const tbody = h("tbody");
    for (const c of checks) {
      const hb = h("td", {});
      heartbeats(c).then((bar) => { if (!destroyed) hb.appendChild(bar); });
      const run = h("button", { class: "btn admin-only", type: "button" }, "Run now");
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
      const graphRow = h("tr", { class: "svc-graph-row", hidden: !openGraphs.has(c.id) }, h("td", { colspan: 9 }));
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
      tbody.appendChild(h("tr", {},
        h("td", {}, stateDot(c)), h("td", {}, c.name, c.state === "down" && c.last_detail ? h("div", { class: "hint" }, c.last_detail) : null),
        h("td", { class: "mono" }, c.target), h("td", {}, c.device_id ? h("a", { href: `#/device/${c.device_id}` }, c.device_name || `device ${c.device_id}`) : ""),
        hb, h("td", { class: uptimeClass(c.uptime_24h) }, uptimeText(c.uptime_24h)), h("td", {}, c.last_ms === null ? "–" : `${Math.round(c.last_ms)} ms`),
        h("td", {}, c.last_ts ? timeAgo(c.last_ts) : "never"), h("td", { class: "actions" }, run, graphBtn, more)));
      tbody.appendChild(graphRow);
    }
    table.appendChild(tbody);
    body.replaceChildren(h("div", { class: "table-wrap" }, table));
  }

  await load();
  const timer = setInterval(() => { if (!destroyed && !document.hidden && !formSlot.firstChild) load(); }, 15000);
  return () => { destroyed = true; clearInterval(timer); };
}
