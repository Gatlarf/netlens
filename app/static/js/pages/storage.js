import { get } from "../api.js";
import { h, clear, timeAgo } from "../util.js";
import { pageHead, tile as uiTile, tileRow, emptyState } from "../ui.js";
import { bytes } from "./backups.js";

const TONE = { critical: "error", warning: "warn-text", ok: "run-ok", unknown: "hint" };
const HEALTH = { critical: "Critical", warning: "Warning", ok: "Healthy", unknown: "Unknown" };
const DISK = { failed: "Failed", degraded: "Degraded", spare: "Spare", ok: "OK", unknown: "Unknown" };

const health = (x) => h("span", { class: TONE[x] || "hint" }, HEALTH[x] || x);
const deviceLink = (id, name, fallback) => (id ? h("a", { href: `#/device/${id}` }, name || "device") : h("span", { class: "hint" }, fallback || ""));

function bar(percent, level) {
  return h("div", { class: "usage-bar", role: "img", "aria-label": `${percent ?? "?"} percent used` }, h("div", { class: `usage-fill ${level === "critical" ? "bad" : level === "warning" ? "warn" : ""}`, style: `width:${Math.min(100, percent || 0)}%` }));
}

function table(heads, rows) {
  const t = h("table", { class: "data" });
  t.appendChild(h("thead", {}, h("tr", {}, ...heads.map((c) => h("th", {}, c)))));
  const body = h("tbody");
  for (const r of rows) body.appendChild(h("tr", {}, ...r.map((c) => h("td", {}, c))));
  t.appendChild(body);
  return h("div", { class: "table-wrap" }, t);
}

const open = new Set();
let focused = false;          // "#/storage?focus=problems" opens the systems with a problem once

function detail(sys, data) {
  const mine = (list) => list.filter((x) => x.plugin_id === sys.plugin_id && x.system_id === sys.id);
  const box = h("div", { class: "storage-detail" });
  for (const w of sys.warnings) box.appendChild(h("p", { class: "warn-text" }, w));
  for (const p of mine(data.pools)) {
    box.appendChild(h("div", {}, h("strong", {}, p.name), h("span", { class: "hint" }, p.raid ? ` · ${p.raid}` : ""), " ", p.health === "ok" || p.health === "unknown" ? null : health(p.health),
      bar(p.percent, p.level), h("p", {}, `${bytes(p.used)} of ${bytes(p.total)} used${p.percent !== null ? ` (${p.percent}%)` : ""}`)));
  }
  const controllers = mine(data.controllers);
  if (controllers.length) {
    box.appendChild(h("h4", {}, "Controllers"));
    box.appendChild(table(["Name", "Address", "State", "Device"], controllers.map((c) => [c.name, [c.ip, c.mac].filter(Boolean).join(" · "), c.online ? health(c.health) : h("span", { class: "error" }, "Offline"), deviceLink(c.device_id, c.device, "not on the network list")])));
  }
  const volumes = mine(data.volumes);
  if (volumes.length) {
    box.appendChild(h("h4", {}, `Volumes and shares (${volumes.length})`));
    box.appendChild(h("p", { class: "hint" }, "The hosts that use a volume come from the storage system (NFS clients, iSCSI initiators). A host Netlens has scanned links to its device."));
    box.appendChild(table(["Name", "Type", "Used", "State", "Used by"], volumes.map((v) => [v.name, [v.kind, v.protocol].filter(Boolean).join(" · "),
      v.size ? `${bytes(v.used)} / ${bytes(v.size)}${v.percent !== null ? ` (${v.percent}%)` : ""}` : "", health(v.health),
      h("span", {}, ...v.clients.slice(0, 8).flatMap((c, i) => [i ? ", " : "", c.device_id ? deviceLink(c.device_id, c.device) : h("span", { class: "hint" }, c.ip)]), v.clients.length > 8 ? ` +${v.clients.length - 8} more` : "")])));
  }
  const disks = mine(data.disks);
  if (disks.length) {
    const bad = disks.filter((d) => d.state === "failed" || d.state === "degraded");
    box.appendChild(h("p", {}, `${disks.length} disk${disks.length === 1 ? "" : "s"}`, bad.length ? h("span", { class: "error" }, ` · ${bad.length} need attention`) : h("span", { class: "run-ok" }, " · all OK")));
    if (bad.length) box.appendChild(table(["Disk", "Slot", "Model", "Size", "State"], bad.map((d) => [d.name, d.slot, d.model, bytes(d.size), h("span", { class: d.state === "failed" ? "error" : "warn-text" }, DISK[d.state])])));
  }
  const alerts = mine(data.alerts);
  if (alerts.length) {
    box.appendChild(h("h4", {}, `Open alerts (${alerts.length})`));
    const list = h("ul", {});
    for (const a of alerts.slice(0, 50)) list.appendChild(h("li", {}, h("span", { class: a.severity === "critical" ? "error" : "warn-text" }, a.severity === "critical" ? "Critical " : "Warning "), a.at ? `${timeAgo(a.at)}: ` : "", a.text));
    box.appendChild(list);
  }
  if (sys.device_id) box.appendChild(h("p", {}, "Device: ", deviceLink(sys.device_id, sys.device)));
  return box;
}

function systemRows(sys, data) {
  const mine = (list) => list.filter((x) => x.plugin_id === sys.plugin_id && x.system_id === sys.id);
  const key = `${sys.plugin_id}/${sys.id}`;
  const pools = mine(data.pools), volumes = mine(data.volumes), disks = mine(data.disks), alerts = mine(data.alerts);
  const failed = disks.filter((d) => d.state === "failed" || d.state === "degraded").length;
  const top = pools.reduce((m, p) => (p.percent !== null && (m === null || p.percent > m.percent) ? p : m), null);
  const subtitle = [sys.vendor, sys.model, sys.version].filter(Boolean).join(" ");
  const bad = sys.health === "critical" || sys.health === "warning" || !sys.online || failed > 0 || alerts.length > 0 || pools.some((p) => p.level !== "ok" || p.health === "critical" || p.health === "warning");
  if (bad && !focused && /[?&]focus=problems/.test(location.hash)) open.add(key);
  const expanded = open.has(key);
  const row = h("tr", { class: `clickable${bad ? " has-problem" : ""}`, tabindex: "0", role: "button", "aria-expanded": String(expanded) },
    h("td", {}, expanded ? "▾" : "▸"),
    h("td", {}, health(sys.health), sys.online ? "" : h("span", { class: "error" }, " · offline")),
    h("td", {}, h("strong", {}, sys.name), subtitle ? h("span", { class: "hint" }, ` · ${subtitle}`) : null),
    h("td", {}, top ? h("span", {}, `${top.percent}%`, bar(top.percent, top.level)) : h("span", { class: "hint" }, "–")),
    h("td", {}, String(pools.length)), h("td", {}, String(volumes.length)),
    h("td", {}, String(disks.length), failed ? h("span", { class: "error" }, ` · ${failed} bad`) : null),
    h("td", {}, alerts.length ? h("span", { class: alerts.some((a) => a.severity === "critical") ? "error" : "warn-text" }, String(alerts.length)) : h("span", { class: "hint" }, "0")));
  const more = h("tr", { class: "storage-more" }, h("td", { colspan: "8" }, detail(sys, data)));
  more.hidden = !expanded;
  const toggle = () => {
    const now = more.hidden;
    more.hidden = !now;
    if (now) open.add(key); else open.delete(key);
    row.setAttribute("aria-expanded", String(now));
    row.firstChild.textContent = now ? "▾" : "▸";
  };
  row.addEventListener("click", (e) => { if (!e.target.closest("a")) toggle(); });
  row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  return [row, more];
}

export async function render(container) {
  focused = false;
  let destroyed = false;
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(pageHead("Storage", "Your storage systems: pools, volumes, disks and who uses what. It comes from a storage plugin (Plugin store)."), body);

  let showProblems = () => {};

  let lastSig = "";
  async function load() {
    let data;
    try {
      data = await get("/api/storage");
    } catch (err) {
      if (!destroyed) { clear(body); body.appendChild(h("p", { class: "error" }, err.message || "Could not load the storage systems.")); }
      return;
    }
    if (destroyed) return;
    const sig = JSON.stringify(data);
    if (sig === lastSig) return;               // nothing changed: leave the page as it is (an opened row stays open)
    lastSig = sig;
    clear(body);
    if (!data.systems.length) {
      body.appendChild(emptyState("No storage system is connected yet", "Install a storage plugin from the Plugin store and turn it on. Netlens then shows pools, volumes and disks, tells you which hosts use which volume, and warns when a system, pool or disk becomes unhealthy or a pool fills up.", h("a", { class: "btn primary", href: "#/settings/plugin-browse" }, "Open the Plugin store")));
      return;
    }
    const s = data.summary;
    const tiles = tileRow();
    const show = (n) => (n ? () => showProblems() : null);
    tiles.append(uiTile("systems", s.systems, "", s.unhealthy ? "bad" : "", show(s.unhealthy)), uiTile("pools filling up or unhealthy", s.pools_filling, "", s.pools_filling ? "warn" : "", show(s.pools_filling)),
      uiTile("failed disks", s.failed_disks, "", s.failed_disks ? "bad" : "", show(s.failed_disks)), uiTile("open alerts", s.alerts, "", s.alerts ? "warn" : "", show(s.alerts)));
    body.appendChild(tiles);
    const t = h("table", { class: "data" });
    t.appendChild(h("thead", {}, h("tr", {}, ...["", "State", "System", "Fullest pool", "Pools", "Volumes", "Disks", "Alerts"].map((c) => h("th", {}, c)))));
    const tb = h("tbody");
    for (const sys of data.systems) for (const r of systemRows(sys, data)) tb.appendChild(r);
    if (!focused) { focused = true; if (/[?&]focus=problems/.test(location.hash)) setTimeout(() => showProblems(), 0); }
    t.appendChild(tb);
    showProblems = () => {
      const rows = [...tb.querySelectorAll("tr.has-problem")];
      for (const r of rows) if (r.getAttribute("aria-expanded") !== "true") r.click();
      if (rows[0]) rows[0].scrollIntoView({ behavior: "smooth", block: "start" });
    };
    body.append(h("p", { class: "hint" }, "Click a system to see its pools, controllers, volumes, disks and alerts."), h("div", { class: "table-wrap" }, t));
  }

  await load();
  const timer = setInterval(() => { if (!document.hidden) load(); }, 60000);
  return () => { destroyed = true; clearInterval(timer); };
}
