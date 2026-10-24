import { get } from "../api.js";
import { h, clear, timeAgo } from "../util.js";
import { pageHead, tile as uiTile, tileRow, emptyState } from "../ui.js";

const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];
export function bytes(n) {
  if (n === null || n === undefined) return "";
  let v = n, i = 0;
  while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i += 1; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${UNITS[i]}`;
}

const TYPE = { vm: "VM", ct: "Container", host: "Host", other: "Other" };
const JOBS = [["gc", "Garbage collection"], ["prune", "Prune"], ["verify", "Verify"], ["sync", "Sync"]];

function age(seconds) {
  if (seconds === null || seconds === undefined) return "never";
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

function stateText(t) {
  if (t.last_state === "failed") return h("span", { class: "error" }, "Last backup failed");
  if (t.late) return h("span", { class: "warn-text" }, "Late");
  if (t.last_state === "warning") return h("span", { class: "warn-text" }, "Warnings");
  return h("span", { class: "run-ok" }, "OK");
}

function jobCell(state, at) {
  if (state === "none") return h("span", { class: "hint" }, "never ran");
  return h("span", { class: state === "ok" ? "run-ok" : state === "warning" ? "warn-text" : "error" }, `${state === "ok" ? "OK" : state === "warning" ? "Warnings" : "Failed"} · ${timeAgo(at)}`);
}

function storeCard(s, server) {
  const bar = h("div", { class: "usage-bar", role: "img", "aria-label": `${s.percent ?? "?"} percent used` }, h("div", { class: `usage-fill ${s.level === "critical" ? "bad" : s.level === "warning" ? "warn" : ""}`, style: `width:${Math.min(100, s.percent || 0)}%` }));
  const full = s.days_to_full === null ? "no estimate yet" : s.days_to_full > 730 ? "not in the next two years" : `in about ${s.days_to_full} day${s.days_to_full === 1 ? "" : "s"}`;
  const card = h("div", {}, h("h4", {}, `${s.name}`, h("span", { class: "hint" }, ` on ${server ? server.name : s.server_id}`)), bar,
    h("p", {}, `${bytes(s.used)} of ${bytes(s.total)} used${s.percent !== null ? ` (${s.percent}%)` : ""} · expected to be full ${full}`));
  const table = h("table", { class: "data plist" });
  for (const [key, label] of JOBS) {
    if (s[`${key}_state`] === "none" && key !== "gc" && key !== "prune") continue;
    table.appendChild(h("tr", {}, h("td", {}, label), h("td", {}, jobCell(s[`${key}_state`], s[`${key}_at`]))));
  }
  card.appendChild(table);
  if (s.verify_state === "none") card.appendChild(h("p", { class: "hint" }, "No verification job has run: backups are never checked for damage. Add one in Proxmox Backup Server (Datastore → Verify Jobs)."));
  return card;
}

const openServers = new Set();

function targetsTable(targets) {
  const table = h("table", { class: "data" });
  table.appendChild(h("thead", {}, h("tr", {}, ...["Name", "Type", "State", "Newest backup", "Copies", "Size", "Verified", "Guest"].map((c) => h("th", {}, c)))));
  const tbody = h("tbody");
  const order = { failed: 0, warning: 1, ok: 2 };
  for (const t of [...targets].sort((a, b) => (b.late - a.late) || (order[a.last_state] ?? 3) - (order[b.last_state] ?? 3) || a.name.localeCompare(b.name))) {
    const guest = t.device_id ? h("a", { href: `#/device/${t.device_id}` }, t.device || "device") : h("span", { class: "hint" }, t.matched ? "known guest" : (t.type === "vm" || t.type === "ct") ? "no such guest now" : "");
    tbody.appendChild(h("tr", {}, h("td", {}, t.name, t.type === "vm" || t.type === "ct" ? h("span", { class: "hint" }, ` (${t.backup_id})`) : ""), h("td", {}, TYPE[t.type] || t.type),
      h("td", {}, stateText(t)), h("td", { title: t.last_backup || "" }, age(t.age_s)), h("td", {}, String(t.count)), h("td", {}, bytes(t.last_size)),
      h("td", {}, t.verify_state === "ok" ? "yes" : t.verify_state === "failed" ? h("span", { class: "error" }, "failed") : h("span", { class: "hint" }, "never")), h("td", {}, guest)));
  }
  table.appendChild(tbody);
  return h("div", { class: "table-wrap" }, table);
}

function serverRows(v, data) {
  const mine = (list) => list.filter((x) => x.plugin_id === v.plugin_id && x.server_id === v.id);
  const key = `${v.plugin_id}/${v.id}`;
  const stores = mine(data.stores), targets = mine(data.targets), problems = mine(data.problems);
  const failed = targets.filter((t) => t.last_state === "failed").length, late = targets.filter((t) => t.late).length;
  const atRisk = stores.filter((x) => x.level !== "ok").length;
  const full = stores.reduce((m, x) => (x.percent !== null && (m === null || x.percent > m.percent) ? x : m), null);
  const newest = targets.map((t) => t.last_backup).filter(Boolean).sort().pop();
  const state = !v.online ? h("span", { class: "error" }, "Offline") : failed ? h("span", { class: "error" }, "Failed") : late || atRisk || v.warnings.length ? h("span", { class: "warn-text" }, "Attention") : h("span", { class: "run-ok" }, "OK");
  const expanded = openServers.has(key);
  const row = h("tr", { class: "clickable", tabindex: "0", role: "button", "aria-expanded": String(expanded) },
    h("td", {}, expanded ? "▾" : "▸"), h("td", {}, state),
    h("td", {}, h("strong", {}, v.name), v.version ? h("span", { class: "hint" }, ` · ${v.version}`) : null),
    h("td", {}, full ? h("span", {}, `${full.percent}%`, h("div", { class: "usage-bar", role: "img", "aria-label": `${full.percent} percent used` }, h("div", { class: `usage-fill ${full.level === "critical" ? "bad" : full.level === "warning" ? "warn" : ""}`, style: `width:${Math.min(100, full.percent)}%` }))) : h("span", { class: "hint" }, "–")),
    h("td", {}, String(targets.length)), h("td", {}, failed ? h("span", { class: "error" }, String(failed)) : "0"), h("td", {}, late ? h("span", { class: "warn-text" }, String(late)) : "0"),
    h("td", { title: newest || "" }, newest ? timeAgo(newest) : "never"));
  const box = h("div", { class: "storage-detail" });
  for (const w of v.warnings) box.appendChild(h("p", { class: "warn-text" }, w));
  if (v.device_id) box.appendChild(h("p", {}, "Device: ", h("a", { href: `#/device/${v.device_id}` }, v.device || "device")));
  for (const st of stores) box.appendChild(storeCard(st, v));
  if (targets.length) { box.appendChild(h("h4", {}, `Backed up (${targets.length})`)); box.appendChild(targetsTable(targets)); }
  if (problems.length) {
    box.appendChild(h("h4", {}, `Recent problems (${problems.length})`));
    const list = h("ul", {});
    for (const p of problems.slice(0, 30)) list.appendChild(h("li", {}, h("span", { class: p.state === "failed" ? "error" : "warn-text" }, p.state === "failed" ? "Failed " : "Warning "), `${timeAgo(p.at)}: ${p.text}`));
    box.appendChild(list);
  }
  const more = h("tr", { class: "storage-more" }, h("td", { colspan: "8" }, box));
  more.hidden = !expanded;
  const toggle = () => {
    const now = more.hidden;
    more.hidden = !now;
    if (now) openServers.add(key); else openServers.delete(key);
    row.setAttribute("aria-expanded", String(now));
    row.firstChild.textContent = now ? "▾" : "▸";
  };
  row.addEventListener("click", (e) => { if (!e.target.closest("a")) toggle(); });
  row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  return [row, more];
}

// The backups of all remote sites in one table (the roll-up of the locations that run a backup plugin).
function siteRollup(sites) {
  const card = h("div", { class: "card" }, h("h3", {}, `Remote sites (${sites.length})`),
    h("p", { class: "hint" }, "The backups of every remote site that has a backup plugin, in one place. Open a site for its devices and checks."));
  const table = h("table", { class: "data" });
  table.appendChild(h("thead", {}, h("tr", {}, ...["Site", "Guests with a backup", "Failed", "Late", "Stores filling up", "Newest backup", "Needs attention"].map((c) => h("th", {}, c)))));
  const tbody = h("tbody");
  const rank = (x) => (x.failed ? 0 : x.late || x.unprotected || x.stores_at_risk ? 1 : 2);
  for (const x of [...sites].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name))) {
    const names = x.attention.slice(0, 4).map((a) => `${a.name} (${a.state})`).join(", ") + (x.attention.length > 4 ? `, +${x.attention.length - 4} more` : "");
    tbody.appendChild(h("tr", {}, h("td", {}, h("a", { href: `#/remote-sites?id=${x.id}` }, x.name)),
      h("td", {}, `${x.protected} / ${x.guests}`, x.unprotected ? h("span", { class: "warn-text" }, ` · ${x.unprotected} without`) : ""),
      h("td", {}, x.failed ? h("span", { class: "error" }, String(x.failed)) : "0"), h("td", {}, x.late ? h("span", { class: "warn-text" }, String(x.late)) : "0"),
      h("td", {}, x.stores_at_risk ? h("span", { class: "warn-text" }, String(x.stores_at_risk)) : "0"),
      h("td", { title: x.newest || "" }, x.newest ? timeAgo(x.newest) : "never"), h("td", { class: "hint" }, names || "–")));
  }
  table.appendChild(tbody);
  card.appendChild(h("div", { class: "table-wrap" }, table));
  return card;
}

export async function render(container) {
  let destroyed = false;
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(pageHead("Backups", "What your backup server holds for each guest. It comes from a backup plugin (Plugin store)."), body);

  async function load() {
    let data;
    try {
      data = await get("/api/guest-backups");
    } catch (err) {
      if (!destroyed) { clear(body); body.appendChild(h("p", { class: "error" }, err.message || "Could not load the backups.")); }
      return;
    }
    if (destroyed) return;
    clear(body);
    const sitesCard = (data.sites || []).length ? siteRollup(data.sites) : null;
    if (!data.servers.length && sitesCard) {
      body.appendChild(sitesCard);
      return;
    }
    if (!data.servers.length) {
      body.appendChild(emptyState("No backup server is connected yet", "Install a backup plugin (for example Proxmox Backup Server) from the Plugin store and turn it on. Netlens then shows the newest backup of every guest, warns when one fails or is late, and lists the guests that have no backup.", h("a", { class: "btn primary", href: "#/settings/plugin-browse" }, "Open the Plugin store")));
      return;
    }
    if (sitesCard) body.appendChild(sitesCard);
    const s = data.summary;
    const tiles = tileRow();
    const tile = (label, value, tone) => uiTile(label, value, "", tone);
    tiles.append(tile("guests with a backup", `${s.protected} / ${s.guests}`, s.unprotected ? "warn" : ""), tile("last backup failed", s.failed, s.failed ? "bad" : ""),
      tile("not backed up on time", s.late, s.late ? "warn" : ""), tile("stores filling up", s.stores_at_risk, s.stores_at_risk ? "warn" : ""));
    body.appendChild(tiles);

    const st = h("table", { class: "data" });
    st.appendChild(h("thead", {}, h("tr", {}, ...["", "State", "Backup server", "Fullest store", "Backed up", "Failed", "Late", "Newest backup"].map((c) => h("th", {}, c)))));
    const sb = h("tbody");
    for (const v of data.servers) for (const r of serverRows(v, data)) sb.appendChild(r);
    st.appendChild(sb);
    body.appendChild(h("div", { class: "card" }, h("p", { class: "hint" }, "Click a backup server to see its stores, what it holds for each guest and its recent problems."), h("div", { class: "table-wrap" }, st)));

    if (data.unprotected.length) {
      const card = h("div", { class: "card" }, h("h3", {}, `Guests without a backup (${data.unprotected.length})`),
        h("p", { class: "hint" }, "Virtual machines and containers of your hypervisors that the backup server has no backup for. Check the backup jobs of your hypervisor."));
      const list = h("ul", {});
      for (const g of data.unprotected) {
        const name = g.device_id ? h("a", { href: `#/device/${g.device_id}` }, g.name) : h("span", {}, g.name);
        list.appendChild(h("li", {}, name, h("span", { class: "hint" }, ` · ${g.kind === "lxc" || g.kind === "ct" ? "container" : "VM"} ${g.guest_id} · ${g.status}`)));
      }
      card.appendChild(list);
      body.appendChild(card);
    }

  }

  await load();
  const timer = setInterval(() => { if (!document.hidden) load(); }, 60000);
  return () => { destroyed = true; clearInterval(timer); };
}
