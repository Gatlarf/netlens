import { get } from "../api.js";
import { h, clear, timeAgo } from "../util.js";

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
  const card = h("div", { class: "card" }, h("h3", {}, `${s.name}`, h("span", { class: "hint" }, ` on ${server ? server.name : s.server_id}`)), bar,
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

export async function render(container) {
  let destroyed = false;
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(h("div", { class: "toolbar" }, h("strong", {}, "Backups"), h("span", { class: "hint" }, "What your backup server holds for each guest. It comes from a backup plugin (Plugin store).")), body);

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
    if (!data.servers.length) {
      body.appendChild(h("div", { class: "card" }, h("p", {}, "No backup server is connected yet."),
        h("p", { class: "hint" }, "Install the ", h("a", { href: "#/settings/plugin-browse" }, "Proxmox Backup Server plugin"), " from the Plugin store and turn it on. Netlens then shows the newest backup of every guest, warns when one fails or is late, and lists the guests that have no backup.")));
      return;
    }
    const s = data.summary;
    const servers = Object.fromEntries(data.servers.map((x) => [x.id, x]));
    const tiles = h("div", { class: "card-row" });
    const tile = (label, value, tone) => h("div", { class: `card tile ${tone || ""}` }, h("div", { class: "tile-value" }, String(value)), h("div", { class: "hint" }, label));
    tiles.append(tile("guests with a backup", `${s.protected} / ${s.guests}`, s.unprotected ? "warn" : ""), tile("last backup failed", s.failed, s.failed ? "bad" : ""),
      tile("not backed up on time", s.late, s.late ? "warn" : ""), tile("stores filling up", s.stores_at_risk, s.stores_at_risk ? "warn" : ""));
    body.appendChild(tiles);

    for (const v of data.servers) for (const w of v.warnings) body.appendChild(h("p", { class: "warn-text" }, `${v.name}: ${w}`));
    for (const st of data.stores) body.appendChild(storeCard(st, servers[st.server_id]));

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

    const card = h("div", { class: "card" }, h("h3", {}, `Backed up (${data.targets.length})`));
    const table = h("table", { class: "data" });
    table.appendChild(h("thead", {}, h("tr", {}, ...["Name", "Type", "State", "Newest backup", "Copies", "Size", "Verified", "Guest"].map((c) => h("th", {}, c)))));
    const tbody = h("tbody");
    const order = { failed: 0, warning: 1, ok: 2 };
    for (const t of [...data.targets].sort((a, b) => (b.late - a.late) || (order[a.last_state] ?? 3) - (order[b.last_state] ?? 3) || a.name.localeCompare(b.name))) {
      const guest = t.device_id ? h("a", { href: `#/device/${t.device_id}` }, t.device || "device") : h("span", { class: "hint" }, t.matched ? "known guest" : (t.type === "vm" || t.type === "ct") ? "no such guest now" : "");
      tbody.appendChild(h("tr", {}, h("td", {}, t.name, t.type === "vm" || t.type === "ct" ? h("span", { class: "hint" }, ` (${t.backup_id})`) : ""), h("td", {}, TYPE[t.type] || t.type),
        h("td", {}, stateText(t)), h("td", { title: t.last_backup || "" }, age(t.age_s)), h("td", {}, String(t.count)), h("td", {}, bytes(t.last_size)),
        h("td", {}, t.verify_state === "ok" ? "yes" : t.verify_state === "failed" ? h("span", { class: "error" }, "failed") : h("span", { class: "hint" }, "never")), h("td", {}, guest)));
    }
    table.appendChild(tbody);
    card.appendChild(h("div", { class: "table-wrap" }, table));
    body.appendChild(card);

    if (data.problems.length) {
      const pcard = h("div", { class: "card" }, h("h3", {}, `Recent problems (${data.problems.length})`));
      const list = h("ul", {});
      for (const p of data.problems.slice(0, 30)) list.appendChild(h("li", {}, h("span", { class: p.state === "failed" ? "error" : "warn-text" }, p.state === "failed" ? "Failed " : "Warning "), `${timeAgo(p.at)}: ${p.text}`));
      pcard.appendChild(list);
      body.appendChild(pcard);
    }
  }

  await load();
  const timer = setInterval(() => { if (!document.hidden) load(); }, 60000);
  return () => { destroyed = true; clearInterval(timer); };
}
