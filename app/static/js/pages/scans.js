import { get } from "../api.js";
import { h, clear, fmtTime, timeAgo, isAdmin } from "../util.js";
import { makeResizable } from "../colresize.js";
import { pageHead } from "../ui.js";
import { EVENT_LABELS as KIND_LABELS, eventLabel } from "../event_labels.js";

const KIND_ORDER = [
  "device_new",
  "device_online",
  "device_offline",
  "ip_changed",
  "port_opened",
  "port_closed",
  "port_unexpected",
  "port_missing",
  "wake_sent",
  "os_changed",
  "host_timeout",
  "device_deleted",
  "ip_reused",
  "wifi_roamed",
  "service_down",
  "service_up",
  "metric_warning",
  "metric_critical",
  "metric_ok",
  "capacity_warning",
  "capacity_critical",
  "anomaly",
  "remote_new",
  "remote_offline",
  "remote_online",
  "remote_service_down",
  "remote_service_up",
  "remote_metric_warning",
  "remote_metric_critical",
  "remote_metric_ok",
  "probe_offline",
  "probe_online",
  "backup_failed",
  "dhcp_rogue",
  "gateway_changed",
  "login_failed",
  "cert_expiring"
];

function statusClass(status) {
  if (status === "done") return "ok";
  if (status === "failed") return "bad";
  if (status === "running" || status === "cancelled") return "warn";
  return "";
}

function duration(started, finished) {
  if (!started || !finished) return "—";
  const start = new Date(started);
  const end = new Date(finished);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "—";
  const ms = end.getTime() - start.getTime();
  if (ms < 0) return "—";
  const totalSec = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSec / 60);
  const seconds = totalSec % 60;
  if (minutes > 0) {
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  }
  return `${seconds}s`;
}

export async function render(container, params) {
  clear(container);

  let tab = "events";
  try { const saved = localStorage.getItem("netlens.scans.tab"); if (saved === "scans" || (saved === "system" && isAdmin())) tab = saved; } catch (e) { /* default */ }
  const tabs = h("nav", { class: "dev-tabs", role: "tablist", "aria-label": "Events or scans" });
  const grid = h("div", { class: "scan-panels" });

  // Left card: Scans
  const scansCard = h("div", { class: "card" });
  const scansTitle = h("h2", { class: "card-title" }, "Scans");
  scansTitle.hidden = true;
  const scansBody = h("div", { class: "card-body" });
  scansCard.appendChild(scansTitle);
  scansCard.appendChild(scansBody);

  // Right card: Events
  const eventsCard = h("div", { class: "card" });
  const eventsTitle = h("h2", { class: "card-title" }, "Events");
  eventsTitle.hidden = true;
  const filterRow = h("div", { class: "filter-row" });
  const select = h("select", { class: "kind-filter" });
  const allOption = h("option", { value: "" }, "All");
  select.appendChild(allOption);
  for (const kind of KIND_ORDER) {
    const opt = h("option", { value: kind }, KIND_LABELS[kind] || kind);
    select.appendChild(opt);
  }
  filterRow.appendChild(select);
  const eventsBody = h("div", { class: "card-body" });
  eventsCard.appendChild(eventsTitle);
  eventsCard.appendChild(filterRow);
  eventsCard.appendChild(eventsBody);

  // Third card: the log of the application itself (administrators)
  const sysCard = h("div", { class: "card" });
  const sysBody = h("div", { class: "card-body" });
  const sysLevel = h("select", { class: "kind-filter", "aria-label": "Level" }, h("option", { value: "error" }, "Errors"), h("option", { value: "warning" }, "Warnings and errors"), h("option", { value: "info" }, "Everything (information too)"));
  sysLevel.value = "warning";
  const sysSearch = h("input", { type: "search", placeholder: "Search the log", "aria-label": "Search the log", style: "min-width:14rem" });
  const sysDownload = h("a", { class: "btn", href: "/api/system-log/download", download: "netlens.log" }, "Download");
  sysCard.append(h("div", { class: "filter-row" }, sysLevel, sysSearch, sysDownload), sysBody);

  async function loadSystem() {
    try {
      const r = await get(`/api/system-log?level=${sysLevel.value}&q=${encodeURIComponent(sysSearch.value)}&limit=300`);
      clear(sysBody);
      if (!r.entries.length) {
        sysBody.appendChild(h("div", { class: "empty" }, r.files ? "Nothing at this level" + (sysSearch.value ? " matches the search" : "") + "." : "No system log yet: it starts with the next start of Netlens."));
      } else {
        const list = h("div", { class: "sys-log" });
        for (const e of r.entries) {
          list.appendChild(h("div", { class: `sys-line sys-${e.level}` }, h("span", { class: "sys-time", title: e.ts }, fmtTime(e.ts)), h("span", { class: "sys-level" }, e.level), h("span", { class: "sys-name" }, e.logger), h("span", { class: "sys-text" }, e.message)));
        }
        sysBody.appendChild(list);
      }
      sysBody.appendChild(h("p", { class: "hint" }, `The application's own log, newest first, kept across restarts (${r.files} file${r.files === 1 ? "" : "s"}, ${(r.bytes / 1024).toFixed(0)} KB, the oldest lines are dropped when it is full). The same lines appear in the container log (docker logs).`));
    } catch (err) {
      clear(sysBody);
      sysBody.appendChild(h("div", { class: "empty" }, "Failed to load the system log."));
    }
  }
  sysLevel.addEventListener("change", loadSystem);
  let sysTimer = null;
  sysSearch.addEventListener("input", () => { clearTimeout(sysTimer); sysTimer = setTimeout(loadSystem, 300); });

  grid.appendChild(eventsCard);
  grid.appendChild(scansCard);
  grid.appendChild(sysCard);
  const showTab = () => {
    eventsCard.hidden = tab !== "events";
    scansCard.hidden = tab !== "scans";
    sysCard.hidden = tab !== "system";
    if (tab === "system") loadSystem();
    for (const b of tabs.querySelectorAll("button")) { b.classList.toggle("active", b.dataset.tab === tab); b.setAttribute("aria-selected", String(b.dataset.tab === tab)); }
  };
  for (const [key, label] of [["events", "Events"], ["scans", "Scans"], ...(isAdmin() ? [["system", "System log"]] : [])]) {
    tabs.appendChild(h("button", { type: "button", role: "tab", class: "dev-tab", "data-tab": key, onclick: () => { tab = key; try { localStorage.setItem("netlens.scans.tab", key); } catch (e) { /* not remembered */ } showTab(); } }, label));
  }
  showTab();
  container.appendChild(pageHead("Scans & events", "What happened on the network (events) and the scans that look for it. Both refresh by themselves."));
  container.appendChild(tabs);
  container.appendChild(grid);

  let intervalId = null;
  let listenerAttached = false;

  async function loadScans() {
    clear(scansBody);
    try {
      const scans = await get("/api/scans?limit=50");
      if (!scans || !scans.length) {
        scansBody.appendChild(h("div", { class: "empty" }, "No scans yet."));
        return;
      }
      // the newest scan failed because the container misses NET_RAW / NET_ADMIN or the host network: say what to do, in full
      const newest = scans[0];
      if (newest && newest.status === "failed" && /^A container setting is missing/.test(newest.error || "")) {
        scansBody.appendChild(h("div", { class: "card error" }, h("h2", {}, "The last scan could not run: a container setting is missing"),
          h("p", {}, "Netlens needs the host network and two extra capabilities, ", h("code", {}, "NET_RAW"), " and ", h("code", {}, "NET_ADMIN"), ", on its container. They are settings of the container, not of Netlens:"),
          h("ul", {},
            h("li", {}, "In a compose file or stack: in the ", h("code", {}, "netlens:"), " service add ", h("code", {}, "network_mode: host"), " and a ", h("code", {}, "cap_add:"), " list with ", h("code", {}, "NET_RAW"), " and ", h("code", {}, "NET_ADMIN"), " (same indentation as ", h("code", {}, "image:"), ")."),
            h("li", {}, "In Portainer's container form: the ", h("em", {}, "Network"), " tab = host, and the ", h("em", {}, "Capabilities"), " tab: switch NET_RAW and NET_ADMIN on."),
            h("li", {}, "On a Synology: use a Project (compose file); the container wizard cannot set capabilities."),
            h("li", {}, "Do not use ", h("code", {}, "no-new-privileges"), ". A running container does not pick up new capabilities: re-create it (stack: Update the stack).")),
          h("p", {}, h("a", { href: "https://www.home.codeshrimp.com/docs/netlens/install/where-do-net-raw-and-net-admin-go/", target: "_blank", rel: "noopener" }, "Step-by-step instructions for Portainer, Synology and compose"))));
      }
      const table = h("table", { class: "data" });
      const thead = h("thead");
      const headRow = h("tr");
      headRow.appendChild(h("th", {}, "Started"));
      headRow.appendChild(h("th", {}, "Kind"));
      headRow.appendChild(h("th", {}, "Status"));
      headRow.appendChild(h("th", {}, "Hosts found"));
      headRow.appendChild(h("th", {}, "Duration"));
      headRow.appendChild(h("th", {}, "Error"));
      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = h("tbody");
      for (const scan of scans) {
        const row = h("tr");
        row.appendChild(h("td", {}, fmtTime(scan.started)));
        row.appendChild(h("td", {}, scan.target ? `${scan.kind} ${scan.target}` : scan.kind));

        const statusCell = h("td", { class: statusClass(scan.status) }, scan.status);
        row.appendChild(statusCell);

        row.appendChild(h("td", {}, String(scan.hosts_found ?? 0)));
        row.appendChild(h("td", {}, duration(scan.started, scan.finished)));

        const errCell = h("td", { class: "muted col-text" }, scan.error || "");          // all of it: it wraps in the space the column has (drag a heading edge to give it more)
        if (scan.error) errCell.title = scan.error;
        row.appendChild(errCell);

        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      makeResizable(table, "scans");
      scansBody.appendChild(h("div", { class: "table-wrap" }, table));
    } catch (err) {
      scansBody.appendChild(h("div", { class: "empty" }, "Failed to load scans."));
    }
  }

  async function loadEvents() {
    clear(eventsBody);
    try {
      const kind = select.value;
      const url = kind ? `/api/events?limit=200&kind=${encodeURIComponent(kind)}` : "/api/events?limit=200";
      const events = await get(url);
      if (!events || !events.length) {
        eventsBody.appendChild(h("div", { class: "empty" }, "No events."));
        return;
      }
      const list = h("ul", { class: "event-list" });
      for (const ev of events) {
        const li = h("li", { class: "event-item" });

        const timeEl = h("span", { class: "event-time" }, timeAgo(ev.ts));
        timeEl.title = fmtTime(ev.ts);
        li.appendChild(timeEl);

        const label = h("span", { class: `event-kind ${ev.kind}` }, eventLabel(ev.kind));
        li.appendChild(label);
        if (ev.maintenance) li.appendChild(h("span", { class: "badge maint", title: "Held back by a maintenance window: not sent to e-mail or channels" }, `maintenance: ${ev.maintenance}`));

        const detail = h("span", { class: "event-detail" }, ev.detail || "");
        li.appendChild(detail);

        if (ev.device_id != null) {
          const link = h("a", { href: `#/device/${ev.device_id}`, class: "event-link" }, ev.device || `Device ${ev.device_id}`);
          li.appendChild(link);
        }

        list.appendChild(li);
      }
      eventsBody.appendChild(list);
    } catch (err) {
      eventsBody.appendChild(h("div", { class: "empty" }, "Failed to load events."));
    }
  }

  function refresh() {
    loadScans();
    loadEvents();
  }

  select.addEventListener("change", () => {
    loadEvents();
  });

  refresh();

  intervalId = setInterval(() => { if (!document.hidden) { refresh(); if (tab === "system" && document.activeElement !== sysSearch) loadSystem(); } }, 10000);

  const onScanFinished = () => {
    refresh();
  };
  window.addEventListener("netlens:scan-finished", onScanFinished);
  listenerAttached = true;

  return () => {
    if (intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
    if (listenerAttached) {
      window.removeEventListener("netlens:scan-finished", onScanFinished);
      listenerAttached = false;
    }
  };
}

export default render;