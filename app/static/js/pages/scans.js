import { get } from "../api.js";
import { h, clear, fmtTime, timeAgo } from "../util.js";
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

function truncate(text, max = 40) {
  if (!text) return "";
  const s = String(text);
  return s.length > max ? s.slice(0, max) + "…" : s;
}

export async function render(container, params) {
  clear(container);

  let tab = "events";
  try { if (localStorage.getItem("netlens.scans.tab") === "scans") tab = "scans"; } catch (e) { /* default */ }
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

  grid.appendChild(eventsCard);
  grid.appendChild(scansCard);
  const showTab = () => {
    eventsCard.hidden = tab !== "events";
    scansCard.hidden = tab !== "scans";
    for (const b of tabs.querySelectorAll("button")) { b.classList.toggle("active", b.dataset.tab === tab); b.setAttribute("aria-selected", String(b.dataset.tab === tab)); }
  };
  for (const [key, label] of [["events", "Events"], ["scans", "Scans"]]) {
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

        const errText = truncate(scan.error);
        const errCell = h("td", { class: "muted" }, errText);
        if (scan.error) errCell.title = scan.error;
        row.appendChild(errCell);

        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      scansBody.appendChild(table);
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

  intervalId = setInterval(() => { if (!document.hidden) refresh(); }, 10000);

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