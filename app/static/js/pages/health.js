import { get, put } from "../api.js";
import { snoozeMenu, wakeButton, untilText } from "../snooze.js";
import { h, clear, toast, statusDot, shortName, timeAgo, isAdmin } from "../util.js";
import { pageHead, emptyState } from "../ui.js";

const REFRESH_MS = 30000;
const METRIC_ORDER = ["cpu_pct", "mem_pct", "disk_pct", "temp_c", "battery_pct", "supply_pct", "on_battery", "storage_status", "sensor_fault", "service_stopped"];
const EVENT_ONLY = ["on_battery", "storage_status", "sensor_fault", "service_stopped"];       // no numbers to set: it is a problem as soon as it happens

const fmtRate = (bps) => (bps === null || bps === undefined ? "–" : bps >= 1e9 ? `${(bps / 1e9).toFixed(1)} Gbit/s` : bps >= 1e6 ? `${(bps / 1e6).toFixed(1)} Mbit/s` : `${Math.round(bps / 1e3)} kbit/s`);
const fmtUptime = (s) => (s === null || s === undefined ? "–" : s >= 86400 ? `${Math.floor(s / 86400)} d` : s >= 3600 ? `${Math.floor(s / 3600)} h` : `${Math.floor(s / 60)} min`);

function level(rule, value) {
  if (!rule || !rule.enabled || value === null || value === undefined) return "";
  const beyond = (limit) => limit !== null && limit !== undefined && (rule.low ? value <= limit : value >= limit);
  return beyond(rule.crit) ? "bad" : beyond(rule.warn) ? "warn" : "";
}

// a small horizontal meter with the number beside it
function meter(value, rule, label) {
  if (value === null || value === undefined) return h("span", { class: "hint" }, "–");
  const tone = level(rule, value);
  const fill = h("span", { class: `hl-fill ${tone}` });
  fill.style.width = `${Math.max(2, Math.min(100, value))}%`;
  return h("span", { class: "hl-meter", title: label || null }, h("span", { class: "hl-track" }, fill), h("span", { class: `hl-num ${tone}` }, `${Math.round(value)}%`));
}

export async function render(container) {
  let disposed = false, timer = null, data = null, rules = {};
  const tiles = h("div", { class: "up-tiles" });
  const problems = h("div", {});
  const list = h("div", {});
  const limitsSlot = h("div", {});
  let limitsOpen = false;      // kept when the page refreshes
  let filter = "";

  const tile = (title, value, sub, kind) => h("section", { class: `dcard ${kind ? `tone-${kind}` : ""}` }, h("h2", { class: "d-title" }, title),
    h("div", { class: "d-body" }, h("div", { class: "d-value" }, value), h("div", { class: "d-sub" }, sub)));

  function draw() {
    if (!data) return;
    clear(tiles); clear(problems); clear(list);
    const rows = data.monitors;
    const critical = rows.filter((r) => r.level === "critical").length;
    const warning = rows.filter((r) => r.level === "warning").length;
    const failing = rows.filter((r) => r.enabled && r.last_ok === false).length;
    tiles.append(
      tile("Monitored", String(rows.length), rows.length ? "devices whose health is read" : "none set up yet", ""),
      tile("Need attention", String(critical + warning), critical ? `${critical} critical, ${warning} warning` : warning ? `${warning} warning` : "everything within its limits", critical ? "bad" : warning ? "warn" : "ok"),
      tile("Cannot be read", String(failing), failing ? "check the login or the address" : "all readings work", failing ? "warn" : "ok"));
    if (!rows.length) {
      list.appendChild(emptyState("Nothing is monitored yet", "Open a device and choose “Set up health monitoring”. Switches, NAS boxes, printers and UPS units are read over SNMP; Linux servers over SSH. Netlens then draws processor, memory, disk and traffic graphs and warns when a disk fills up, a server runs hot or a UPS runs on battery. Nothing is installed on the devices.", h("a", { class: "btn primary", href: "#/devices" }, "Choose a device")));
      return;
    }
    if (data.problems.length) {
      const card = h("div", { class: "card" }, h("h2", {}, "Needs attention"));
      for (const p of data.problems) {
        card.appendChild(h("div", { class: "kv" },
          h("span", { class: "kv-label" }, h("span", { class: `hl-badge ${p.level === "critical" ? "bad" : "warn"}` }, p.level === "critical" ? "Critical" : "Warning"), " ", h("a", { href: `#/device/${p.device_id}` }, shortName(p.device))),
          h("span", {}, `${p.title}${p.label ? ` · ${p.label}` : ""}: ${p.metric === "service_stopped" ? "stopped" : p.metric === "storage_status" ? (p.level === "critical" ? "failed" : "degraded") : p.unit === "%" ? `${Math.round(p.value)}%` : p.unit === "°C" ? `${Math.round(p.value)} °C` : Math.round(p.value * 10) / 10}`, " ", h("span", { class: "hint" }, `since ${timeAgo(p.since)}`), " ",
            p.snoozed_until ? h("span", {}, h("span", { class: "hint" }, `snoozed for another ${untilText(p.snoozed_until)}`), " ", wakeButton(p.snooze)) : snoozeMenu(p.snooze))));
      }
      problems.appendChild(card);
    }
    const q = filter.trim().toLowerCase();
    const table = h("table", { class: "data hl-table" });
    table.appendChild(h("thead", {}, h("tr", {}, ["", "Device", "Processor", "Memory", "Disk (fullest) / supply", "Temp", "Traffic in / out", "Running", "Read"].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    for (const r of rows.filter((r) => !q || `${r.name} ${r.ip || ""}`.toLowerCase().includes(q))) {
      const l = r.latest;
      const cell = (...c) => h("td", {}, ...c);
      const state = !r.enabled ? "paused" : r.last_ok === false ? "bad" : r.level === "critical" ? "bad" : r.level === "warning" ? "warn" : "ok";
      body.appendChild(h("tr", { class: `hl-row hl-${state}` },
        cell(statusDot(r.online)),
        cell(h("a", { href: `#/device/${r.device_id}`, title: r.name }, shortName(r.name)), r.ip && r.ip !== r.name ? h("div", { class: "mono hint" }, r.ip) : null,
          r.last_ok === false ? h("div", { class: "hint error" }, r.last_error || "cannot be read") : null),
        cell(meter(l.cpu, rules.cpu_pct)), cell(meter(l.mem, rules.mem_pct)),
        l.disk === null && l.supply !== null
          ? cell(meter(l.supply, rules.supply_pct, l.supply_label), h("div", { class: "hint" }, `${l.supply_label || "supply"} left`))
          : cell(meter(l.disk, rules.disk_pct, l.disk_label || null), l.disk_label ? h("div", { class: "hint" }, l.disk_label) : null),
        cell(l.temp === null ? h("span", { class: "hint" }, "–") : h("span", { class: level(rules.temp_c, l.temp) }, `${Math.round(l.temp)} °C`)),
        cell(l.rx === null ? h("span", { class: "hint" }, "–") : h("span", { class: "mono" }, `${fmtRate(l.rx)} / ${fmtRate(l.tx)}`)),
        cell(fmtUptime(l.uptime)),
        cell(r.last_ts ? timeAgo(r.last_ts) : "never")));
    }
    table.appendChild(body);
    list.append(h("div", { class: "up-tools" }, h("input", { type: "text", placeholder: "Filter by name or IP", "aria-label": "Filter", value: filter, oninput: (e) => { filter = e.target.value; draw(); const i = list.querySelector("input"); if (i) { i.focus(); i.setSelectionRange(filter.length, filter.length); } } })),
      h("div", { class: "table-wrap" }, table));
  }

  function limitsCard() {
    clear(limitsSlot);
    const card = h("div", { class: "card" }, h("h2", {}, "When to warn"),
      h("p", { class: "hint" }, "A reading has to stay past a limit for a few rounds in a row before Netlens says anything, so a short peak is not an alarm. Warnings go through the notification channels (events: Health warning, Health critical, Health normal)."));
    const table = h("table", { class: "data" });
    table.appendChild(h("thead", {}, h("tr", {}, ["Reading", "Warn at", "Critical at", "On"].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    const inputs = {};
    for (const metric of METRIC_ORDER) {
      const r = rules[metric];
      if (!r) continue;
      const warn = h("input", { type: "number", step: "any", value: r.warn === null ? "" : String(r.warn), "aria-label": `${r.title} warning limit`, disabled: !isAdmin() });
      const crit = h("input", { type: "number", step: "any", value: r.crit === null ? "" : String(r.crit), "aria-label": `${r.title} critical limit`, disabled: !isAdmin() || EVENT_ONLY.includes(metric) });
      const on = h("input", { type: "checkbox", disabled: !isAdmin() });
      on.checked = r.enabled;
      inputs[metric] = { warn, crit, on };
      body.appendChild(h("tr", {}, h("td", {}, r.title, r.low ? h("span", { class: "hint" }, " (warns when it falls below the limit)") : null),
        h("td", {}, EVENT_ONLY.includes(metric) ? h("span", { class: "hint" }, "as soon as it happens") : warn, r.unit ? ` ${r.unit}` : ""), h("td", {}, EVENT_ONLY.includes(metric) ? "" : crit, r.unit && !EVENT_ONLY.includes(metric) ? ` ${r.unit}` : ""), h("td", {}, on)));
    }
    table.appendChild(body);
    const save = h("button", { class: "btn primary admin-only", type: "button" }, "Save limits");
    save.addEventListener("click", async () => {
      const payload = {};
      for (const [metric, f] of Object.entries(inputs)) {
        const num = (el) => (el.value === "" ? null : Number(el.value));
        payload[metric] = { enabled: f.on.checked };
        if (!EVENT_ONLY.includes(metric)) { payload[metric].warn = num(f.warn); payload[metric].crit = num(f.crit); }
      }
      save.disabled = true;
      try {
        rules = (await put("/api/monitoring/limits", { rules: payload })).rules;
        toast("Limits saved", "success");
        draw();
      } catch (err) {
        toast(err.message || "Could not save", "error");
      }
      save.disabled = false;
    });
    card.append(h("div", { class: "table-wrap" }, table), save);
    const heading = card.querySelector("h2");
    const folded = h("details", { class: "card health-limits", open: limitsOpen }, h("summary", {}, h("strong", {}, "When to warn"), h("span", { class: "hint" }, " the limits that raise a warning (admins can change them)")));
    folded.addEventListener("toggle", () => { limitsOpen = folded.open; });
    if (heading) heading.remove();
    folded.appendChild(card);
    limitsSlot.appendChild(folded);
  }

  const onSnoozed = () => { if (!disposed) load(); };
  document.addEventListener("netlens:snoozed", onSnoozed);
  async function load() {
    try {
      const [overview, limits] = await Promise.all([get("/api/monitors"), get("/api/monitoring/limits")]);
      if (disposed) return;
      data = overview;
      const first = !Object.keys(rules).length;
      rules = limits.rules;
      draw();
      if (first) limitsCard();
    } catch (err) {
      if (!disposed) toast("Failed to load the health overview", "error");
    }
  }

  clear(container);
  container.append(pageHead("Health", "Processor, memory, disks, temperature and network traffic of the devices Netlens reads over SNMP or SSH. Set a device up on its own page; click a name for the graphs."),
  tiles, problems, list, limitsSlot);
  list.append(h("p", { class: "hint" }, "Loading…"));
  await load();
  timer = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);   // a tab nobody looks at does not poll
  return () => { disposed = true; if (timer) clearInterval(timer); document.removeEventListener("netlens:snoozed", onSnoozed); };
}
