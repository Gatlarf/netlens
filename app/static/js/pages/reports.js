import { get, put, post } from "../api.js";
import { h, clear, toast, isAdmin } from "../util.js";
import { pageHead } from "../ui.js";

// Reports: the weekly summary (text, as it is sent) and the monthly availability of devices and services.
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const monthName = (m) => `${MONTHS[Number(m.slice(5, 7)) - 1]} ${m.slice(0, 4)}`;
const pct = (v) => (v === null || v === undefined ? "–" : `${v}%`);
const tone = (v) => (v === null || v === undefined ? "" : v >= 99.9 ? "ok" : v >= 99 ? "" : v >= 95 ? "warn" : "bad");

function table(head, rows) {
  return h("div", { class: "rep-scroll" }, h("table", { class: "rep-table" },
    h("thead", {}, h("tr", {}, ...head.map((t) => h("th", {}, t)))),
    h("tbody", {}, ...rows.map((r) => h("tr", {}, ...r.map((c) => (c instanceof Node ? h("td", {}, c) : h("td", {}, c === null || c === undefined ? "" : String(c)))))))));
}

// what the monthly report covers, remembered in this browser
const FILTER_KEY = "netlens.reports.filter";
const DEFAULT_FILTER = { scope: "all", services: true, group: "", only_outages: false, target: "", hours: null, ignore: null };      // hours / ignore null: what the report settings say
function loadFilter() {
  try { return { ...DEFAULT_FILTER, ...JSON.parse(localStorage.getItem(FILTER_KEY) || "{}") }; } catch (e) { return { ...DEFAULT_FILTER }; }
}
function saveFilter(f) {
  try { localStorage.setItem(FILTER_KEY, JSON.stringify(f)); } catch (e) { /* the filter is then only kept while the page is open */ }
}
function filterQuery(month, f) {
  const q = new URLSearchParams();
  if (month) q.set("month", month);
  if (f.scope !== "all") q.set("scope", f.scope);
  if (!f.services) q.set("services", "false");
  if (f.group) q.set("group", f.group);
  if (f.only_outages) q.set("only_outages", "true");
  if (f.target !== "" && !Number.isNaN(Number(f.target))) q.set("target", String(f.target));
  if (f.hours) q.set("hours", f.hours);
  if (f.ignore !== null && f.ignore !== undefined) q.set("ignore_maintenance", String(f.ignore));
  const text = q.toString();
  return text ? `?${text}` : "";
}

// settings that both reports share: how many items the text lists, planned maintenance, business hours, and the monthly mail
function reportOptions(s) {
  const save = async (changes, redraw = true) => {
    try { await put("/api/reports/weekly/settings", changes); toast("Saved", "success"); if (redraw) drawAll(); } catch (err) { toast(err.message || "Could not save", "error"); }
  };
  const max = h("input", { type: "number", min: "1", max: "30", value: String(s.max_items), class: "rep-target" });
  max.addEventListener("change", () => save({ max_items: Number(max.value) }));
  const quiet = h("input", { type: "checkbox" });
  quiet.checked = s.ignore_maintenance;
  quiet.addEventListener("change", () => save({ ignore_maintenance: quiet.checked }));
  const hours = h("select", {}, h("option", { value: "all" }, "All hours"), h("option", { value: "business" }, "Business hours only"));
  hours.value = s.hours;
  hours.addEventListener("change", () => save({ hours: hours.value }));
  const names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const days = names.map((n, i) => { const b = h("input", { type: "checkbox" }); b.checked = s.business_days.includes(i); return [i, b, h("label", { class: "rep-part" }, b, ` ${n}`)]; });
  const hourSelect = (value, from, to) => h("select", {}, Array.from({ length: to - from + 1 }, (_, i) => h("option", { value: String(from + i) }, `${String(from + i).padStart(2, "0")}:00`)));
  const start = hourSelect(s.business_start, 0, 23), end = hourSelect(s.business_end, 1, 24);
  start.value = String(s.business_start);
  end.value = String(s.business_end);
  const saveBusiness = () => save({ business_days: days.filter(([, b]) => b.checked).map(([i]) => i), business_start: Number(start.value), business_end: Number(end.value) });
  for (const [, b] of days) b.addEventListener("change", saveBusiness);
  start.addEventListener("change", saveBusiness);
  end.addEventListener("change", saveBusiness);
  const monthly = h("input", { type: "checkbox" });
  monthly.checked = s.monthly;
  const mday = h("select", {}, Array.from({ length: 28 }, (_, i) => h("option", { value: String(i + 1) }, String(i + 1))));
  mday.value = String(s.monthly_day);
  const mhour = hourSelect(s.monthly_hour, 0, 23);
  mhour.value = String(s.monthly_hour);
  const mtarget = h("input", { type: "number", min: "0", max: "100", step: "0.1", placeholder: "e.g. 99.9", class: "rep-target", value: s.monthly_target === null ? "" : String(s.monthly_target) });
  monthly.addEventListener("change", () => save({ monthly: monthly.checked }, false));
  mday.addEventListener("change", () => save({ monthly_day: Number(mday.value) }, false));
  mhour.addEventListener("change", () => save({ monthly_hour: Number(mhour.value) }, false));
  mtarget.addEventListener("change", () => save({ monthly_target: mtarget.value === "" ? null : Number(mtarget.value) }, false));
  const send = h("button", { class: "btn", type: "button" }, "Send it now");
  send.addEventListener("click", async () => {
    send.disabled = true;
    try {
      const r = await post("/api/reports/monthly/send", {});
      toast(r.failed ? `Sent to ${r.sent}, failed for ${r.failed}: ${r.errors.join("; ")}` : `Sent to ${r.sent} channel(s)`, r.failed ? "error" : "success");
    } catch (err) {
      toast(err.message || "Could not send", "error");
    }
    send.disabled = false;
  });
  return h("details", { class: "rep-options" }, h("summary", {}, "More report settings"),
    h("div", { class: "rep-schedule" }, h("strong", {}, "List at most "), max, " outages, disks and problems in the text"),
    h("div", { class: "rep-schedule" }, h("strong", {}, "Count: "), hours, h("label", { class: "rep-part", title: "Leave out the checks that fall in a planned maintenance window (Settings → Maintenance windows)." }, quiet, " Leave out planned maintenance")),
    h("div", { class: "rep-schedule" }, h("strong", {}, "Business hours: "), ...days.map((d) => d[2]), start, " to ", end, h("span", { class: "hint" }, " (the time of the server)")),
    h("div", { class: "rep-schedule" }, h("label", { class: "rep-part" }, monthly, " Also send the report of the last month on day "), mday, " at ", mhour, " with target ", mtarget, " %", send),
    h("p", { class: "hint" }, "The monthly report goes to the notification channels that have “Monthly report” ticked (Settings → Alert channels), and follows the choices above."));
}

let drawAll = () => {};

export async function render(container) {
  let disposed = false;
  let month = null;
  const filter = loadFilter();
  const weeklySlot = h("div", {});
  const monthSlot = h("div", {});
  container.appendChild(h("div", { class: "rep-page" },
    pageHead("Reports", "The weekly report and the monthly availability figures, ready to send or print."),
    weeklySlot, monthSlot));

  async function drawWeekly() {
    let w;
    try {
      w = await get("/api/reports/weekly");
    } catch (err) {
      return;
    }
    if (disposed) return;
    clear(weeklySlot);
    const card = h("div", { class: "card" }, h("h2", {}, "Weekly report"),
      h("p", { class: "hint" }, "A summary of the last seven days in plain language: what was down and for how long, what is past a limit, which disks are filling up. This is the text that is sent."),
      h("pre", { class: "rep-text" }, `${w.title}\n\n${w.text}`));
    if (isAdmin()) {
      const enabled = h("input", { type: "checkbox" });
      enabled.checked = w.settings.enabled;
      const day = h("select", {}, w.days.map((d, i) => h("option", { value: String(i) }, d)));
      day.value = String(w.settings.day);
      const hour = h("select", {}, Array.from({ length: 24 }, (_, i) => h("option", { value: String(i) }, `${String(i).padStart(2, "0")}:00`)));
      hour.value = String(w.settings.hour);
      const save = async () => {
        try {
          await put("/api/reports/weekly/settings", { enabled: enabled.checked, day: Number(day.value), hour: Number(hour.value) });
          toast("Saved", "success");
        } catch (err) {
          toast(err.message || "Could not save", "error");
        }
      };
      for (const el of [enabled, day, hour]) el.addEventListener("change", save);
      // what the report covers: all devices or only the always-on ones, and which parts of the text
      const scope = h("select", {}, h("option", { value: "all" }, "All devices"), h("option", { value: "core" }, "Always-on devices only"));
      scope.value = w.settings.scope || "all";
      const parts = [["services", "Service checks"], ["new_devices", "New devices"], ["health", "Health readings past a limit"], ["disks", "Disks filling up"], ["sites", "Remote sites"]];
      const boxes = parts.map(([key, label]) => {
        const box = h("input", { type: "checkbox" });
        box.checked = w.settings[key] !== false;
        box.addEventListener("change", async () => {
          try { await put("/api/reports/weekly/settings", { [key]: box.checked }); drawWeekly(); } catch (err) { toast(err.message || "Could not save", "error"); }
        });
        return h("label", { class: "rep-part" }, box, ` ${label}`);
      });
      scope.addEventListener("change", async () => {
        try { await put("/api/reports/weekly/settings", { scope: scope.value }); drawWeekly(); } catch (err) { toast(err.message || "Could not save", "error"); }
      });
      card.append(h("div", { class: "rep-schedule" }, h("strong", {}, "Covers: "), scope), h("div", { class: "rep-schedule" }, h("strong", {}, "Include: "), ...boxes));
      card.appendChild(reportOptions(w.settings));
      const send = h("button", { class: "btn", type: "button" }, "Send it now");
      send.addEventListener("click", async () => {
        send.disabled = true;
        try {
          const r = await post("/api/reports/weekly/send", {});
          toast(r.failed ? `Sent to ${r.sent}, failed for ${r.failed}: ${r.errors.join("; ")}` : `Sent to ${r.sent} channel(s)`, r.failed ? "error" : "success");
        } catch (err) {
          toast(err.message || "Could not send", "error");
        }
        send.disabled = false;
      });
      card.append(h("div", { class: "rep-schedule" },
        h("label", {}, enabled, " Send it every "), day, " at ", hour, send),
      h("p", { class: "hint" }, "It goes to the notification channels that have “Weekly report” ticked (Settings → Notifications). The time is that of the server."));
    }
    weeklySlot.appendChild(card);
  }

  async function drawMonth() {
    let r;
    try {
      r = await get(`/api/reports/availability${filterQuery(month, filter)}`);
    } catch (err) {
      clear(monthSlot);
      monthSlot.appendChild(h("p", { class: "error" }, err.message || "The report could not be loaded"));
      return;
    }
    if (disposed) return;
    month = r.month;
    clear(monthSlot);
    const select = h("select", {}, r.months.map((m) => h("option", { value: m }, monthName(m))));
    select.value = month;
    select.addEventListener("change", () => { month = select.value; drawMonth(); });
    const s = r.summary;
    const csv = h("a", { class: "btn", href: `/api/reports/availability.csv${filterQuery(month, filter)}`, download: "" }, "Download as CSV");
    const print = h("button", { class: "btn", type: "button", onclick: () => window.print() }, "Print");
    const head = h("div", { class: "upc-head" }, h("h2", {}, `Availability in ${monthName(month)}`), h("div", { class: "rep-tools" }, select, csv, print));
    const card = h("div", { class: "card rep-month" }, head);
    // what the report covers (the choice is kept in this browser)
    const scope = h("select", {}, h("option", { value: "all" }, "All devices"), h("option", { value: "core" }, "Always-on devices only"));
    scope.value = filter.scope;
    const services = h("input", { type: "checkbox" });
    services.checked = filter.services;
    const group = h("select", {}, h("option", { value: "" }, "All groups"), ...(r.groups || []).map((g) => h("option", { value: String(g.id) }, g.name)));
    group.value = filter.group;
    const outages = h("input", { type: "checkbox" });
    outages.checked = filter.only_outages;
    const target = h("input", { type: "number", min: "0", max: "100", step: "0.1", placeholder: "e.g. 99.9", value: filter.target, class: "rep-target" });
    const hours = h("select", { title: "The business hours are set in the weekly report settings above (the time of the server)." }, h("option", { value: "all" }, "All hours"), h("option", { value: "business" }, "Business hours only"));
    hours.value = filter.hours || r.summary.hours || "all";
    const quiet = h("input", { type: "checkbox" });
    quiet.checked = filter.ignore === null ? !!r.summary.ignore_maintenance : !!filter.ignore;
    const apply = () => {
      Object.assign(filter, { scope: scope.value, services: services.checked, group: group.value, only_outages: outages.checked, target: target.value, hours: hours.value, ignore: quiet.checked });
      saveFilter(filter); drawMonth();
    };
    for (const el of [scope, services, group, outages, hours, quiet]) el.addEventListener("change", apply);
    target.addEventListener("change", apply);
    card.appendChild(h("div", { class: "rep-filter" }, scope, h("label", { class: "rep-part" }, services, " Services"), (r.groups || []).length ? group : null, hours,
      h("label", { class: "rep-part", title: "Leave out the checks that fall in a planned maintenance window of the device (Settings → Maintenance windows)." }, quiet, " Leave out planned maintenance"),
      h("label", { class: "rep-part" }, outages, " Only with an outage"), h("label", { class: "rep-part" }, "Target ", target, " %")));
    if (!r.devices.length && !r.services.length) {
      card.appendChild(h("p", { class: "hint" }, "Netlens has no checks for this month yet."));
    } else {
      card.appendChild(h("p", {},
        s.core_devices && s.scope !== "core" ? `Always-on devices: ${pct(s.core_availability)} · ` : "", `${s.scope === "core" ? "Always-on devices" : "All devices"}: ${pct(s.devices_availability)}`,
        s.services ? ` · Services: ${pct(s.services_availability)}` : "", ` · ${s.with_outages} with an outage`, s.target !== null && s.target !== undefined ? ` · ${s.below_target} below the ${s.target}% target` : ""));
      if (r.devices.length) {
        card.appendChild(h("h3", {}, "Devices"));
        card.appendChild(table(["Device", "Availability", "Outages", "Longest", "Time down"],
          [...r.devices].sort((a, b) => a.availability - b.availability || a.name.localeCompare(b.name)).map((d) => [
            h("a", { href: `#/device/${d.id}` }, d.name), h("span", { class: `d-${tone(d.availability) || "ok"}`, title: d.below_target ? "Below the target" : "" }, pct(d.availability), d.below_target ? " ⚠" : ""),
            d.outages, d.outages ? d.longest : "", d.down_seconds ? d.down_text : ""])));
      }
      if (r.services.length) {
        card.appendChild(h("h3", {}, "Services"));
        card.appendChild(table(["Service", "Availability", "Outages", "Longest", "Time down", "Average"],
          [...r.services].sort((a, b) => a.availability - b.availability || a.name.localeCompare(b.name)).map((x) => [
            x.name, h("span", { class: `d-${tone(x.availability) || "ok"}`, title: x.below_target ? "Below the target" : "" }, pct(x.availability), x.below_target ? " ⚠" : ""),
            x.outages, x.outages ? x.longest : "", x.down_seconds ? x.down_text : "", x.avg_ms === null ? "" : `${x.avg_ms} ms`])));
      }
      card.appendChild(h("p", { class: "hint" }, "Availability is the share of checks that succeeded. A device that was switched off on purpose counts as down; mark always-on devices on the Uptime page to see them apart."));
    }
    monthSlot.appendChild(card);
  }

  drawAll = () => { drawWeekly(); drawMonth(); };
  await Promise.all([drawWeekly(), drawMonth()]);
  return () => { disposed = true; };
}
