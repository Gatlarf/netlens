import { get, put, post } from "../api.js";
import { h, clear, toast, isAdmin } from "../util.js";

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
const DEFAULT_FILTER = { scope: "all", services: true, group: "", only_outages: false, target: "" };
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
  const text = q.toString();
  return text ? `?${text}` : "";
}

export async function render(container) {
  let disposed = false;
  let month = null;
  const filter = loadFilter();
  const weeklySlot = h("div", {});
  const monthSlot = h("div", {});
  container.appendChild(h("div", { class: "rep-page" },
    h("div", { class: "heading-row" }, h("h1", {}, "Reports")),
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
    const apply = () => { filter.scope = scope.value; filter.services = services.checked; filter.group = group.value; filter.only_outages = outages.checked; filter.target = target.value; saveFilter(filter); drawMonth(); };
    for (const el of [scope, services, group, outages]) el.addEventListener("change", apply);
    target.addEventListener("change", apply);
    card.appendChild(h("div", { class: "rep-filter" }, scope, h("label", { class: "rep-part" }, services, " Services"), (r.groups || []).length ? group : null,
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

  await Promise.all([drawWeekly(), drawMonth()]);
  return () => { disposed = true; };
}
