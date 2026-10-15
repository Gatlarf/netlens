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

export async function render(container) {
  let disposed = false;
  let month = null;
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
      r = await get(`/api/reports/availability${month ? `?month=${month}` : ""}`);
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
    const csv = h("a", { class: "btn", href: `/api/reports/availability.csv?month=${month}`, download: "" }, "Download as CSV");
    const print = h("button", { class: "btn", type: "button", onclick: () => window.print() }, "Print");
    const head = h("div", { class: "upc-head" }, h("h2", {}, `Availability in ${monthName(month)}`), h("div", { class: "rep-tools" }, select, csv, print));
    const card = h("div", { class: "card rep-month" }, head);
    if (!r.devices.length && !r.services.length) {
      card.appendChild(h("p", { class: "hint" }, "Netlens has no checks for this month yet."));
    } else {
      card.appendChild(h("p", {},
        s.core_devices ? `Always-on devices: ${pct(s.core_availability)} · ` : "", `All devices: ${pct(s.devices_availability)}`,
        s.services ? ` · Services: ${pct(s.services_availability)}` : "", ` · ${s.with_outages} with an outage`));
      if (r.devices.length) {
        card.appendChild(h("h3", {}, "Devices"));
        card.appendChild(table(["Device", "Availability", "Outages", "Longest", "Time down"],
          [...r.devices].sort((a, b) => a.availability - b.availability || a.name.localeCompare(b.name)).map((d) => [
            h("a", { href: `#/device/${d.id}` }, d.name), h("span", { class: `d-${tone(d.availability) || "ok"}` }, pct(d.availability)),
            d.outages, d.outages ? d.longest : "", d.down_seconds ? d.down_text : ""])));
      }
      if (r.services.length) {
        card.appendChild(h("h3", {}, "Services"));
        card.appendChild(table(["Service", "Availability", "Outages", "Longest", "Time down", "Average"],
          [...r.services].sort((a, b) => a.availability - b.availability || a.name.localeCompare(b.name)).map((x) => [
            x.name, h("span", { class: `d-${tone(x.availability) || "ok"}` }, pct(x.availability)),
            x.outages, x.outages ? x.longest : "", x.down_seconds ? x.down_text : "", x.avg_ms === null ? "" : `${x.avg_ms} ms`])));
      }
      card.appendChild(h("p", { class: "hint" }, "Availability is the share of checks that succeeded. A device that was switched off on purpose counts as down; mark always-on devices on the Uptime page to see them apart."));
    }
    monthSlot.appendChild(card);
  }

  await Promise.all([drawWeekly(), drawMonth()]);
  return () => { disposed = true; };
}
