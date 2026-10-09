import { get, post } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const LEVEL_LABEL = { warn: "Look at this", info: "Note", ok: "Fine" };

function duration(seconds) {
  if (seconds == null) return "still down";
  if (seconds < 90) return `${Math.round(seconds)} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

function findingsList(findings) {
  const list = h("ul", { class: "findings" });
  for (const f of findings) {
    list.appendChild(h("li", { class: `finding ${f.level}` }, h("strong", {}, f.title), h("span", { class: "finding-level" }, LEVEL_LABEL[f.level] || ""), h("p", {}, f.detail)));
  }
  return list;
}

function hourChart(counts) {
  const max = Math.max(1, ...counts);
  const chart = h("div", { class: "hour-chart", title: "Missed scans per hour of the day (your time zone)" });
  counts.forEach((n, hour) => {
    chart.appendChild(h("div", { class: "hour-col", title: `${String(hour).padStart(2, "0")}:00 — ${n} missed` },
      h("i", { style: `height:${Math.round((n / max) * 100)}%` }), h("span", {}, hour % 6 === 0 ? String(hour) : "")));
  });
  return chart;
}

function renderReport(box, r, device) {
  clear(box);
  if (r.checks < 10 || r.outages === undefined) {
    box.appendChild(findingsList(r.findings));
    return;
  }
  const facts = h("div", { class: "facts" });
  const fact = (label, value) => facts.appendChild(h("div", {}, h("b", {}, value), h("span", {}, label)));
  fact("scans missed", `${r.down_percent} %`);
  fact("times it went offline", String(r.outages));
  if (r.median_outage_seconds != null) fact("typical gap", duration(r.median_outage_seconds));
  if (r.longest_outage_seconds != null) fact("longest gap", duration(r.longest_outage_seconds));
  if (r.behind_stayed_up_percent != null) fact("gaps in which devices behind it stayed up", `${r.behind_stayed_up_percent} %`);
  box.appendChild(facts);
  box.appendChild(findingsList(r.findings));
  if (r.down_by_hour) {
    box.appendChild(h("h3", {}, "When it is missed"));
    box.appendChild(hourChart(r.down_by_hour));
  }
  if (r.recent_outages && r.recent_outages.length) {
    box.appendChild(h("h3", {}, "Latest gaps"));
    const table = h("table", { class: "data" });
    table.appendChild(h("thead", {}, h("tr", {}, h("th", {}, "Went offline"), h("th", {}, "Gap"), h("th", {}, "Missed scans"))));
    const body = h("tbody");
    for (const o of r.recent_outages) body.appendChild(h("tr", {}, h("td", {}, fmtTime(o.start)), h("td", {}, duration(o.seconds)), h("td", {}, String(o.checks))));
    table.appendChild(body);
    box.appendChild(table);
  }
}

function renderProbe(box, r) {
  clear(box);
  box.appendChild(h("h3", {}, `Live test of ${r.ip}`));
  const table = h("table", { class: "data" });
  table.appendChild(h("thead", {}, h("tr", {}, h("th", {}, "Probe"), h("th", {}, "Answered"), h("th", {}, "Typical answer time"))));
  const body = h("tbody");
  for (const m of r.methods) body.appendChild(h("tr", {}, h("td", {}, m.method), h("td", {}, `${m.answered} of ${m.asked}`), h("td", {}, m.rtt_ms != null ? `${m.rtt_ms} ms` : "—")));
  if (r.scan) body.appendChild(h("tr", {}, h("td", {}, "Netlens quick scan of just this device"), h("td", {}, r.scan.up ? "found it" : "did not find it"), h("td", {}, `${r.scan.seconds} s`)));
  table.appendChild(body);
  box.appendChild(table);
  box.appendChild(findingsList(r.findings));
}

let sectionOpen = false;
// While the Stability section is open the device page must not refresh itself, or the report would vanish
export function isStabilityOpen() {
  return sectionOpen;
}

// Collapsible section at the bottom of the Uptime card
export function buildStabilitySection(device) {
  sectionOpen = false;
  const details = h("details", { class: "stability-details", id: "stability-card" });
  details.appendChild(h("summary", {}, h("strong", {}, "Stability"), h("span", { class: "hint" }, "Does it keep going offline? Find out why. (The page stops refreshing while this is open.)")));
  details.addEventListener("toggle", () => { sectionOpen = details.open; });
  const body = h("div", { class: "stability-body" });
  details.appendChild(body);
  body.appendChild(h("p", { class: "hint" }, "Netlens looks at the scan history of this device, at the devices behind it and at the rest of the network, and can ask the device directly."));
  const days = h("select", { name: "days" });
  for (const d of [1, 3, 7, 14, 30]) days.appendChild(h("option", { value: String(d), selected: d === 7 }, d === 1 ? "last day" : `last ${d} days`));
  const run = h("button", { type: "button", class: "btn", id: "investigate" }, "Investigate");
  const live = h("button", { type: "button", class: "btn", id: "live-test", title: "Asks the device 8 times by ARP, ping and TCP (about 10 seconds)" }, "Run live test");
  body.appendChild(h("div", { class: "btn-row" }, days, run, live));
  const report = h("div", { class: "stability-report", id: "stability-report" });
  const probe = h("div", { class: "stability-report", id: "stability-probe" });
  body.append(report, probe);

  run.addEventListener("click", async () => {
    run.disabled = true;
    try {
      const tz = -new Date().getTimezoneOffset();
      renderReport(report, await get(`/api/devices/${device.id}/flapping?days=${days.value}&tz=${tz}`), device);
    } catch (err) {
      toast(err.message || "Could not investigate", "error");
    }
    run.disabled = false;
  });
  live.addEventListener("click", async () => {
    live.disabled = true;
    live.textContent = "Testing…";
    clear(probe);
    try {
      renderProbe(probe, await post(`/api/devices/${device.id}/flapping/probe`));
    } catch (err) {
      toast(err.message || "The live test failed", "error");
    }
    live.disabled = false;
    live.textContent = "Run live test";
  });
  if (!device.primary_ip) live.disabled = true;
  return details;
}
