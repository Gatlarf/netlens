import { get } from "../api.js";
import { h, clear, fmtTime } from "../util.js";
import { heartbeatBar, responseLine, rangeTabs, savedRange, RANGES, uptimeText, uptimeClass, humanDuration } from "../heartbeat.js";

function kvRow(label, value) {
  const row = h("div", { class: "kv" });
  row.appendChild(h("span", { class: "kv-label" }, label));
  row.appendChild(value);
  return row;
}

export async function buildDeviceUptimeCard(deviceId) {
  const card = h("div", { class: "card" });
  let range = savedRange();
  const slots = () => (window.matchMedia("(max-width: 700px)").matches ? 30 : 90);

  async function draw() {
    try {
      const data = await get(`/api/devices/${deviceId}/uptime?range=${range}&limit=${slots()}`);
      const checks = data.checks || [];
      const label = RANGES.find(([k]) => k === range)[1].toLowerCase();
      const head = h("div", { class: "upc-head" }, h("h2", {}, "Uptime"), rangeTabs(range, (key) => { range = key; draw(); }));
      const body = [head];
      if (checks.length === 0 && data.since === null) {
        body.push(h("p", { class: "hint" }, "No scans recorded yet."));
        card.replaceChildren(...body);
        return;
      }
      const three = h("div", { class: "upc-three" });
      for (const [key, text, field] of [["24h", "24 hours", "up_24h"], ["7d", "7 days", "up_7d"], ["30d", "30 days", "up_30d"]]) {
        three.appendChild(h("div", { class: key === range ? "picked" : "" }, h("small", {}, text), h("strong", { class: uptimeClass(data[field]) }, uptimeText(data[field]))));
      }
      body.push(three);
      if (checks.length) {
        body.push(h("span", { class: "up-graph-label" }, `Availability \u00b7 ${label}`), heartbeatBar(checks, slots()));
        body.push(h("span", { class: "up-graph-label" }, `Response time \u00b7 ${label}`), responseLine(checks, slots(), { height: 70, axis: true }));
      } else {
        body.push(h("p", { class: "hint" }, `No scans in the last ${label}.`));
      }
      body.push(kvRow(`Average response (${label})`, h("span", {}, data.avg_rtt_ms != null ? `${data.avg_rtt_ms} ms` : "\u2013")));
      if (data.status_for_seconds != null) {
        const up = checks.length ? checks[checks.length - 1].up : true;
        body.push(kvRow("Current status", h("span", {}, (up ? "Up for " : "Down for ") + humanDuration(data.status_for_seconds))));
      }
      body.push(kvRow("Monitored since", h("span", {}, fmtTime(data.since))));
      card.replaceChildren(...body);
    } catch (err) {
      card.replaceChildren(h("h2", {}, "Uptime"), h("p", { class: "error" }, err.message || "Failed to load uptime data"));
    }
  }

  card.append(h("h2", {}, "Uptime"), h("p", { class: "hint" }, "Loading..."));
  await draw();
  return card;
}
