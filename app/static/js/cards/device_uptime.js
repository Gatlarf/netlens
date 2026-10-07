import { get } from "../api.js";
import { h, clear, fmtTime } from "../util.js";
import { heartbeatBar, uptimeText, uptimeClass, humanDuration, sparkline } from "../heartbeat.js";

function kvRow(label, value) {
  const row = h("div", { class: "kv" });
  row.appendChild(h("span", { class: "kv-label" }, label));
  row.appendChild(value);
  return row;
}

export async function buildDeviceUptimeCard(deviceId) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Uptime"));
  card.appendChild(h("p", { class: "hint" }, "Loading..."));

  try {
    const data = await get(`/api/devices/${deviceId}/uptime?limit=90`);
    clear(card);
    card.appendChild(h("h2", {}, "Uptime"));

    const checks = data.checks || [];
    if (checks.length === 0) {
      card.appendChild(h("p", { class: "hint" }, "No scans recorded yet."));
      return card;
    }

    card.appendChild(heartbeatBar(checks, 90));

    card.appendChild(kvRow("Last 24 hours", h("span", { class: uptimeClass(data.up_24h) }, uptimeText(data.up_24h))));
    card.appendChild(kvRow("Last 7 days", h("span", { class: uptimeClass(data.up_7d) }, uptimeText(data.up_7d))));
    card.appendChild(kvRow("Last 30 days", h("span", { class: uptimeClass(data.up_30d) }, uptimeText(data.up_30d))));

    const avgText = data.avg_rtt_ms != null ? `${data.avg_rtt_ms} ms` : "–";
    card.appendChild(kvRow("Average response", h("span", {}, avgText)));

    const newest = checks[checks.length - 1];
    const statusText = newest.up ? "Up for " : "Down for ";
    card.appendChild(kvRow("Current status", h("span", {}, statusText + humanDuration(data.status_for_seconds))));

    card.appendChild(kvRow("Monitored since", h("span", {}, fmtTime(data.since))));

    const numericChecks = checks.filter(c => typeof c.rtt_ms === "number");
    if (numericChecks.length >= 2) {
      card.appendChild(h("p", { class: "hint" }, "Response time (ms)"));
      card.appendChild(sparkline(checks.map(c => c.rtt_ms)));
    }
  } catch (err) {
    clear(card);
    card.appendChild(h("h2", {}, "Uptime"));
    card.appendChild(h("p", { class: "error" }, err.message || "Failed to load uptime data"));
  }

  return card;
}