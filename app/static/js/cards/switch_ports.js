import { get } from "../api.js";
import { h, fmtTime } from "../util.js";
import { fmtNumber } from "../charts.js";

function speed(p) {
  if (!p.up) return "no link";
  if (!p.speed_mbps) return "link up";
  const text = p.speed_mbps >= 1000 ? `${p.speed_mbps / 1000} Gbit/s` : `${p.speed_mbps} Mbit/s`;
  return p.duplex ? `${text} ${p.duplex}` : text;
}


// The ports of a switch that a switch plugin (for example TP-Link Easy Smart) reports. Returns null for any other device.
export async function buildSwitchPortsCard(deviceId) {
  const data = await get(`/api/devices/${deviceId}/switch-ports?hours=24`);
  if (!data.ports.length) return null;
  let connected = {};
  try {
    for (const p of (await get(`/api/devices/${deviceId}/port-map`)).ports) connected[p.port] = p.devices;
  } catch (err) {
    connected = {};
  }
  const card = h("div", { class: "card switch-ports-card" });
  const up = data.ports.filter((p) => p.up).length;
  card.appendChild(h("h2", {}, "Switch ports"));
  card.appendChild(h("p", { class: "hint" }, `${up} of ${data.ports.length} ports have a link. Errors and link changes cover the last ${data.hours} hours. The traffic of each port, with a graph per port, is in the Ports card above.`));
  const table = h("table", { class: "table" });
  table.appendChild(h("thead", {}, h("tr", {}, ...["Port", "Link", "Connected", "Errors (24 h)", "Link changes"].map((t) => h("th", {}, t)))));
  const body = h("tbody", {});
  for (const p of data.ports) {
    const errors = (p.tx_errors_window || 0) + (p.rx_errors_window || 0);
    const label = p.name ? `${p.port} ${p.name}` : String(p.port);
    const row = h("tr", { title: p.enabled ? "" : "Disabled on the switch" },
      h("td", {}, p.enabled ? label : `${label} (disabled)`),
      h("td", { class: p.up ? "" : "muted" }, speed(p)),
      h("td", {}, ...(connected[String(p.port)] || []).flatMap((d, i) => [i ? ", " : "", h("a", { href: `#/device/${d.id}` }, d.name), d.behind_total ? ` (+${d.behind_total} behind)` : ""])),
      h("td", { class: errors ? "bad" : "" }, errors ? `${fmtNumber(errors)} (${fmtNumber(p.tx_errors_window || 0)} out, ${fmtNumber(p.rx_errors_window || 0)} in)` : "0"),
      h("td", { class: p.flaps > 2 ? "bad" : "" }, String(p.flaps)));
    body.appendChild(row);
  }
  table.appendChild(body);
  card.appendChild(table);
  card.appendChild(h("p", { class: "hint" }, `Updated ${fmtTime(data.ports[0].updated)}`));
  return card;
}
