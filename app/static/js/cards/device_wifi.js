import { get } from "../api.js";
import { h, fmtTime } from "../util.js";
import { lineChart } from "../charts.js";

const QUALITY_TEXT = {
  excellent: "Excellent",
  good: "Good",
  fair: "Fair",
  weak: "Weak",
};

function kvRow(label, value) {
  return h("div", { class: "kv" }, h("span", { class: "kv-label" }, label), value);
}

// Wi-Fi details of a device (signal, node, band, history, moves between nodes). Returns null when the router plugin
// has never seen the device on Wi-Fi.
export async function buildDeviceWifiCard(deviceId) {
  const data = await get(`/api/devices/${deviceId}/wifi?hours=24`);
  if (!data.current) return null;
  const card = h("div", { class: "card wifi-card" });
  card.appendChild(h("h2", {}, "Wi-Fi"));
  const c = data.current;
  const quality = c.quality ? h("span", { class: `wifi-quality q-${c.quality}` }, `${QUALITY_TEXT[c.quality]}, ${c.rssi} dBm`) : h("span", {}, "–");
  card.appendChild(kvRow("Signal", quality));
  card.appendChild(kvRow("Connected to", h("span", {}, c.node || "unknown")));
  if (c.band) card.appendChild(kvRow("Band", h("span", {}, c.band)));
  if (c.tx_mbps !== null && c.tx_mbps !== undefined) {
    card.appendChild(kvRow("Link rate", h("span", {}, `${c.tx_mbps} Mbit/s sending, ${c.rx_mbps ?? "–"} receiving`)));
  }
  card.appendChild(kvRow("Measured", h("span", { title: fmtTime(c.ts) }, fmtTime(c.ts))));

  const points = data.samples.filter((s) => s.rssi !== null).map((s) => ({ x: s.ts.slice(11, 16), rssi: s.rssi }));
  if (points.length >= 2) {
    card.appendChild(h("h3", {}, "Signal, last 24 hours (dBm)"));
    card.appendChild(lineChart(points, [{ key: "rssi", label: "signal" }], { height: 110 }));
  }
  if (data.roams.length) {
    card.appendChild(h("h3", {}, "Recent moves between nodes"));
    const list = h("ul", { class: "roam-list" });
    for (const r of data.roams) list.appendChild(h("li", {}, `${fmtTime(r.ts)}: ${r.detail}`));
    card.appendChild(list);
  }
  return card;
}
