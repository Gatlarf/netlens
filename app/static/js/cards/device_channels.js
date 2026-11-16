import { get } from "../api.js";
import { h, fmtTime } from "../util.js";

const RANGE = { "2.4 GHz": [1, 13], "5 GHz": [36, 165], "6 GHz": [1, 233] };

function signalText(dbm) {
  return dbm === null || dbm === undefined ? "–" : `${dbm} dBm`;
}

// A strip of the channels of one band: where this access point sits and how many neighbouring networks are heard on each channel
function strip(radio, networks) {
  const band = radio.band;
  const heard = networks.filter((n) => n.band === band && n.channel);
  const channels = [...new Set([...heard.map((n) => n.channel), radio.channel].filter(Boolean))].sort((a, b) => a - b);
  if (!channels.length) return null;
  const most = Math.max(1, ...channels.map((c) => heard.filter((n) => n.channel === c).length));
  const row = h("div", { class: "chan-strip" });
  for (const c of channels) {
    const count = heard.filter((n) => n.channel === c).length;
    const mine = c === radio.channel;
    row.appendChild(h("div", { class: `chan-col${mine ? " mine" : ""}`, title: `Channel ${c}: ${count} neighbouring network${count === 1 ? "" : "s"}${mine ? " (this access point)" : ""}` },
      h("div", { class: "chan-bar", style: `height:${Math.max(4, Math.round(54 * count / most))}px` }),
      h("div", { class: "chan-num" }, String(c))));
  }
  return row;
}

// The air around an access point: its radios, the networks it hears, and a quieter channel when there is one. Returns null when the plugin reports no radios.
export async function buildWifiChannelsCard(deviceId) {
  const data = await get(`/api/devices/${deviceId}/wifi-channels`);
  if (!data.radios.length) return null;
  const card = h("div", { class: "card wifi-channels-card" });
  card.appendChild(h("h2", {}, "Wi-Fi channels"));
  const table = h("table", { class: "table" });
  table.appendChild(h("thead", {}, h("tr", {}, ...["Radio", "Channel", "Width", "Clients", "Airtime", "Neighbours", ""].map((t) => h("th", {}, t)))));
  const body = h("tbody", {});
  for (const r of data.radios) {
    const advice = r.advice || {};
    const busy = r.utilization_pct !== null && r.utilization_pct >= 70;
    body.appendChild(h("tr", {},
      h("td", {}, r.band || r.name),
      h("td", {}, r.channel ? String(r.channel) : "–"),
      h("td", {}, r.width_mhz ? `${r.width_mhz} MHz` : "–"),
      h("td", {}, r.clients === null ? "–" : String(r.clients)),
      h("td", { class: busy ? "bad" : "" }, r.utilization_pct === null ? "–" : `${Math.round(r.utilization_pct)}%`),
      h("td", { title: "Other networks on the same frequencies" }, advice.networks === null || advice.networks === undefined ? "–" : String(advice.networks)),
      h("td", { class: advice.suggest ? "warn" : "muted" }, advice.suggest ? `Channel ${advice.suggest.channel} is quieter` + (advice.suggest.networks ? ` (${advice.suggest.networks} network${advice.suggest.networks === 1 ? "" : "s"})` : "") : (data.scanned ? "Fine" : ""))));
  }
  table.appendChild(body);
  card.appendChild(table);
  const others = data.neighbours.filter((n) => !n.known);
  for (const r of data.radios) {
    const s = strip(r, others);
    if (s) card.append(h("h3", {}, `${r.band || r.name}: networks per channel`), s);
  }
  if (others.length) {
    card.appendChild(h("h3", {}, `Networks this access point hears (${others.length})`));
    const list = h("table", { class: "table" });
    list.appendChild(h("thead", {}, h("tr", {}, ...["Name", "Band", "Channel", "Signal", "Security"].map((t) => h("th", {}, t)))));
    const rows = h("tbody", {});
    for (const n of others.slice(0, 25)) {
      rows.appendChild(h("tr", { title: n.bssid },
        h("td", {}, n.ssid || h("span", { class: "muted" }, "hidden network")), h("td", {}, n.band || "–"), h("td", {}, n.channel ? String(n.channel) : "–"),
        h("td", {}, signalText(n.signal_dbm)), h("td", {}, n.security || "–")));
    }
    list.appendChild(rows);
    card.appendChild(list);
    if (others.length > 25) card.appendChild(h("p", { class: "hint" }, `${others.length - 25} weaker networks are not listed.`));
  }
  card.appendChild(h("p", { class: "hint" }, `Updated ${fmtTime(data.radios[0].updated)}`));
  return card;
}
