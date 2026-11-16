import { get } from "../api.js";
import { h, fmtTime } from "../util.js";

function state(c) {
  if (c.up === false) return h("span", { class: "bad" }, "Down");
  if (c.active) return h("span", { class: "good" }, "In use");
  if (c.up) return h("span", {}, "Standby");
  return h("span", { class: "muted" }, "Unknown");
}

// The internet connections of a gateway with more than one. Returns null for any other device.
export async function buildUplinksCard(deviceId) {
  const data = await get(`/api/devices/${deviceId}/uplinks`);
  if (data.connections.length < 2) return null;
  const card = h("div", { class: "card uplinks-card" });
  card.appendChild(h("h2", {}, "Internet connections"));
  if (data.mode_text) card.appendChild(h("p", { class: "hint" }, data.mode_text));
  const table = h("table", { class: "table" });
  const balance = data.mode === "balance";
  table.appendChild(h("thead", {}, h("tr", {}, ...["Connection", "State", "Address", "Gateway", balance ? "Share" : "Priority", "Answer time"].map((t) => h("th", {}, t)))));
  const body = h("tbody", {});
  const total = data.connections.reduce((a, c) => a + (c.weight || 0), 0);
  for (const c of data.connections) {
    const share = balance && c.weight && total ? `${Math.round(100 * c.weight / total)}%` : "–";
    body.appendChild(h("tr", {},
      h("td", { title: c.interface || "" }, c.name), h("td", {}, state(c)), h("td", {}, c.ip || "–"), h("td", {}, c.gateway || "–"),
      h("td", {}, balance ? share : (c.priority === null ? "–" : String(c.priority))),
      h("td", {}, c.latency_ms === null ? "–" : `${Math.round(c.latency_ms)} ms`)));
  }
  table.appendChild(body);
  card.appendChild(table);
  card.appendChild(h("p", { class: "hint" }, `Updated ${fmtTime(data.connections[0].updated)}`));
  return card;
}
