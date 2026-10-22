import { get } from "../api.js";
import { h, fmtTime } from "../util.js";

function dayText(l) {
  if (l.days_left === null || l.days_left === undefined) return "no end date";
  if (l.days_left < 0) return `ended ${-l.days_left} day${l.days_left === -1 ? "" : "s"} ago`;
  return l.days_left === 0 ? "ends today" : `${l.days_left} day${l.days_left === 1 ? "" : "s"} left`;
}

// What a firewall plugin (FortiGate, Palo Alto, Check Point) reports about the device: version, high availability, VPN tunnels, licences.
// Returns null for any other device.
export async function buildFirewallCard(deviceId) {
  const data = await get(`/api/devices/${deviceId}/firewall`);
  const fw = data.firewall;
  if (!fw) return null;
  const card = h("div", { class: "card firewall-card" });
  card.appendChild(h("h2", {}, "Firewall"));
  const facts = [fw.model, fw.version && `version ${fw.version}`, fw.serial && `serial ${fw.serial}`].filter(Boolean);
  if (facts.length) card.appendChild(h("p", { class: "hint" }, facts.join(" · ")));
  if (fw.ha) {
    const bits = [fw.ha.mode, fw.ha.state && `this unit: ${fw.ha.state}`, fw.ha.peer_state && `peer: ${fw.ha.peer_state}`, fw.ha.in_sync === false ? "NOT in sync" : fw.ha.in_sync ? "in sync" : ""].filter(Boolean);
    card.appendChild(h("h3", {}, "High availability"));
    card.appendChild(h("p", { class: fw.ha.in_sync === false ? "bad" : "" }, bits.join(" · ")));
  }
  if (fw.tunnels && fw.tunnels.length) {
    const down = fw.tunnels.filter((t) => !t.up).length;
    card.appendChild(h("h3", {}, `VPN tunnels (${fw.tunnels.length - down} up${down ? `, ${down} down` : ""})`));
    const list = h("ul", { class: "pm-devices" });
    for (const t of fw.tunnels) {
      list.appendChild(h("li", { class: "pm-device" }, h("span", { class: `dot ${t.up ? "on" : "off"}`, title: t.up ? "up" : "down" }), " ", t.name, t.remote ? h("span", { class: "hint" }, ` to ${t.remote}`) : ""));
    }
    card.appendChild(list);
  }
  if (fw.licences && fw.licences.length) {
    card.appendChild(h("h3", {}, "Licences and support"));
    const list = h("ul", { class: "pm-devices" });
    for (const l of fw.licences) {
      const tone = l.days_left !== null && l.days_left !== undefined ? (l.days_left < 0 ? "bad" : l.days_left <= 30 ? "warn" : "") : "";
      list.appendChild(h("li", { class: `pm-device ${tone}` }, l.name, h("span", { class: "hint" }, ` · ${l.expires || ""} · `), dayText(l)));
    }
    card.appendChild(list);
  }
  card.appendChild(h("p", { class: "hint" }, `Updated ${fmtTime(data.updated)}`));
  return card;
}
