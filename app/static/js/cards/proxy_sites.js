import { get } from "../api.js";
import { h } from "../util.js";

const TYPE_TEXT = { proxy: "", redirect: "redirects to ", stream: "stream ", dead: "404 page" };

function siteCell(s) {
  const cell = h("td", {});
  if (s.type === "stream") {
    cell.appendChild(h("span", {}, `port ${s.incoming_port || "?"}${s.protocols && s.protocols.length ? " " + s.protocols.join("/") : ""}`));
  } else if (!s.domains.length) {
    cell.appendChild(h("span", { class: "hint" }, "no domain"));
  }
  s.domains.forEach((d, i) => {
    if (i) cell.appendChild(h("br"));
    cell.appendChild(d.startsWith("*") ? h("span", {}, d) : h("a", { href: `${s.ssl ? "https" : "http"}://${d}`, target: "_blank", rel: "noopener" }, d));
  });
  if (s.type === "redirect" && s.redirect_to) cell.appendChild(h("div", { class: "hint" }, TYPE_TEXT.redirect + s.redirect_to));
  if (s.type === "dead") cell.appendChild(h("div", { class: "hint" }, TYPE_TEXT.dead));
  if (!s.enabled) cell.appendChild(h("span", { class: "tag off", title: "Turned off in the proxy" }, "off"));
  if (s.access_list) cell.appendChild(h("span", { class: "tag", title: "Access list" }, s.access_list));
  return cell;
}

function targetCell(s, from) {
  const cell = h("td", {});
  if (s.type === "redirect" || s.type === "dead") return cell.appendChild(h("span", { class: "hint" }, "–")), cell;
  const where = `${s.forward_host}${s.forward_port ? ":" + s.forward_port : ""}`;
  if (s.target_device_id) {
    const label = s.target_container ? `${s.target_name} (container)` : s.target_device || s.target_name;
    if (from === "target") cell.appendChild(h("span", {}, label));
    else cell.appendChild(h("a", { href: `#/device/${s.target_device_id}` }, label));
    cell.appendChild(h("div", { class: "hint", title: s.target_how }, where));
  } else {
    cell.appendChild(h("span", { class: "tag unknown-tag", title: "Netlens does not know a device or container with this address" }, "not found"));
    cell.appendChild(h("div", { class: "hint" }, where));
  }
  return cell;
}

function certCell(s) {
  const cell = h("td", {});
  if (!s.ssl) return cell.appendChild(h("span", { class: "hint" }, s.type === "stream" ? "–" : "no HTTPS")), cell;
  if (s.cert_days === null || s.cert_days === undefined) return cell.appendChild(h("span", { class: "hint" }, "certificate")), cell;
  const text = s.cert_days < 0 ? "expired" : s.cert_days === 0 ? "expires today" : `${s.cert_days} day${s.cert_days === 1 ? "" : "s"} left`;
  cell.appendChild(h("span", { class: s.cert_days <= 14 ? "tag unknown-tag" : "hint", title: s.cert_expires || "" }, text));
  return cell;
}

function checkCell(s) {
  const cell = h("td", {});
  if (!s.check_id) return cell.appendChild(h("span", { class: "hint" }, "–")), cell;
  cell.appendChild(h("a", { href: "#/services", title: "See it under Services" }, s.check_state === "up" ? "up" : s.check_state === "down" ? "DOWN" : "waiting"));
  return cell;
}

/** `from`: "target" on the page of the device a site leads to, "proxy" on the proxy's page, "all" in the plugin's card. */
export function sitesTable(sites, from) {
  const table = h("table", { class: "data" });
  table.appendChild(h("thead", {}, h("tr", {}, ["Site", from === "target" ? "Published by" : "Leads to", "Certificate", "Check"].map((t) => h("th", {}, t)))));
  const body = h("tbody");
  for (const s of sites) {
    const second = from === "target"
      ? h("td", {}, s.proxy_device_id ? h("a", { href: `#/device/${s.proxy_device_id}` }, s.proxy_device || s.proxy) : h("span", {}, s.proxy), h("div", { class: "hint" }, `${s.forward_host}${s.forward_port ? ":" + s.forward_port : ""}`))
      : targetCell(s, from);
    body.appendChild(h("tr", {}, siteCell(s), second, certCell(s), checkCell(s)));
  }
  table.appendChild(body);
  return h("div", { class: "table-wrap" }, table);
}

/** On a device page: the sites that lead to it and the sites it publishes. */
export function buildDeviceSitesCards(device) {
  const info = device.sites;
  const cards = [];
  if (!info) return cards;
  if (info.published && info.published.length) {
    const card = h("div", { class: "card" });
    card.appendChild(h("h2", {}, "Published through a reverse proxy"));
    card.appendChild(h("p", { class: "hint" }, "Domains your reverse proxy forwards to this device (or a container on it)."));
    card.appendChild(sitesTable(info.published, "target"));
    cards.push(card);
  }
  if (info.serves && info.serves.length) {
    const card = h("div", { class: "card" });
    card.appendChild(h("h2", {}, `Sites served (${info.serves.length})`));
    card.appendChild(h("p", { class: "hint" }, "What this reverse proxy publishes and where each site leads."));
    card.appendChild(sitesTable(info.serves, "proxy"));
    cards.push(card);
  }
  return cards;
}

/** In the plugin's settings card: every site, with the ones Netlens cannot place first. */
export async function buildPluginSitesCard() {
  const data = await get("/api/sites");
  if (!data.sites.length) return null;
  const s = data.summary;
  const box = h("details", { class: "plugin-info", open: s.unmatched > 0 || s.down > 0 || s.expiring > 0 });
  const bits = [`${s.total} site${s.total === 1 ? "" : "s"}`];
  if (s.unmatched) bits.push(`${s.unmatched} not found in Netlens`);
  if (s.expiring) bits.push(`${s.expiring} certificate${s.expiring === 1 ? "" : "s"} expiring`);
  if (s.down) bits.push(`${s.down} down`);
  box.appendChild(h("summary", {}, "Sites: " + bits.join(", ")));
  const order = (x) => (x.type === "proxy" && x.enabled && !x.target_device_id ? 0 : 1);
  box.appendChild(sitesTable([...data.sites].sort((a, b) => order(a) - order(b)), "all"));
  return box;
}
