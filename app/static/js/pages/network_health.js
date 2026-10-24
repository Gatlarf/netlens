// Network health: is the IPv4 and the IPv6 side of this network in good order, said in plain words. One tab each.
import { get, post } from "../api.js";
import { h, clear, toast, isAdmin, timeAgo } from "../util.js";
import { pageHead, tabbed } from "../ui.js";
import { boardPage } from "../layout_cards.js";

const MARK = { good: "✓", warn: "!", bad: "✕", info: "i" };
const STALE_MS = 15 * 60 * 1000;
const TONE = { good: "ok", warn: "warn", bad: "bad", info: "info" };

function primer() {
  return h("details", { class: "card ipv6-primer" }, h("summary", {}, h("strong", {}, "New to IPv6? What these words mean")),
    h("dl", {},
      h("dt", {}, "Prefix (subnet)"), h("dd", {}, "The first half of an IPv6 address. Every device on the same network shares it, like the 192.168.1 of 192.168.1.20. A /64 is the normal size of one network."),
      h("dt", {}, "Router advertisement"), h("dd", {}, "How devices learn their address: the router announces the prefix and the device makes up the rest itself (SLAAC). There is no DHCP lease to look at."),
      h("dt", {}, "Link-local (fe80::)"), h("dd", {}, "An address every IPv6 device gives itself. It only works on the same cable or Wi-Fi, never across a router."),
      h("dt", {}, "Unique-local (fd…)"), h("dd", {}, "The private range, comparable to 192.168.x.x. It works inside your network only."),
      h("dt", {}, "Global (2…)"), h("dd", {}, "An address from your provider that works on the internet. Every device has its own, so there is no NAT: what protects a device is the firewall of your router."),
      h("dt", {}, "Temporary address"), h("dd", {}, "Phones and computers change their outgoing address now and then for privacy, so one device can show several addresses.")));
}

function verdictCard(title, r, facts) {
  return h("div", { class: `dash-hero tone-${TONE[r.verdict] || "info"}` },
    h("div", { class: "dash-hero-main" }, h("h1", {}, title), h("p", { class: "dash-verdict" }, r.headline),
      h("div", { class: "dash-facts" }, ...facts, h("span", { class: "dash-fact hint" }, `checked ${timeAgo(r.ts)}`))));
}

const fact = (value, label) => h("span", { class: "dash-fact" }, h("strong", {}, String(value)), ` ${label}`);

function findingsCard(r) {
  return h("div", { class: "card" }, h("h2", {}, "What Netlens found"), h("ul", { class: "ipv6-findings" }, r.findings.map((f) => h("li", { class: `ipv6-${f.level}` },
    h("span", { class: "ipv6-mark", "aria-hidden": "true" }, MARK[f.level]), h("div", {}, h("strong", {}, f.title), h("p", { class: "hint" }, f.text))))));
}

// the cards of a tab go in one grid the reader can arrange (Customize)
const cardFlow = (...cards) => h("div", { class: "dev-flow" }, ...cards.filter(Boolean));
const tagged = (el, id, title, kind, size) => { el.dataset.card = id; el.dataset.title = title; el.dataset.kind = kind; if (size) el.dataset.size = size; return el; };

function table(head, rows) {
  return h("table", { class: "data" }, h("thead", {}, h("tr", {}, head.map((t) => h("th", {}, t)))), h("tbody", {}, rows.map((cells) => h("tr", {}, cells.map((c) => h("td", {}, c))))));
}

function drawV4(slot, doc) {
  clear(slot);
  const r = doc.result;
  if (!r) { slot.append(h("p", { class: "hint" }, "No check has run yet.")); return; }
  slot.append(verdictCard("IPv4 on this network", r, [fact(`${r.devices.online} / ${r.devices.known}`, "devices online"), r.subnets.length ? fact(r.subnets.length, r.subnets.length === 1 ? "subnet" : "subnets") : null]));
  const cards = [tagged(findingsCard(r), "found", "What Netlens found", "list", "w")];
  if (r.subnets.length) {
    cards.push(tagged(h("div", { class: "card" }, h("h2", {}, "Subnets Netlens scans"),
      h("p", { class: "hint" }, "How many of the addresses in each range belong to a device Netlens has seen. A router hands out only part of a range, so this is a rough guide to running out of space."),
      table(["Range", "Online", "Known", "Used", ""], r.subnets.map((s) => [h("span", { class: "mono" }, s.range), String(s.online), String(s.known), `${s.usage}% of ${s.size}`,
        h("span", { class: "hint" }, s.attached ? "this computer is here" : "not directly connected")]))), "subnets", "Subnets Netlens scans", "table", "w"));
  }
  slot.append(cardFlow(...cards));
}

function drawV6(slot, doc) {
  clear(slot);
  const r = doc.result;
  if (!r) { slot.append(h("p", { class: "hint" }, "No check has run yet.")); return; }
  slot.append(verdictCard("IPv6 on this network", r, [r.devices.online ? fact(`${r.devices.with_ipv6} / ${r.devices.online}`, "online devices have IPv6") : null, r.subnets.length ? fact(r.subnets.length, r.subnets.length === 1 ? "subnet" : "subnets") : null]));
  const cards = [tagged(findingsCard(r), "found", "What Netlens found", "list", "w")];
  if (r.subnets.length) {
    cards.push(tagged(h("div", { class: "card" }, h("h2", {}, "Subnets in use"),
      h("p", { class: "hint" }, "Devices in the same subnet can reach each other directly. More than one internet subnet on one network usually means a second router or a provider change."),
      table(["Prefix", "Kind", "Devices"], r.subnets.map((s) => [h("span", { class: "mono" }, s.prefix), [s.scope === "global" ? "Internet (global)" : "Private (unique-local)", s.this_computer ? h("span", { class: "hint" }, " · this computer is here") : null], String(s.devices)]))), "subnets", "Subnets in use", "table", "w"));
  }
  if (r.routers.length) {
    cards.push(tagged(h("div", { class: "card" }, h("h2", {}, "Devices that announce themselves as routers"),
      h("ul", { class: "d-list" }, r.routers.map((x) => h("li", {}, h("span", { class: "mono" }, x.ip), x.name ? h("span", { class: "d-note" }, x.name) : null)))), "routers", "Devices that announce themselves as routers", "list"));
  }
  slot.append(cardFlow(...cards));
  if (!doc.discovery && isAdmin()) slot.append(h("p", { class: "hint" }, "Per-device results need IPv6 discovery. ", h("a", { href: "#/settings/ipv6" }, "Switch it on in Settings → IPv6"), "."));
  slot.append(primer());
}

export async function render(container) {
  clear(container);
  if (location.hash.startsWith("#/ipv6")) { try { localStorage.setItem("netlens.nethealth.tab", "v6"); } catch (e) { /* default tab */ } }
  const slots = { v4: h("div", {}, h("p", { class: "hint" }, "Looking at the network…")), v6: h("div", {}, h("p", { class: "hint" }, "Looking at the network…")) };
  const docs = {};
  const board = boardPage("nethealth", "Network health", [["v4", "IPv4"], ["v6", "IPv6"]], "*", isAdmin);
  const button = h("button", { class: "btn primary admin-only", type: "button" }, "Check now");
  container.append(pageHead("Network health", "Is the network in good order? Addresses, gateway, DNS, DHCP and IPv6, checked from this computer and explained in plain words. Netlens repeats the check every half hour and alerts you when a problem stays (choose how in Settings → Alert channels).", board.button(() => { try { return localStorage.getItem("netlens.nethealth.tab") || "v4"; } catch (e) { return "v4"; } }), button),
    tabbed("netlens.nethealth.tab", [["v4", "IPv4", slots.v4], ["v6", "IPv6", slots.v6]]));
  const paint = () => {
    if (board.editing) return;                                   // the page does not redraw under the arranging drawer
    if (docs.v4) drawV4(slots.v4, docs.v4);
    if (docs.v6) drawV6(slots.v6, docs.v6);
    board.apply({ v4: slots.v4, v6: slots.v6 });
  };
  const run = async () => {
    button.disabled = true;
    for (const s of Object.values(slots)) s.prepend(h("p", { class: "hint" }, "Checking… this takes up to a minute."));
    try {
      [docs.v4, docs.v6] = await Promise.all([post("/api/ipv4/health/run", {}), post("/api/ipv6/health/run", {})]);
      paint();
    } catch (err) {
      toast(err.message || "The check failed", "error");
      paint();
    }
    button.disabled = false;
  };
  button.addEventListener("click", run);
  try {
    [docs.v4, docs.v6] = await Promise.all([get("/api/ipv4/health"), get("/api/ipv6/health")]);
    paint();
    const old = (d) => !d.result || Date.now() - Date.parse(d.result.ts) > STALE_MS;
    if ((old(docs.v4) || old(docs.v6)) && isAdmin()) run();
  } catch (err) {
    container.append(h("p", { class: "error" }, err.message || "Could not load the network health"));
  }
  return () => board.close();
}
