// IPv6 health: is IPv6 on this network working as it should, said in plain words, with the subnets (prefixes) in use.
import { get, post } from "../api.js";
import { h, clear, toast, isAdmin, timeAgo } from "../util.js";
import { pageHead } from "../ui.js";

const MARK = { good: "✓", warn: "!", bad: "✕", info: "i" };
const STALE_MS = 15 * 60 * 1000;

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

function draw(slot, doc, run) {
  clear(slot);
  const r = doc.result;
  if (!r) { slot.append(h("div", { class: "card" }, h("p", { class: "hint" }, "No check has run yet."))); return; }
  const tone = { good: "ok", warn: "warn", bad: "bad", info: "info" }[r.verdict] || "info";
  slot.append(h("div", { class: `dash-hero tone-${tone}` },
    h("div", { class: "dash-hero-main" }, h("h1", {}, "IPv6 on this network"), h("p", { class: "dash-verdict" }, r.headline),
      h("div", { class: "dash-facts" },
        r.devices.online ? h("span", { class: "dash-fact" }, h("strong", {}, `${r.devices.with_ipv6} / ${r.devices.online}`), " online devices have IPv6") : null,
        r.subnets.length ? h("span", { class: "dash-fact" }, h("strong", {}, String(r.subnets.length)), r.subnets.length === 1 ? " subnet" : " subnets") : null,
        h("span", { class: "dash-fact hint" }, `checked ${timeAgo(r.ts)}`)))));
  const list = h("ul", { class: "ipv6-findings" }, r.findings.map((f) => h("li", { class: `ipv6-${f.level}` },
    h("span", { class: "ipv6-mark", "aria-hidden": "true" }, MARK[f.level]), h("div", {}, h("strong", {}, f.title), h("p", { class: "hint" }, f.text)))));
  slot.append(h("div", { class: "card" }, h("h2", {}, "What Netlens found"), list));
  if (r.subnets.length) {
    slot.append(h("div", { class: "card" }, h("h2", {}, "Subnets in use"),
      h("p", { class: "hint" }, "Devices in the same subnet can reach each other directly. More than one internet subnet on one network usually means a second router or a provider change."),
      h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Prefix", "Kind", "Devices"].map((t) => h("th", {}, t)))),
        h("tbody", {}, r.subnets.map((s) => h("tr", {}, h("td", { class: "mono" }, s.prefix), h("td", {}, s.scope === "global" ? "Internet (global)" : "Private (unique-local)", s.this_computer ? h("span", { class: "hint" }, " · this computer is here") : null), h("td", {}, String(s.devices))))))));
  }
  if (r.routers.length) {
    slot.append(h("div", { class: "card" }, h("h2", {}, "Devices that announce themselves as routers"),
      h("ul", { class: "d-list" }, r.routers.map((x) => h("li", {}, h("span", { class: "mono" }, x.ip), x.name ? h("span", { class: "d-note" }, x.name) : null)))));
  }
  if (!doc.discovery && isAdmin()) slot.append(h("p", { class: "hint" }, "Per-device results need IPv6 discovery. ", h("a", { href: "#/settings/ipv6" }, "Switch it on in Settings → IPv6"), "."));
  slot.append(primer());
}

export async function render(container) {
  clear(container);
  const slot = h("div", {}, h("p", { class: "hint" }, "Looking at the IPv6 side of your network…"));
  const button = h("button", { class: "btn primary admin-only", type: "button" }, "Check now");
  container.append(pageHead("IPv6 health", "Where your IPv6 addresses come from, whether they work on the internet, and whether your devices can reach each other.", button), slot);
  let doc;
  const run = async () => {
    button.disabled = true;
    slot.prepend(h("p", { class: "hint" }, "Checking… this takes up to a minute."));
    try { doc = await post("/api/ipv6/health/run", {}); draw(slot, doc, run); } catch (err) { toast(err.message || "The check failed", "error"); }
    button.disabled = false;
  };
  button.addEventListener("click", run);
  try {
    doc = await get("/api/ipv6/health");
    draw(slot, doc, run);
    const old = !doc.result || Date.now() - Date.parse(doc.result.ts) > STALE_MS;
    if (old && isAdmin()) run();
  } catch (err) {
    slot.replaceChildren(h("p", { class: "error" }, err.message || "Could not load the IPv6 page"));
  }
}
