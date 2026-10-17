// The DNS page: what Netlens would register in your DNS server, and the settings behind it.
import { h, clear } from "../util.js";
import { pageHead } from "../ui.js";
import { buildDnsCard } from "../cards/dns.js";

export async function render(container) {
  clear(container);
  container.append(pageHead("DNS", "Register the devices Netlens knows in your DNS server and keep the addresses right when DHCP changes them. Nothing is written before you approve it."));
  const slot = h("div", {}, h("p", { class: "hint" }, "Loading…"));
  container.append(slot);
  try {
    slot.replaceChildren(await buildDnsCard());
  } catch (err) {
    slot.replaceChildren(h("p", { class: "error" }, err.message || "Could not load the DNS page"));
  }
}
