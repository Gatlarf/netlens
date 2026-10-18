import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

// Settings page: the optional IPv6 discovery.
export async function buildIpv6Card() {
  const card = h("div", { class: "card" });
  function draw(info) {
    clear(card);
    card.appendChild(h("h2", {}, "IPv6"));
    card.appendChild(h("p", { class: "hint" },
      "Off by default. A whole IPv6 network cannot be swept like an IPv4 range, so Netlens asks the network instead: after every scan it sends one multicast echo to all IPv6 devices on the connected networks and reads which addresses answer. Each address is attached to the device that was found by the normal scan (the match is the MAC address), and shown on the device page. Devices that only have IPv6 are not added in this version. It works on the networks this machine is directly connected to, so Netlens in Docker needs host networking (as for ARP)."));
    const box = h("input", { type: "checkbox" });
    box.checked = info.enabled;
    box.addEventListener("change", async () => {
      try { draw(await put("/api/ipv6", { enabled: box.checked })); toast(box.checked ? "IPv6 discovery is on" : "IPv6 discovery is off", "success"); } catch (err) { toast(err.message || "Could not save", "error"); box.checked = !box.checked; }
    });
    card.appendChild(h("label", { class: "check" }, box, " Look for IPv6 addresses after every scan"));
    const show = h("input", { type: "checkbox" });
    show.checked = info.show;
    show.addEventListener("change", async () => {
      try { draw(await put("/api/ipv6", { show: show.checked })); toast(show.checked ? "IPv6 addresses are shown" : "IPv6 addresses are hidden", "success"); } catch (err) { toast(err.message || "Could not save", "error"); show.checked = !show.checked; }
    });
    card.appendChild(h("label", { class: "check" }, show, " Show IPv6 addresses (in the device list, on the device page and in the search)"));
    const st = info.status || {};
    card.appendChild(h("p", {}, st.ts ? `Last look ${timeAgo(st.ts)}: ${st.seen} neighbour${st.seen === 1 ? "" : "s"} answered, ${st.attached} address${st.attached === 1 ? "" : "es"} attached to known devices${st.unknown ? `, ${st.unknown} belong to devices that are not known` : ""}.` : "Not run yet."));
    card.appendChild(h("p", { class: "hint" }, `${info.addresses} address${info.addresses === 1 ? "" : "es"} on ${info.devices} device${info.devices === 1 ? "" : "s"} are stored (kept for 30 days after they were last seen).`));
    card.appendChild(h("p", {}, h("a", { href: "#/ipv6" }, "Is IPv6 working on my network? Open Network health")));
    const now = h("button", { class: "btn", type: "button" }, "Look now");
    now.addEventListener("click", async () => {
      now.disabled = true;
      try { draw(await post("/api/ipv6/discover", {})); } catch (err) { toast(err.message || "Failed", "error"); now.disabled = false; }
    });
    card.appendChild(h("div", { class: "form-actions" }, now));
  }
  draw(await get("/api/ipv6"));
  return card;
}
