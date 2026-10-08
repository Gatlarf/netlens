import { get } from "../api.js";
import { h, clear, timeAgo } from "../util.js";
import { buildServiceForm } from "./service_form.js";
import { stateDot } from "../pages/services.js";

// The service checks of one device, with a button to add one that is pre-filled with the device's address.
export async function buildDeviceServicesCard(device) {
  const card = h("div", { class: "card" });
  async function fill() {
    const checks = await get(`/api/service-checks?device_id=${device.id}`);
    clear(card);
    card.appendChild(h("h2", {}, "Service checks"));
    if (!checks.length) card.appendChild(h("p", { class: "hint" }, "No checks for this device. Watch a web page, a port or a DNS answer on it."));
    for (const c of checks) {
      card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, stateDot(c), " ", c.name),
        h("span", {}, `${c.target} · ${c.state === "down" ? c.last_detail : c.state === "up" ? `${Math.round(c.last_ms ?? 0)} ms` : "waiting"}${c.last_ts ? `, ${timeAgo(c.last_ts)}` : ""}`)));
    }
    const add = h("button", { class: "btn", type: "button" }, "Add check");
    const slot = h("div", {});
    add.addEventListener("click", async () => {
      add.disabled = true;
      slot.appendChild(await buildServiceForm({ defaults: { host: device.primary_ip || "", device_id: device.id }, onDone: (changed) => { if (changed) fill(); else { clear(slot); add.disabled = false; } } }));
    });
    card.append(add, " ", h("a", { href: "#/services" }, "All checks"), slot);
  }
  await fill();
  return card;
}
