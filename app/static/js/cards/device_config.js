import { get } from "../api.js";
import { h, fmtTime } from "../util.js";

// What changed in the settings of a router, firewall or controller, as its plugin reports them. Returns null when no plugin reports settings for
// this device (or the viewer is not an administrator), so the card only exists where it has something to say.
export async function buildDeviceConfigCard(device) {
  const data = await get(`/api/devices/${device.id}/config?limit=30`).catch(() => null);
  if (!data || !data.plugin) return null;
  const card = h("div", { class: "card device-config-card" });
  card.appendChild(h("h2", {}, "Configuration changes"));
  card.appendChild(h("p", { class: "hint", title: `Read by the ${data.plugin} plugin. Netlens never writes to the device.` }, `${data.items} settings, last read ${fmtTime(data.updated)}.`));
  if (!data.changes.length) {
    card.appendChild(h("p", { class: "hint" }, "No change since Netlens started recording."));
    return card;
  }
  for (const c of data.changes) {
    const rows = [
      ...c.changed.map((x) => h("li", {}, h("span", { class: "mono" }, x.key), `: ${x.before || "(empty)"} → ${x.after || "(empty)"}`)),
      ...c.added.map((x) => h("li", {}, "Added ", h("span", { class: "mono" }, x.key), `: ${x.value || "(empty)"}`)),
      ...c.removed.map((x) => h("li", {}, "Removed ", h("span", { class: "mono" }, x.key), `: ${x.value || "(empty)"}`)),
    ];
    card.appendChild(h("div", { class: "config-change" }, h("p", {}, h("strong", {}, fmtTime(c.ts)), ` ${c.changed.length} changed, ${c.added.length} added, ${c.removed.length} removed`), h("ul", {}, ...rows)));
  }
  return card;
}
