import { get } from "../api.js";
import { h } from "../util.js";

// The times the processor of this host was past its limit, with what Netlens made of them: explained (a known job, or it is busy at this time every day) or a warning.
export async function buildDeviceBusyCard(device) {
  let data;
  try {
    data = await get(`/api/devices/${device.id}/busy-periods`);
  } catch (err) {
    return null;
  }
  if (!data.periods.length) return null;
  const card = h("div", { class: "card" }, h("h2", {}, "Busy periods"));
  const list = h("ul", { class: "d-events" });
  for (const p of data.periods) {
    const when = new Date(p.start).toLocaleString([], { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
    const what = p.explained || (p.process ? `mostly ${p.process}` : "");
    list.appendChild(h("li", {}, h("span", { class: "d-time" }, when), h("span", { class: "d-kind" }, `${p.minutes} min, up to ${p.peak}%${p.open ? " (going on)" : ""}`),
      h("span", { class: "hint" }, p.explained ? ` explained: ${what}` : what ? ` ${what}` : "")));
  }
  card.appendChild(list);
  if (!data.enabled) card.appendChild(h("p", { class: "hint" }, "Expected busy periods are not being explained (Health → When to warn)."));
  return card;
}
