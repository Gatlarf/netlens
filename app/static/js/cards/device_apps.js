import { get } from "../api.js";
import { h } from "../util.js";
import { barList, columnChart, emptyNote, fmtBytes, fmtNumber } from "../charts.js";

const PERIODS = [[1, "Today"], [7, "7 days"], [30, "30 days"]];

// What one device used the traffic for, as the router's traffic analyser counts it. Returns null when application statistics are off
// or the router has nothing for this device, so the card only exists where it has something to say.
export async function buildDeviceApplicationsCard(device) {
  let days = 7, by = "applications";
  let last = null;
  const first = await get(`/api/devices/${device.id}/applications?days=${days}`).catch(() => null);
  if (!first || !first.available) return null;
  const card = h("div", { class: "card device-apps-card" });
  const body = h("div", {});
  async function draw(data) {
    last = data;
    body.replaceChildren();
    const total = data.rx + data.tx;
    body.appendChild(h("p", { class: "hint" }, `${fmtBytes(data.rx)} downloaded, ${fmtBytes(data.tx)} uploaded${data.days > 1 ? ` over ${fmtNumber(data.days)} days` : ""}.`));
    const list = by === "categories" ? data.categories : data.applications;
    if (list.length) {
      body.appendChild(barList(list.map((a) => ({ label: a.name, count: a.rx + a.tx, text: `${fmtBytes(a.rx + a.tx)} · ${Math.round(a.share)}%` }))));
    } else {
      body.appendChild(emptyNote(total ? "The router did not tell which applications this device used." : "No traffic."));
    }
    if (data.per_day.length > 1) body.appendChild(columnChart(data.per_day.map((r) => ({ x: r.day, v: r.rx + r.tx }))));
  }
  const tabs = h("div", { class: "range-tabs", role: "group", "aria-label": "Period" });
  for (const [n, text] of PERIODS) {
    const b = h("button", { type: "button", "aria-pressed": String(n === days) }, text);
    b.addEventListener("click", async () => {
      days = n;
      for (const o of tabs.children) o.setAttribute("aria-pressed", String(o === b));
      try { await draw(await get(`/api/devices/${device.id}/applications?days=${n}`)); } catch (err) { body.replaceChildren(emptyNote("Could not load.")); }
    });
    tabs.appendChild(b);
  }
  const kinds = h("div", { class: "range-tabs", role: "group", "aria-label": "Group by" });
  if (first.detail === "names") {
    for (const [kind, text] of [["applications", "Applications"], ["categories", "Categories"]]) {
      const b = h("button", { type: "button", "aria-pressed": String(kind === by) }, text);
      b.addEventListener("click", () => { by = kind; for (const o of kinds.children) o.setAttribute("aria-pressed", String(o === b)); draw(last); });
      kinds.appendChild(b);
    }
  }
  card.append(h("div", { class: "upc-head" }, h("h2", {}, first.detail === "names" ? "Applications" : "Categories"), kinds, tabs), body);
  await draw(first);
  return card;
}
