import { h, shortName } from "../util.js";

// "Running out soon": the disks that fill up first, with the day they are full. Disks that are not growing are listed
// below as steady, so the card is never empty while there are monitored disks.
const SHOW = 5;

const daysText = (d) => (d < 1 ? "less than a day" : d < 2 ? "about a day" : d < 60 ? `${Math.round(d)} days` : `${Math.round(d / 30)} months`);

function row(item, urgent) {
  const lvl = item.days_to_full == null ? "" : item.days_to_full <= 3 ? "d-bad" : item.days_to_full <= 14 ? "d-warn" : "";
  const link = h("a", { href: `#/device/${item.device_id}`, onclick: () => { try { sessionStorage.setItem("netlens.devicetab", "health"); } catch (e) { /* ignore */ } } },
    `${shortName(item.device)}${item.label ? ` · ${item.label}` : ""}`);
  const when = item.days_to_full != null ? `full in ${daysText(item.days_to_full)}`
    : item.trend === "shrinking" ? "getting emptier"
      : item.trend === "steady" ? "steady" : `not enough history yet (${item.days_of_data} days)`;
  return h("li", { class: `cap-row ${lvl}` },
    h("span", { class: "cap-name" }, link),
    h("span", { class: "cap-bar", title: `${item.current}% used` }, h("span", { class: `cap-fill ${lvl}`, style: `width:${Math.min(100, item.current)}%` })),
    h("span", { class: "cap-when", title: item.full_on ? `expected full on ${item.full_on}` : "" }, `${Math.round(item.current)}% · ${when}`));
}

export function buildCapacityCard({ items }) {
  const filling = items.filter((i) => i.days_to_full != null);
  const rest = items.filter((i) => i.days_to_full == null);
  const lines = [];
  for (const i of filling.slice(0, SHOW)) lines.push(row(i, true));
  if (!filling.length) {
    for (const i of [...rest].sort((a, b) => b.current - a.current).slice(0, 3)) lines.push(row(i, false));
  }
  const head = filling.length
    ? h("p", { class: `hm-headline ${filling.some((i) => i.days_to_full <= 14) ? "d-warn" : "d-ok"}` },
      `${filling.length} ${filling.length === 1 ? "disk is" : "disks are"} filling up`)
    : h("p", { class: "hm-headline d-ok" }, "No disk is on course to fill up");
  const more = filling.length > SHOW ? h("p", { class: "hint" }, `and ${filling.length - SHOW} more`) : null;
  return h("div", { class: "cap" }, head, h("ul", { class: "cap-list" }, ...lines), more,
    h("p", { class: "hint" }, "Worked out from the last weeks of readings. A disk needs a few days of history first."));
}

export const capacityTone = (c) => {
  const f = c.items.filter((i) => i.days_to_full != null);
  if (f.some((i) => i.days_to_full <= 3)) return "bad";
  if (f.some((i) => i.days_to_full <= 14)) return "warn";
  return "ok";
};
