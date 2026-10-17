import { get } from "../api.js";
import { h, clear, timeAgo } from "../util.js";
import { pageHead } from "../ui.js";

const PERIODS = [["6h", "6 hours"], ["24h", "24 hours"], ["3d", "3 days"], ["7d", "7 days"], ["30d", "30 days"]];
const SEEN_KEY = "netlens.changes.seen";
const PERIOD_KEY = "netlens.changes.period";

function stored(key) {
  try { return localStorage.getItem(key); } catch (e) { return null; }
}
function store(key, value) {
  try { localStorage.setItem(key, value); } catch (e) { /* no storage */ }
}

function dayHeading(iso) {
  const day = new Date(iso);
  const today = new Date();
  const same = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  const yesterday = new Date(today.getTime() - 86400000);
  if (same(day, today)) return "Today";
  if (same(day, yesterday)) return "Yesterday";
  return day.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" });
}

export async function render(container) {
  let disposed = false;
  let period = stored(PERIOD_KEY) || "24h";
  if (!PERIODS.some(([k]) => k === period)) period = "24h";
  let category = "";
  const lastSeen = stored(SEEN_KEY);       // what was new at the previous visit gets a mark
  let data = null;
  let timer = null;

  const periodBar = h("div", { class: "chg-periods", role: "group", "aria-label": "Period" });
  const chips = h("div", { class: "chg-chips" });
  const list = h("div", { class: "chg-list" });
  const summary = h("p", { class: "hint" });

  function drawPeriods() {
    clear(periodBar);
    for (const [key, label] of PERIODS) {
      periodBar.append(h("button", { type: "button", class: `btn${key === period ? " primary" : ""}`, "aria-pressed": String(key === period),
        onclick: () => { period = key; store(PERIOD_KEY, key); drawPeriods(); load(); } }, `Last ${label}`));
    }
  }

  function draw() {
    clear(chips);
    clear(list);
    if (!data) return;
    const names = data.categories;
    const all = Object.values(data.counts).reduce((a, b) => a + b, 0);
    chips.append(h("button", { type: "button", class: `chg-chip${category ? "" : " active"}`, onclick: () => { category = ""; load(); } }, `Everything (${all})`));
    for (const [key, label] of Object.entries(names)) {
      const n = data.counts[key] || 0;
      chips.append(h("button", { type: "button", class: `chg-chip chg-${key}${category === key ? " active" : ""}`, disabled: !n && category !== key,
        onclick: () => { category = category === key ? "" : key; load(); } }, `${label} (${n})`));
    }
    summary.textContent = data.total ? `${data.total} thing${data.total === 1 ? "" : "s"} happened${category ? " in this group" : ""}, newest first.` : "";
    if (!data.items.length) {
      list.append(h("div", { class: "card" }, h("p", {}, "Nothing changed in this period. ", h("span", { class: "hint" }, "A quiet network is a good network."))));
      return;
    }
    let day = "";
    let card = null;
    for (const it of data.items) {
      const heading = dayHeading(it.ts);
      if (heading !== day || !card) {
        day = heading;
        list.append(h("h2", { class: "chg-day" }, heading));
        card = h("div", { class: "card chg-card" });
        list.append(card);
      }
      const fresh = lastSeen && it.ts > lastSeen;
      const time = new Date(it.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
      card.append(h("div", { class: `chg-row${fresh ? " fresh" : ""}` },
        h("span", { class: "chg-time", title: it.ts }, time),
        h("span", { class: `chg-badge chg-${it.category}` }, names[it.category] || it.category),
        h("span", { class: "chg-text" }, it.who ? h("strong", {}, `${it.who}: `) : null, it.text,
          it.device_id ? [" ", h("a", { class: "chg-link", href: `#/device/${it.device_id}` }, `${it.device || "device"} →`)] : null),
        fresh ? h("span", { class: "chg-new", title: "Happened since you last looked" }, "new") : null));
    }
    if (data.total > data.items.length) list.append(h("p", { class: "hint" }, `The newest ${data.items.length} of ${data.total} are shown. Choose a group or a shorter period to see the rest.`));
  }

  async function load() {
    try {
      data = await get(`/api/changes?period=${period}${category ? `&category=${category}` : ""}`);
      if (!disposed) draw();
    } catch (err) {
      if (!disposed) { clear(list); list.append(h("p", { class: "error" }, err.message || "Could not load what changed")); }
    }
  }

  clear(container);
  container.append(
    pageHead("What changed", "New and missing devices, alerts, address and port changes and the changes people made, on one timeline. " +
      (lastSeen ? `Entries marked new happened after your last visit ${timeAgo(lastSeen)}.` : ""), periodBar),
    chips, summary, list);
  drawPeriods();
  await load();
  store(SEEN_KEY, new Date().toISOString().replace(/\.\d+Z$/, "Z"));
  timer = setInterval(() => { if (!document.hidden) load(); }, 60000);
  return () => { disposed = true; if (timer) clearInterval(timer); };
}
