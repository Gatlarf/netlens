// The two things you can do with a graph besides looking at it: lay another measurement over it (Compare), and ask whether two
// measurements move together (Correlate, drawn as a scatter plot). Both pick a measurement of this or another device.
import { get } from "./api.js";
import { h } from "./util.js";
import { describeSeries } from "./seriesinfo.js";
import { formatValue, overlayColour } from "./timegraph.js";
import { canOverlay, describeCorrelation, niceScale } from "./graphmath.js";

const NS = "http://www.w3.org/2000/svg";
const el = (tag, attrs = {}) => {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
};

// ---------- what can be picked ----------
let deviceCache = null;
async function devices() {
  if (deviceCache && Date.now() - deviceCache.at < 60000) return deviceCache.list;
  let list = [];
  try {
    list = (await get("/api/map")).nodes.filter((n) => !String(n.id).startsWith("v")).map((n) => ({ id: n.id, name: n.label || n.ip || `device ${n.id}`, ip: n.ip }));
  } catch (err) {
    list = [];                                              // a customer view may not list devices: only the device at hand is offered
  }
  list.sort((a, b) => a.name.localeCompare(b.name));
  deviceCache = { at: Date.now(), list };
  return list;
}

async function seriesOf(entity, id) {
  try {
    const data = await get(`/api/timeseries/${entity}/${id}`);
    return data.series.map((s) => ({ ...s, title: describeSeries(s).title, unit: s.unit || describeSeries(s).unit || "" }))
      .sort((a, b) => describeSeries(a).order - describeSeries(b).order || a.label.localeCompare(b.label));
  } catch (err) {
    return [];
  }
}

const nameOf = (s) => (s.label ? `${s.title} · ${s.label}` : s.title);

// A device box (with type-ahead) and a measurement box. `onChange` fires when the measurement changes. `allow(unit)` can grey a measurement out.
async function picker({ entity, id, label, metric, mLabel = "", avoid = null, allow = () => true, onChange = () => {} }) {
  const all = entity === "device" ? await devices() : [];
  const here = all.find((d) => d.id === id) || { id, name: entity === "device" ? `device ${id}` : "this one" };
  const list = all.some((d) => d.id === id) || entity !== "device" ? all : [here, ...all];
  const names = new Map(list.map((d) => [d.name + (d.ip ? ` (${d.ip})` : ""), d]));
  const listId = `gt-dev-${Math.random().toString(36).slice(2, 8)}`;
  const deviceInput = h("input", { type: "text", list: listId, class: "gt-device", autocomplete: "off", value: here.name + (here.ip ? ` (${here.ip})` : ""), "aria-label": `${label}: device`, disabled: entity !== "device" });
  const datalist = h("datalist", { id: listId }, ...[...names.keys()].map((n) => h("option", { value: n })));
  const select = h("select", { class: "gt-metric", "aria-label": `${label}: measurement` });
  const note = h("div", { class: "hint gt-note" });
  let current = here;
  let currentSeries = [];

  async function fill(preferred) {
    currentSeries = await seriesOf(entity, current.id);
    select.replaceChildren();
    for (const s of currentSeries) {
      const ok = allow(s.unit);
      select.appendChild(h("option", { value: `${s.metric}\u0000${s.label}`, disabled: !ok, selected: false }, nameOf(s) + (s.unit ? ` (${s.unit})` : "") + (ok ? "" : " – another scale is already in use")));
    }
    const pick = (preferred && currentSeries.findIndex((s) => s.metric === preferred.metric && s.label === (preferred.label || "") && allow(s.unit)))
      ?? -1;
    const taken = (s) => avoid && current.id === id && s.metric === avoid.metric && s.label === (avoid.label || "");        // not the line that is already there
    let index = pick >= 0 && !taken(currentSeries[pick]) ? pick : currentSeries.findIndex((s) => allow(s.unit) && !taken(s));
    if (index < 0) index = currentSeries.findIndex((s) => allow(s.unit));
    if (index >= 0) select.selectedIndex = index;
    note.textContent = currentSeries.length ? "" : "This device has no measurements yet.";
    select.disabled = !currentSeries.length;
    onChange();
  }
  deviceInput.addEventListener("change", async () => {
    const found = names.get(deviceInput.value) || list.find((d) => d.name === deviceInput.value);
    if (!found) { note.textContent = "Choose a device from the list."; return; }
    current = found;
    await fill(null);
  });
  select.addEventListener("change", () => onChange());
  await fill(metric ? { metric, label: mLabel } : null);
  return {
    root: h("div", { class: "gt-picker" }, deviceInput, datalist, select, note),
    value() {
      const [m, l] = (select.value || "").split("\u0000");
      const s = currentSeries.find((x) => x.metric === m && x.label === (l || ""));
      return s ? { entity, id: current.id, metric: s.metric, label: s.label, unit: s.unit, title: nameOf(s), device: current.name, name: (current.id === id ? "" : `${current.name} · `) + nameOf(s) } : null;
    },
  };
}

function dialogShell(title, ...content) {
  const dialog = h("dialog", { class: "stepup-dialog gt-dialog", "aria-label": title });
  const close = () => { dialog.close(); dialog.remove(); };
  dialog.addEventListener("cancel", () => dialog.remove());
  document.body.appendChild(dialog);
  return { dialog, close, fill: (...nodes) => { dialog.replaceChildren(h("h2", {}, title), ...nodes); }, show: () => dialog.showModal() };
}

// ---------- Compare ----------
// Resolves to {entity, id, metric, label, unit, name} for the line to add, or null.
export function chooseOverlay({ entity, id, metric, label, title, unit, overlays }) {
  return new Promise(async (resolve) => {
    const shell = dialogShell(`Compare ${title} with`);
    const body = h("p", { class: "hint" }, "Loading…");
    shell.fill(body);
    shell.show();
    const allow = (u) => canOverlay(unit, overlays, u);
    const pick = await picker({ entity, id, label: "Compare", metric, mLabel: label, avoid: { metric, label }, allow });
    const error = h("p", { class: "error", role: "alert", hidden: true });
    const add = h("button", { class: "btn primary", type: "submit" }, "Add to the graph");
    const cancel = h("button", { class: "btn", type: "button" }, "Cancel");
    const done = (value) => { shell.close(); resolve(value); };
    cancel.addEventListener("click", () => done(null));
    shell.dialog.addEventListener("close", () => resolve(null));
    const form = h("form", { method: "dialog" },
      h("p", { class: "hint" }, "Pick another device, or another measurement of this one. A line in the same unit shares the scale; one in another unit gets its own scale on the right (one such unit at a time, up to three lines)."),
      h("div", { class: "field" }, h("label", {}, "Measurement"), pick.root), error, h("div", { class: "btn-row" }, add, cancel));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const value = pick.value();
      if (!value) { error.textContent = "Choose a measurement."; error.hidden = false; return; }
      if (value.entity === entity && value.id === id && value.metric === metric && value.label === label) { error.textContent = "That is the line already shown."; error.hidden = false; return; }
      if (overlays.some((o) => o.entity === value.entity && o.id === value.id && o.metric === value.metric && (o.label || "") === value.label)) { error.textContent = "That line is already on the graph."; error.hidden = false; return; }
      done({ entity: value.entity, id: value.id, metric: value.metric, label: value.label, unit: value.unit, name: value.name });
    });
    shell.fill(form);
  });
}

// ---------- Correlate ----------
export function scatter(data, { xTitle, yTitle, width = 560, height = 340 } = {}) {
  const L = 62, R = 14, T = 12, B = 44;
  const root = el("svg", { viewBox: `0 0 ${width} ${height}`, class: "gt-scatter", role: "img", "aria-label": `${yTitle} against ${xTitle}` });
  const xs = data.pairs.map((p) => p[1]), ys = data.pairs.map((p) => p[2]);
  const [x0, x1, xt] = niceScale(Math.min(...xs), Math.max(...xs));
  const [y0, y1, yt] = niceScale(Math.min(...ys), Math.max(...ys));
  const X = (v) => L + ((v - x0) / (x1 - x0)) * (width - L - R);
  const Y = (v) => T + (1 - (v - y0) / (y1 - y0)) * (height - T - B);
  for (const v of yt) {
    root.appendChild(el("line", { x1: L, x2: width - R, y1: Y(v), y2: Y(v), stroke: "currentColor", "stroke-opacity": 0.15 }));
    const t = el("text", { x: L - 6, y: Y(v) + 3, "text-anchor": "end", "font-size": 10, fill: "currentColor", "fill-opacity": 0.7 });
    t.textContent = formatValue(v, data.y.unit).replace(/ ?(ms|%)$/, (m) => m.trim());
    root.appendChild(t);
  }
  for (const v of xt) {
    root.appendChild(el("line", { x1: X(v), x2: X(v), y1: T, y2: height - B, stroke: "currentColor", "stroke-opacity": 0.08 }));
    const t = el("text", { x: X(v), y: height - B + 14, "text-anchor": "middle", "font-size": 10, fill: "currentColor", "fill-opacity": 0.7 });
    t.textContent = formatValue(v, data.x.unit).replace(/ ?(ms|%)$/, (m) => m.trim());
    root.appendChild(t);
  }
  const axisX = el("text", { x: (L + width - R) / 2, y: height - 6, "text-anchor": "middle", "font-size": 11, fill: "currentColor" });
  axisX.textContent = xTitle;
  const axisY = el("text", { x: 12, y: (T + height - B) / 2, "text-anchor": "middle", "font-size": 11, fill: "currentColor", transform: `rotate(-90 12 ${(T + height - B) / 2})` });
  axisY.textContent = yTitle;
  root.append(axisX, axisY);
  const colour = overlayColour(0);
  data.pairs.forEach((p, i) => {
    const c = el("circle", { cx: X(p[1]), cy: Y(p[2]), r: 3.4, fill: colour, "fill-opacity": 0.25 + 0.6 * (i / Math.max(1, data.pairs.length - 1)) });     // older readings are fainter
    const tip = el("title", {});
    tip.textContent = `${new Date(p[0] * 1000).toLocaleString()}: ${formatValue(p[1], data.x.unit)} and ${formatValue(p[2], data.y.unit)}`;
    c.appendChild(tip);
    root.appendChild(c);
  });
  if (data.r !== null && data.slope !== null) {
    const a = Math.max(x0, Math.min(...xs)), b = Math.min(x1, Math.max(...xs));
    root.appendChild(el("line", { x1: X(a), y1: Y(data.slope * a + data.intercept), x2: X(b), y2: Y(data.slope * b + data.intercept), stroke: "currentColor", "stroke-width": 1.6, "stroke-dasharray": "6 4", "stroke-opacity": 0.8 }));
  }
  return root;
}

// x: {entity, id, metric, label, title}; query: the period as the time series API wants it; windowText: the same in words
export async function openCorrelate({ x, query, windowText }) {
  const shell = dialogShell("Do these two move together?");
  shell.fill(h("p", { class: "hint" }, "Loading…"));
  shell.show();
  const area = h("div", { class: "gt-result" });
  let token = 0;
  async function run() {
    const a = left.value(), b = right.value();
    if (!a || !b) { area.replaceChildren(h("p", { class: "hint" }, "Choose a measurement on both sides.")); return; }
    const mine = ++token;
    area.replaceChildren(h("p", { class: "hint" }, "Working it out…"));
    const ref = (v) => `${v.entity}:${v.id}:${v.metric}${v.label ? ":" + v.label : ""}`;
    try {
      const data = await get(`/api/timeseries/correlate?x=${encodeURIComponent(ref(a))}&y=${encodeURIComponent(ref(b))}&${query}`);
      if (mine !== token) return;
      if (data.n < 3) { area.replaceChildren(h("p", { class: "hint" }, "These two have too few readings at the same moments in this period. Try a longer period, or another pair.")); return; }
      const strength = data.r === null ? null : Math.abs(data.r);
      area.replaceChildren(
        h("div", { class: "gt-verdict" }, h("span", { class: `gt-r ${strength === null ? "" : strength >= 0.6 ? "strong" : strength >= 0.4 ? "mid" : "weak"}` }, data.r === null ? "r = –" : `r = ${data.r.toFixed(2)}`),
          h("span", {}, describeCorrelation(data.r)), h("span", { class: "hint" }, `${data.n} readings paired`)),
        scatter(data, { xTitle: `${a.name}${a.unit ? ` (${a.unit})` : ""}`, yTitle: `${b.name}${b.unit ? ` (${b.unit})` : ""}` }),
        h("p", { class: "hint" }, "Moving together does not mean one causes the other: a third thing, such as the time of day, can drive both."));
    } catch (err) {
      if (mine === token) area.replaceChildren(h("p", { class: "error" }, err.message || "Could not work it out."));
    }
  }
  const left = await picker({ entity: x.entity, id: x.id, label: "First", metric: x.metric, mLabel: x.label, onChange: () => right && run() });
  // the second one starts on another measurement of the same device, so there is something to see at once
  const other = (await seriesOf(x.entity, x.id)).find((s) => !(s.metric === x.metric && s.label === (x.label || "")) && s.unit !== "state" && s.metric !== "uptime_s");          // one that varies: up/down and the time since start say little
  var right = null;
  right = await picker({ entity: x.entity, id: x.id, label: "Second", metric: other ? other.metric : null, mLabel: other ? other.label : "", onChange: () => right && run() });
  const close = h("button", { class: "btn", type: "button", onclick: shell.close }, "Close");
  shell.fill(
    h("p", { class: "hint" }, `Period: ${windowText}. Zoom a graph first to look at a shorter stretch.`),
    h("div", { class: "gt-pair" }, h("div", { class: "field" }, h("label", {}, "First"), left.root), h("div", { class: "field" }, h("label", {}, "Second"), right.root)),
    area, h("div", { class: "btn-row" }, close));
  run();
}
