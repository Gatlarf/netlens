// Card layouts for pages made of cards (the device page): hide, reorder and widen cards, saved on the server per user and per device type,
// with templates an administrator pushes to everybody. Cards are elements with data-card (an id) and data-title; a panel holds them in
// one ".dev-flow" container.
import { get, put, del } from "./api.js";
import { h, clear, toast } from "./util.js";

const flowOf = (panel) => (panel.classList.contains("dev-flow") ? panel : panel.querySelector(".dev-flow"));
const cardsOf = (panel) => { const flow = flowOf(panel); return flow ? [...flow.children].filter((c) => c.dataset && c.dataset.card) : []; };

export const emptyLayout = () => ({ order: {}, hidden: [], full: [] });

export async function loadLayout(type) {
  try {
    return await get(`/api/layouts/device?type=${encodeURIComponent(type || "*")}`);
  } catch (e) {
    return { effective: null, source: "builtin", mine: null, template: null, template_type: null };
  }
}

// Puts the cards of every panel in the order of the layout, hides what is hidden and widens what is full width.
export function applyLayout(panels, layout) {
  for (const [tab, panel] of Object.entries(panels)) {
    const flow = flowOf(panel);
    if (!flow) continue;
    const cards = cardsOf(panel);
    const wanted = layout && layout.order && layout.order[tab] ? layout.order[tab] : [];
    const rank = (c) => { const i = wanted.indexOf(c.dataset.card); return i < 0 ? 1e6 : i; };
    const sorted = [...cards].sort((a, b) => rank(a) - rank(b) || cards.indexOf(a) - cards.indexOf(b));
    for (const c of sorted) {
      flow.appendChild(c);
      c.hidden = !!(layout && layout.hidden.includes(c.dataset.card));
      c.classList.toggle("dev-full", layout ? layout.full.includes(c.dataset.card) : c.dataset.full === "1");
    }
  }
}

// The layout that matches what is on the screen now (used as the starting point for editing).
export function snapshot(panels) {
  const out = emptyLayout();
  for (const [tab, panel] of Object.entries(panels)) {
    const cards = cardsOf(panel);
    out.order[tab] = cards.map((c) => c.dataset.card);
    for (const c of cards) {
      if (c.hidden) out.hidden.push(c.dataset.card);
      if (c.classList.contains("dev-full")) out.full.push(c.dataset.card);
    }
  }
  return out;
}

const TAB_LABEL = (tabs, key) => (tabs.find(([k]) => k === key) || [key, key])[1];

// state: { layout (the loaded document), set(layout) }. Returns a function that closes the drawer.
export function openCustomizer({ panels, tabs, activeTab, deviceType, typeLabel, isAdmin, state, onClose }) {
  let tab = activeTab;
  let draft = snapshot(panels);
  const drawer = h("aside", { class: "lay-drawer", role: "dialog", "aria-label": "Customize this page" });
  document.body.appendChild(drawer);

  const redraw = () => { applyLayout(panels, draft); state.set(draft); paint(); };
  const move = (id, by) => {
    const list = draft.order[tab] || [];
    const i = list.indexOf(id);
    const j = i + by;
    if (i < 0 || j < 0 || j >= list.length) return;
    [list[i], list[j]] = [list[j], list[i]];
    redraw();
  };
  const flip = (list, id) => { const i = list.indexOf(id); if (i < 0) list.push(id); else list.splice(i, 1); redraw(); };

  async function save(kind) {
    try {
      const q = `?type=${encodeURIComponent(kind.all ? "*" : deviceType)}`;
      if (kind.template) await put(`/api/layouts/device/template${q}`, draft);
      else await put(`/api/layouts/device/mine${q}`, draft);
      toast(kind.template ? `Saved as the template for ${kind.all ? "all devices" : typeLabel}` : "Saved: this is your layout now", "success");
      Object.assign(state, { doc: await loadLayout(deviceType) });
    } catch (err) { toast(err.message || "Could not save the layout", "error"); }
  }
  async function reset(kind) {
    try {
      const q = `?type=${encodeURIComponent(deviceType)}`;
      await del(kind === "template" ? `/api/layouts/device/template${q}` : `/api/layouts/device/mine${q}`);
      if (kind === "template") await del("/api/layouts/device/template?type=*").catch(() => {});
      state.doc = await loadLayout(deviceType);
      draft = state.doc.effective || emptyLayout();
      applyLayout(panels, state.doc.effective);
      if (!state.doc.effective) draft = snapshot(panels);
      state.set(state.doc.effective);
      paint();
      toast(kind === "template" ? "Template removed" : "Back to the template or the built-in layout", "success");
    } catch (err) { toast(err.message || "Could not reset", "error"); }
  }

  function paint() {
    clear(drawer);
    const src = state.doc && state.doc.source;
    drawer.append(
      h("div", { class: "lay-head" }, h("strong", {}, "Customize"), h("button", { class: "btn ghost", type: "button", "aria-label": "Close", onclick: () => close() }, "✕")),
      h("p", { class: "hint" }, src === "mine" ? "You are using your own layout." : src === "template" ? "You are using the template of your administrator." : "You are using the built-in layout.",
        ` Changes apply to ${typeLabel} devices.`),
      h("select", { class: "lay-tab", "aria-label": "Section", onchange: (e) => { tab = e.target.value; paint(); } }, tabs.filter(([k]) => panels[k]).map(([k, l]) => h("option", { value: k, selected: k === tab }, l))));
    const list = h("ul", { class: "lay-list" });
    const ids = draft.order[tab] || [];
    for (const card of cardsOf(panels[tab]).filter((c) => c.childElementCount || draft.hidden.includes(c.dataset.card))) {
      const id = card.dataset.card;
      list.appendChild(h("li", {}, h("label", { class: "lay-show" }, h("input", { type: "checkbox", checked: !draft.hidden.includes(id), onchange: () => flip(draft.hidden, id) }), " ", card.dataset.title || id),
        h("span", { class: "lay-tools" },
          h("label", { class: "hint", title: "Use the full width of the page" }, h("input", { type: "checkbox", checked: draft.full.includes(id), onchange: () => flip(draft.full, id) }), " wide"),
          h("button", { class: "btn ghost", type: "button", disabled: ids.indexOf(id) <= 0, "aria-label": "Move up", onclick: () => move(id, -1) }, "▲"),
          h("button", { class: "btn ghost", type: "button", disabled: ids.indexOf(id) >= ids.length - 1, "aria-label": "Move down", onclick: () => move(id, 1) }, "▼"))));
    }
    drawer.appendChild(list);
    const actions = h("div", { class: "lay-actions" },
      h("button", { class: "btn primary", type: "button", onclick: () => save({}) }, "Save for me"),
      state.doc && state.doc.mine ? h("button", { class: "btn", type: "button", onclick: () => reset("mine") }, "Reset my layout") : null);
    drawer.appendChild(actions);
    if (isAdmin) {
      drawer.appendChild(h("div", { class: "lay-actions" },
        h("p", { class: "hint" }, "As administrator you can give everybody a starting layout. Users can still change it for themselves."),
        h("button", { class: "btn", type: "button", onclick: () => save({ template: true }) }, `Use as template for ${typeLabel}`),
        h("button", { class: "btn", type: "button", onclick: () => save({ template: true, all: true }) }, "Use as template for all devices"),
        state.doc && state.doc.template ? h("button", { class: "btn", type: "button", onclick: () => reset("template") }, "Remove the templates") : null));
    }
  }

  function close() { drawer.remove(); document.body.classList.remove("lay-editing"); if (onClose) onClose(); }
  document.body.classList.add("lay-editing");
  paint();
  return close;
}
