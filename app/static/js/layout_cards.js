// Card layouts for pages made of cards in sections (the device page, Statistics): hide, reorder and resize cards with the editing kit of
// board.js. A layout is saved on the server per user and per page type (a device type, or "*" for all), with templates an administrator
// pushes to everybody. Cards are elements with data-card (an id), data-title and optionally data-kind and data-size (s, w or f).
import { get, put, del } from "./api.js";
import { h, toast } from "./util.js";
import { SIZE_NAME, controlBar, dragCard, nextSize, openDrawer } from "./board.js";

const flowsOf = (panel) => [...(panel.matches(".dev-flow, .stat-grid") ? [panel] : []), ...panel.querySelectorAll(".dev-flow, .stat-grid")];
const cardsIn = (flow) => [...flow.children].filter((c) => c.dataset && c.dataset.card);
const cardsOf = (panel) => flowsOf(panel).flatMap(cardsIn);
const defaultSize = (el) => el.dataset.size || (el.dataset.full === "1" ? "f" : "s");

export const emptyLayout = () => ({ order: {}, hidden: [], sizes: {} });

export async function loadLayout(page, type) {
  try {
    return await get(`/api/layouts/${page}?type=${encodeURIComponent(type || "*")}`);
  } catch (e) {
    return { effective: null, source: "builtin", mine: null, template: null, template_type: null };
  }
}

// Puts the cards of every panel in the order of the layout, hides what is hidden and gives every card its width.
export function applyLayout(panels, layout) {
  for (const [tab, panel] of Object.entries(panels)) {
    const wanted = layout && layout.order && layout.order[tab] ? layout.order[tab] : [];
    for (const flow of flowsOf(panel)) {
      const cards = cardsIn(flow);
      const rank = (c) => { const i = wanted.indexOf(c.dataset.card); return i < 0 ? 1e6 : i; };
      for (const c of [...cards].sort((a, b) => rank(a) - rank(b) || cards.indexOf(a) - cards.indexOf(b))) flow.appendChild(c);
    }
    for (const c of cardsOf(panel)) {
      c.hidden = !!(layout && layout.hidden.includes(c.dataset.card));
      setSize(c, layout && layout.sizes && layout.sizes[c.dataset.card] ? layout.sizes[c.dataset.card] : defaultSize(c));
    }
  }
}

function setSize(card, size) {
  card.dataset.currentSize = size;
  card.classList.remove("bd-s", "bd-w", "bd-f");
  card.classList.add(`bd-${size}`);
}

// The layout that matches what is on the screen now (the starting point for editing).
export function snapshot(panels) {
  const out = emptyLayout();
  for (const [tab, panel] of Object.entries(panels)) {
    const cards = cardsOf(panel);
    out.order[tab] = cards.map((c) => c.dataset.card);
    for (const c of cards) {
      if (c.hidden) out.hidden.push(c.dataset.card);
      if (c.dataset.currentSize && c.dataset.currentSize !== defaultSize(c)) out.sizes[c.dataset.card] = c.dataset.currentSize;
    }
  }
  return out;
}

// Editing mode: bars on the cards and the drawer. state: { doc (what loadLayout returned), set(layout) }. Returns a function that closes it.
export function startBoard({ page, panels, tabs, getTab, typeKey, typeLabel, isAdmin, state, onClose }) {
  let draft = snapshot(panels);
  let timer = null, pending = false;
  const root = document.querySelector(".view") || document.body;
  root.classList.add("bd-editing");

  const save = () => {                               // every change is kept: the layout is saved a moment after the last one
    clearTimeout(timer);
    pending = true;
    timer = setTimeout(async () => {
      pending = false;
      try {
        await put(`/api/layouts/${page}/mine?type=${encodeURIComponent(typeKey)}`, draft);
        state.doc = { ...state.doc, mine: draft, source: "mine", effective: draft };
      } catch (err) { toast(err.message || "Could not save the layout", "error"); }
    }, 500);
  };
  const changed = () => { applyLayout(panels, draft); state.set(draft); decorate(); save(); paint(); };
  const tabOf = (card) => Object.keys(panels).find((t) => cardsOf(panels[t]).includes(card));

  function decorate() {
    for (const [tab, panel] of Object.entries(panels)) {
      for (const flow of flowsOf(panel)) {
        for (const card of cardsIn(flow)) {
          card.classList.add("bd-card");
          for (const old of card.querySelectorAll(":scope > .bd-bar")) old.remove();
          if (card.hidden || !card.childElementCount) continue;
          const id = card.dataset.card;
          card.prepend(controlBar({
            size: card.dataset.currentSize,
            onGrip: (e) => dragCard(e, card, flow, () => {
              draft.order[tab] = cardsOf(panel).map((c) => c.dataset.card);
              state.set(draft); save();
            }),
            onSize: () => { draft.sizes[id] = nextSize(card.dataset.currentSize); if (draft.sizes[id] === defaultSize(card)) delete draft.sizes[id]; changed(); toast(`Width: ${SIZE_NAME[card.dataset.currentSize]}`, "info"); },
            onRemove: () => { if (!draft.hidden.includes(id)) draft.hidden.push(id); changed(); },
          }));
        }
      }
    }
  }

  async function reset(which) {
    try {
      const q = `?type=${encodeURIComponent(typeKey)}`;
      if (which === "template") { await del(`/api/layouts/${page}/template${q}`); await del(`/api/layouts/${page}/template?type=*`).catch(() => {}); }
      else await del(`/api/layouts/${page}/mine${q}`);
      state.doc = await loadLayout(page, typeKey);
      applyLayout(panels, state.doc.effective);
      draft = state.doc.effective || snapshot(panels);
      if (!state.doc.effective) { draft = emptyLayout(); applyLayout(panels, null); draft = snapshot(panels); }
      state.set(state.doc.effective);
      decorate(); paint();
      toast(which === "template" ? "Template removed" : "Back to the template or the built-in layout", "success");
    } catch (err) { toast(err.message || "Could not reset", "error"); }
  }
  async function template(all) {
    try {
      await put(`/api/layouts/${page}/template?type=${encodeURIComponent(all ? "*" : typeKey)}`, draft);
      state.doc = await loadLayout(page, typeKey);
      toast(`Saved as the template for ${all ? "all" : typeLabel} pages`, "success");
      paint();
    } catch (err) { toast(err.message || "Could not save the template", "error"); }
  }

  let drawer = null;
  let pickTab = getTab();
  function paint() {
    if (!drawer) return;
    const rows = cardsOf(panels[pickTab] || Object.values(panels)[0]).filter((c) => c.childElementCount > (c.querySelector(":scope > .bd-bar") ? 1 : 0) || draft.hidden.includes(c.dataset.card)).map((c) => ({
      id: c.dataset.card, title: c.dataset.title || c.dataset.card, kind: c.dataset.kind || "table", checked: !draft.hidden.includes(c.dataset.card),
      onToggle: (on) => { draft.hidden = on ? draft.hidden.filter((x) => x !== c.dataset.card) : [...draft.hidden, c.dataset.card]; changed(); },
    }));
    const src = state.doc && state.doc.source;
    const picker = h("select", { class: "bd-pick", "aria-label": "Section", onchange: (e) => { pickTab = e.target.value; paint(); } }, tabs.filter(([k]) => panels[k]).map(([k, l]) => h("option", { value: k, selected: k === pickTab }, l)));
    const head = [h("p", { class: "hint bd-pick" }, `${src === "mine" ? "Your own layout" : src === "template" ? "Your administrator's template" : "The built-in layout"} for ${typeLabel}. Drag the grip on a card, use ↔ for its width, ✕ to remove it; tick a card here to bring it back.`), picker];
    const foot = [
      state.doc && state.doc.mine ? h("button", { class: "btn", type: "button", onclick: () => reset("mine") }, "Reset") : null,
      ...(isAdmin ? [h("button", { class: "btn", type: "button", title: "Everybody starts from this arrangement and can still change it", onclick: () => template(false) }, `Template for ${typeLabel}`),
        h("button", { class: "btn", type: "button", onclick: () => template(true) }, "Template for all"),
        state.doc && state.doc.template ? h("button", { class: "btn", type: "button", onclick: () => reset("template") }, "Remove templates") : null] : []),
    ].filter(Boolean);
    drawer.update(rows, head);
    drawer.el.querySelector("footer").append(...foot);
  }

  drawer = openDrawer({ title: "Customize this page", rows: [], onClose: () => {
    clearTimeout(timer);
    if (pending) put(`/api/layouts/${page}/mine?type=${encodeURIComponent(typeKey)}`, draft).catch(() => {});       // a change the timer has not saved yet
    pending = false;
    root.classList.remove("bd-editing");
    for (const b of document.querySelectorAll(".bd-bar")) b.remove();
    if (onClose) onClose();
  } });
  decorate();
  paint();
  return { close: () => drawer.close(), setTab(t) { pickTab = t; paint(); } };
}
