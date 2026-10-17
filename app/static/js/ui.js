// Shared building blocks, so every page starts the same way: a title with one line of help and the page's actions on the
// right, summary tiles in one style, and an empty state that says what the page is for.
import { h } from "./util.js";

export function pageHead(title, hint, ...actions) {
  return h("div", { class: "page-head up-head" },
    h("div", { class: "page-title" }, h("h1", {}, title), hint ? h("p", { class: "hint" }, hint) : null),
    actions.length ? h("div", { class: "page-actions" }, ...actions) : null);
}

// One summary tile: a small title, a big value and a line below it. `tone` is ok, warn or bad (the coloured edge).
export function tile(title, value, sub, tone) {
  return h("section", { class: `dcard ${tone ? `tone-${tone}` : ""}` }, h("h2", { class: "d-title" }, title),
    h("div", { class: "d-body" }, h("div", { class: "d-value" }, String(value)), sub ? h("div", { class: "d-sub" }, sub) : null));
}

export function tileRow(...tiles) {
  return h("div", { class: "up-tiles" }, ...tiles.flat().filter(Boolean));
}

// What a page shows when there is nothing yet: what it is for, then what to do.
export function emptyState(title, text, ...actions) {
  return h("div", { class: "card empty-state" }, h("h2", {}, title), text ? h("p", { class: "hint" }, text) : null,
    actions.length ? h("div", { class: "page-actions" }, ...actions) : null);
}

// A card with a title row (title left, optional actions right) so cards on every page line up.
export function card(title, hint, ...children) {
  return h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, title), hint ? h("p", { class: "hint" }, hint) : null), ...children);
}

// A "⋯" menu for the rarely used actions of a table row, so a row shows one or two buttons instead of five.
// items: [{ label, onclick, danger }]
export function rowMenu(items, { label = "More actions", cls = "" } = {}) {
  const menu = h("details", { class: `row-menu ${cls}` }, h("summary", { class: "btn", "aria-label": label, title: label }, "⋯"),
    h("div", { class: "row-menu-list" }, items.map((it) => h("button", { type: "button", class: `menu-item${it.danger ? " danger-text" : ""}`,
      onclick: (e) => { menu.open = false; it.onclick(e); } }, it.label))));
  return menu;
}
document.addEventListener("click", (e) => { for (const d of document.querySelectorAll("details.row-menu[open]")) if (!d.contains(e.target)) d.open = false; });

// Tabs for a page with several parts: only the chosen part is shown, and the choice is remembered. defs: [[key, label, element or [elements]]]
export function tabbed(storageKey, defs) {
  let current = defs[0][0];
  try { const saved = localStorage.getItem(storageKey); if (defs.some((d) => d[0] === saved)) current = saved; } catch (e) { /* default */ }
  const nav = h("nav", { class: "dev-tabs", role: "tablist" });
  const panels = defs.map(([key, , content]) => h("div", { class: "tab-panel", "data-tab": key }, ...[content].flat()));
  const show = () => {
    for (const p of panels) p.hidden = p.dataset.tab !== current;
    for (const b of nav.children) { b.classList.toggle("active", b.dataset.tab === current); b.setAttribute("aria-selected", String(b.dataset.tab === current)); }
  };
  for (const [key, label] of defs) {
    nav.appendChild(h("button", { type: "button", role: "tab", class: "dev-tab", "data-tab": key, onclick: () => {
      current = key;
      try { localStorage.setItem(storageKey, key); } catch (e) { /* not remembered */ }
      show();
    } }, label));
  }
  show();
  return h("div", { class: "tabbed" }, nav, ...panels);
}

// Buttons that follow each other in a form (Save, Reset, Test ...) are put on one row instead of a column of wide bars.
export function groupButtons(root) {
  for (const form of root.querySelectorAll(".edit-form, form")) {
    let run = [];
    const flush = () => {
      if (run.length > 1) {
        const row = h("div", { class: "form-actions" });
        run[0].before(row);
        row.append(...run);
      }
      run = [];
    };
    for (const child of [...form.children]) {
      if (child.matches("button, a.btn") && !child.hidden) run.push(child); else flush();
    }
    flush();
  }
}
