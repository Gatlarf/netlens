// Shared building blocks, so every page starts the same way: a title with one line of help and the page's actions on the
// right, summary tiles in one style, and an empty state that says what the page is for.
import { h } from "./util.js";

// `hint` says what the page does; it sits behind a "?" next to the title so the content starts higher and every page begins the same way.
export function pageHead(title, hint, ...actions) {
  return h("div", { class: "page-head up-head" },
    h("div", { class: "page-title" }, h("h1", {}, title, hint ? infoTip(hint) : null)),
    actions.length ? h("div", { class: "page-actions" }, ...actions) : null);
}

// A small "?" that shows a sentence of explanation on hover, on focus and on a tap. It keeps a page quiet: the explanation is there when asked for.
export function infoTip(text) {
  const tip = h("span", { class: "info-tip", tabindex: "0", role: "note", "aria-label": text, "data-tip": text }, "?");
  tip.addEventListener("click", (e) => e.stopPropagation());       // inside a clickable tile the tap must not follow the tile
  return tip;
}

// One summary tile: a small title (with a "?" that explains it), a big value. Every tile has the same low height. `tone` is ok, warn or bad (the coloured edge).
// `sub` is the explanation behind the "?". href (a #/ address) or onClick makes the whole tile clickable: a problem on a tile leads to the place where it can be seen.
export function tile(title, value, sub, tone, target) {
  const node = h("section", { class: `dcard ${tone ? `tone-${tone}` : ""}` }, h("h2", { class: "d-title" }, title, sub ? infoTip(sub) : null),
    h("div", { class: "d-body" }, h("div", { class: "d-value" }, String(value))));
  if (target) {
    const go = () => (typeof target === "function" ? target() : (location.hash = target));
    node.classList.add("clickable-tile");
    node.setAttribute("role", "link");
    node.tabIndex = 0;
    node.addEventListener("click", go);
    node.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  }
  return node;
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
// A button that opens a small panel holding any controls (selects, buttons), for a toolbar that would otherwise be a wall of controls.
export function popMenu(label, controls, { cls = "", title = "" } = {}) {
  return h("details", { class: `row-menu pop-menu ${cls}` }, h("summary", { class: "btn", title }, `${label} ▾`), h("div", { class: "row-menu-list pop-menu-list" }, controls));
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

// A full-screen preview of a generated page (the network documentation) inside the app, with its own Back, Print and Download buttons:
// an installed app has no browser buttons, so a page opened in a new tab or window cannot be left again. The phone's back gesture and Esc close it too.
export async function previewHtml(title, url, downloadUrl) {
  const res = await fetch(url, { credentials: "same-origin" });
  if (!res.ok) throw new Error(res.status === 403 ? "this needs an administrator" : `could not load the preview (${res.status})`);
  const html = await res.text();
  const frame = h("iframe", { class: "preview-frame", title, sandbox: "allow-same-origin allow-modals" });
  frame.srcdoc = html;
  let pushed = false, closed = false;
  const close = (fromHistory = false) => {
    if (closed) return;
    closed = true;
    document.removeEventListener("keydown", onKey);
    window.removeEventListener("popstate", onPop);
    overlay.remove();
    document.body.classList.remove("preview-open");
    if (pushed && !fromHistory) history.back();
  };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const onPop = () => close(true);
  const overlay = h("div", { class: "preview-overlay", role: "dialog", "aria-label": title },
    h("div", { class: "preview-bar" }, h("button", { class: "btn", type: "button", onclick: () => close() }, "← Back"), h("strong", { class: "preview-title" }, title),
      h("span", { class: "preview-actions" }, h("button", { class: "btn", type: "button", onclick: () => frame.contentWindow.print() }, "Print"),
        downloadUrl ? h("a", { class: "btn", href: downloadUrl, download: "" }, "Download") : null)),
    frame);
  document.body.append(overlay);
  document.body.classList.add("preview-open");
  try { history.pushState({ preview: true }, "", location.href); pushed = true; } catch (e) { /* the buttons still work */ }
  document.addEventListener("keydown", onKey);
  window.addEventListener("popstate", onPop);
  overlay.querySelector("button").focus();
}

// "Connect as <login>" with a small × beside it that forgets that saved login. The two sit together, so it is clear what the × belongs to.
export function savedLoginButton(label, onConnect, onForget) {
  return h("span", { class: "btn-split" },
    h("button", { type: "button", class: "btn", onclick: onConnect }, label),
    h("button", { type: "button", class: "btn btn-split-x", title: "Forget this saved login", "aria-label": "Forget this saved login", onclick: onForget }, "×"));
}

// Settings pages: long explanations sit behind a "?" next to the heading or the field they belong to, so a page shows its controls first.
// A short hint (a unit, "0 = never") stays where it is. Run on every redraw; a hint that was moved is not looked at again.
const HELP_LONG = 70, HELP_FIELD = 48;
function helpTip(hint) {
  const body = h("div", { class: "help-body", role: "note" });
  body.append(...hint.childNodes);
  const tip = h("span", { class: "help-tip", "data-help": "1" },
    h("button", { type: "button", class: "help-btn", "aria-label": "Explanation", "aria-expanded": "false" }, "?"), body);
  return tip;
}
export function compactHelp(root) {
  const text = (el) => (el.textContent || "").trim();
  for (const hint of root.querySelectorAll("p.hint, .field > .hint, .check-field > .hint, .inline-setting > .hint")) {
    if (hint.closest(".help-body") || hint.querySelector("input, select, textarea, button")) continue;
    const len = text(hint).length;
    const inField = hint.matches(".field > .hint, .check-field > .hint, .inline-setting > .hint");
    if (len < (inField ? HELP_FIELD : HELP_LONG)) continue;
    let anchor = null;
    if (inField) {
      anchor = hint.parentElement.querySelector(":scope > label, :scope > .check-label, :scope > h4");
    } else {
      let prev = hint.previousElementSibling;
      while (prev && prev.matches(".help-tip, .hint")) prev = prev.previousElementSibling;
      if (prev && prev.matches("h1, h2, h3, h4, legend, .card-title, .card-head")) anchor = prev.matches(".card-head") ? (prev.querySelector("h2, h3") || prev) : prev;
      else if (prev && prev.matches(".field, .check-field, label, .inline-setting")) anchor = prev.matches("label") ? prev : prev.querySelector("label");
      else if (!prev && hint.parentElement) anchor = hint.parentElement.querySelector(":scope > h2, :scope > h3, :scope > legend");
    }
    if (!anchor) continue;
    let tip = anchor.querySelector(":scope > .help-tip");
    if (tip) { tip.querySelector(".help-body").append(h("br"), ...hint.childNodes); }
    else { tip = helpTip(hint); anchor.appendChild(tip); }
    hint.remove();
  }
}
document.addEventListener("click", (event) => {
  const btn = event.target.closest && event.target.closest(".help-btn");
  for (const open of document.querySelectorAll(".help-tip.open")) {
    if (!btn || open !== btn.parentElement) { open.classList.remove("open"); open.firstChild.setAttribute("aria-expanded", "false"); }
  }
  if (btn) {
    event.preventDefault();
    const tip = btn.parentElement, on = !tip.classList.contains("open");
    tip.classList.toggle("open", on);
    btn.setAttribute("aria-expanded", String(on));
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") for (const open of document.querySelectorAll(".help-tip.open")) open.classList.remove("open");
});
