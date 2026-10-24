// The editing kit shared by every page of cards (dashboard, device page, statistics): a bar on each card with a drag grip, a width button
// and a remove button, and a drawer on the right with a tick box and a small picture for every card that can be shown. This is the
// behaviour of the Overview beta page, made reusable (see contrib/UI-RULES.md).
import { h, clear } from "./util.js";

export const SIZE_STEPS = ["s", "w", "f"];                      // one column, two columns, the whole row
export const SIZE_NAME = { s: "narrow", w: "wide", f: "full width" };
export const nextSize = (size) => SIZE_STEPS[(Math.max(0, SIZE_STEPS.indexOf(size)) + 1) % SIZE_STEPS.length];

// a tiny sketch of a card for the drawer, so the choice is visual
export function thumb(kind) {
  const bars = (n) => h("div", { class: "mk-th mk-th-bars" }, ...Array.from({ length: n }, (_, i) => h("i", { style: `height:${25 + ((i * 37) % 60)}%` })));
  if (kind === "donut") return h("div", { class: "mk-th mk-th-donut" }, h("i", {}), h("b", {}));
  if (kind === "list") return h("div", { class: "mk-th mk-th-list" }, ...[90, 70, 45, 30].map((w) => h("i", { style: `width:${w}%` })));
  if (kind === "table") return h("div", { class: "mk-th mk-th-table" }, ...Array.from({ length: 4 }, () => h("i", {})));
  if (kind === "tiles") return h("div", { class: "mk-th mk-th-tiles" }, ...Array.from({ length: 4 }, () => h("i", {})));
  return kind === "line" ? h("div", { class: "mk-th mk-th-line" }, h("i", {})) : bars(14);
}

// the bar on a card in editing mode
export function controlBar({ onGrip, onSize, onRemove, size, extra = [] }) {
  const grip = h("span", { class: "bd-grip", title: "Drag to move", "aria-label": "Drag to move", role: "button" }, "⋮⋮");
  grip.addEventListener("pointerdown", onGrip);
  const sizeBtn = h("button", { class: "bd-btn bd-size", type: "button", title: `Width: ${SIZE_NAME[size] || "narrow"}. Press to change it.`, "aria-label": "Change the width", onclick: onSize }, "↔");
  return h("div", { class: "bd-bar" }, ...extra, grip, sizeBtn, h("button", { class: "bd-btn", type: "button", title: "Remove from this page", "aria-label": "Remove", onclick: onRemove }, "✕"));
}

// Drag a card by its grip (mouse and touch): it follows the pointer, the others make room, onDrop gets the new order of the container.
export function dragCard(e, box, container, onDrop) {
  if (e.button !== undefined && e.button !== 0) return;
  e.preventDefault();
  const rect = box.getBoundingClientRect();
  const offX = e.clientX - rect.left, offY = e.clientY - rect.top;
  const ghost = box.cloneNode(true);
  ghost.classList.add("mk-ghost");
  ghost.style.width = `${rect.width}px`; ghost.style.height = `${rect.height}px`;
  document.body.appendChild(ghost);
  box.classList.add("mk-moving");
  const place = (x, y) => { ghost.style.left = `${x - offX}px`; ghost.style.top = `${y - offY}px`; };
  place(e.clientX, e.clientY);
  const move = (ev) => {
    place(ev.clientX, ev.clientY);
    if (ev.clientY < 70) window.scrollBy(0, -18); else if (ev.clientY > innerHeight - 70) window.scrollBy(0, 18);
    ghost.style.display = "none";
    const under = document.elementFromPoint(ev.clientX, ev.clientY);
    ghost.style.display = "";
    const over = under && under.closest("[data-card]");
    if (!over || over === box || over.parentElement !== container) return;
    const kids = [...container.children];
    if (kids.indexOf(box) < kids.indexOf(over)) over.after(box); else over.before(box);      // swap places with the card under the pointer
  };
  const up = () => {
    window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); window.removeEventListener("pointercancel", up);
    ghost.remove(); box.classList.remove("mk-moving");
    onDrop([...container.children].filter((c) => c.dataset && c.dataset.card).map((c) => c.dataset.card));
  };
  window.addEventListener("pointermove", move); window.addEventListener("pointerup", up); window.addEventListener("pointercancel", up);
}

// The drawer on the right. rows: [{id, title, about, kind, checked, onToggle(checked)}]; head: extra elements under the title (a section picker);
// footer: buttons. Returns {el, update(rows), close()}.
export function openDrawer({ title, head = [], rows, footer = [], onClose }) {
  const el = h("aside", { class: "bd-drawer", role: "dialog", "aria-label": title });
  document.body.appendChild(el);
  document.body.classList.add("bd-open");
  const api = {
    el,
    close() { el.remove(); document.body.classList.remove("bd-open"); if (onClose) onClose(); },
    update(next, nextHead) {
      clear(el);
      const list = h("div", { class: "mk-opts" });
      for (const r of [...next].sort((a, b) => Number(b.checked) - Number(a.checked))) {
        const box = h("input", { type: "checkbox", id: `bd-${r.id}`, checked: r.checked, onchange: (e) => r.onToggle(e.target.checked) });
        list.appendChild(h("label", { class: "mk-opt", for: `bd-${r.id}` }, h("span", { class: "mk-opt-title" }, box, r.title), r.about ? h("span", { class: "hint" }, r.about) : null, thumb(r.kind), r.extra && r.extra.length ? h("span", { class: "bd-extra" }, ...r.extra) : null));
      }
      el.append(h("header", {}, h("h2", {}, title), h("button", { class: "mk-x", type: "button", "aria-label": "Close", onclick: () => api.close() }, "×")), ...(nextHead || head), list,
        h("footer", {}, h("button", { class: "btn primary", type: "button", onclick: () => api.close() }, "Done"), ...footer));
    },
  };
  api.update(rows);
  return api;
}
