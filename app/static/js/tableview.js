// Table views: a table whose columns the reader chooses, orders and sizes, with views that can be saved, switched and shared.
//
//   const tv = await createTableViews({ table: "devices", catalog, builtins, locked: ["status", "name"], getFilters, setFilters, onChange });
//   tv.table / tv.tbody   the table to put on the page (the page fills the body with rows made of tv.rowCells(row))
//   tv.controls           the "View" menu and the "Columns" button for the toolbar
//
// catalog: [{key, label, group, sort(row) -> number|text|null, cell(row, ctx) -> node|text, text(row) -> plain text, extra?: "link"|"wifi"|"uptime", min?: px}]
// builtins: [{id, name, columns, sort?, filters?}]. A view is kept per user on the server; an administrator can share one with everybody.
import { get, put } from "./api.js";
import { h, toast, isAdmin } from "./util.js";
import { formDialog } from "./formdialog.js";
import { normalise, sameView, moveColumn, dropColumn, toggleColumn, sortRows, tableCsv, MIN_WIDTH } from "./tableviewmath.js";

const GROUP_ORDER = ["Basics", "Network", "Wi-Fi", "System", "Health"];

export async function createTableViews({ table, catalog, builtins, locked, getFilters = () => ({}), setFilters = () => {}, transient = ["q"], onChange = () => {}, tableClass = "data", trailing = false, groups = GROUP_ORDER }) {
  const known = catalog.map((c) => c.key);
  const byKey = new Map(catalog.map((c) => [c.key, c]));
  const draftKey = `netlens.tv.${table}.draft`;
  let server = { views: [], shared: [], active: null };
  let canSave = true;
  try {
    const got = await get(`/api/me/table-views/${table}`);
    server = { views: got.views || [], shared: got.shared || [], active: got.active || null };
  } catch (err) {
    canSave = false;                      // the views of this user cannot be read: the built-in ones still work
  }

  const find = (id) => {
    if (id && id.startsWith("builtin:")) return builtins.find((b) => `builtin:${b.id}` === id) || null;
    if (id && id.startsWith("shared:")) return server.shared.find((v) => `shared:${v.id}` === id) || null;
    return server.views.find((v) => v.id === id) || null;
  };
  let activeId = find(server.active) ? server.active : `builtin:${builtins[0].id}`;
  const fromHash = /[?&]view=([a-z0-9-]+)/.exec(location.hash);           // "#/devices?view=network" opens that built-in view
  if (fromHash && builtins.some((b) => b.id === fromHash[1])) activeId = `builtin:${fromHash[1]}`;
  const withoutTransient = (f) => Object.fromEntries(Object.entries(f || {}).filter(([k, v]) => v && !transient.includes(k)));
  const norm = (v) => normalise({ ...v, filters: withoutTransient(v.filters) }, known, locked);
  let view = norm(find(activeId));
  let base = view;
  try {                                    // changes that were not saved are still there after a reload
    const draft = JSON.parse(localStorage.getItem(draftKey) || "null");
    if (draft && draft.active === activeId && draft.view) view = norm(draft.view);
  } catch (err) { /* no draft */ }

  const draw = { sort: null, dragging: null };
  const table_ = h("table", { class: `${tableClass} tv-table` });
  const thead = h("thead");
  const tbody = h("tbody");
  table_.append(thead, tbody);

  const currentFilters = () => withoutTransient(getFilters());
  const workingView = () => ({ ...view, filters: currentFilters() });
  const dirty = () => !sameView(workingView(), base, known, locked);
  const nameOf = (id) => (find(id) ? find(id).name : "Standard");
  const writable = () => activeId.startsWith("shared:") ? isAdmin() : !activeId.startsWith("builtin:");

  function keepDraft() {
    try {
      if (dirty()) localStorage.setItem(draftKey, JSON.stringify({ active: activeId, view: workingView() })); else localStorage.removeItem(draftKey);
    } catch (err) { /* not kept */ }
  }

  let saveTimer = null;
  function persistActive() {
    if (!canSave) return;
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => put(`/api/me/table-views/${table}`, { views: server.views, active: activeId }).catch(() => {}), 400);
  }

  // ---------- the table head ----------
  function setWidths() {
    const any = Object.keys(view.widths).length > 0;
    table_.style.tableLayout = any ? "fixed" : "";
    table_.style.width = any ? `${view.columns.reduce((a, k) => a + (view.widths[k] || byKey.get(k).min || 110), 0) + (trailing ? 150 : 0)}px` : "";
    for (const th of thead.querySelectorAll("th[data-key]")) {
      const w = view.widths[th.dataset.key];
      th.style.width = any ? `${w || byKey.get(th.dataset.key).min || 110}px` : "";
    }
  }

  function buildHead() {
    const row = h("tr");
    for (const key of view.columns) {
      const col = byKey.get(key);
      const sorted = view.sort && view.sort.key === key;
      const th = h("th", { "data-key": key, "aria-label": col.label ? null : (col.title || key), class: `${col.sort ? "sortable" : ""}${sorted ? ` sorted-${view.sort.dir}` : ""}`, "aria-sort": sorted ? (view.sort.dir === "asc" ? "ascending" : "descending") : "none" },
        h("span", { class: "tv-th-label" }, col.label));
      if (col.sort) {
        th.addEventListener("click", () => {
          view = { ...view, sort: sorted ? { key, dir: view.sort.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" } };
          changed("sort");
        });
      }
      if (!locked.includes(key)) {                                    // drag a heading to move the column
        th.draggable = true;
        th.addEventListener("dragstart", (e) => { draw.dragging = key; e.dataTransfer.effectAllowed = "move"; try { e.dataTransfer.setData("text/plain", key); } catch (err) { /* some browsers insist */ } th.classList.add("tv-dragging"); });
        th.addEventListener("dragend", () => { draw.dragging = null; for (const t of thead.querySelectorAll(".tv-dragging, .tv-over")) t.classList.remove("tv-dragging", "tv-over"); });
      }
      th.addEventListener("dragover", (e) => { if (draw.dragging && draw.dragging !== key) { e.preventDefault(); th.classList.add("tv-over"); } });
      th.addEventListener("dragleave", () => th.classList.remove("tv-over"));
      th.addEventListener("drop", (e) => {
        e.preventDefault();
        if (!draw.dragging) return;
        view = { ...view, columns: dropColumn(view.columns, draw.dragging, key, locked) };
        draw.dragging = null;
        changed("columns");
      });
      const grip = h("span", { class: "col-grip", "aria-hidden": "true", title: "Drag to resize; double-click for the automatic width", draggable: "false" });
      grip.addEventListener("click", (e) => e.stopPropagation());
      grip.addEventListener("mousedown", (e) => e.stopPropagation());
      grip.addEventListener("dblclick", (e) => { e.stopPropagation(); const w = { ...view.widths }; delete w[key]; view = { ...view, widths: Object.keys(w).length ? w : {} }; changed("widths"); });
      grip.addEventListener("pointerdown", (e) => {
        e.preventDefault(); e.stopPropagation();
        const widths = {};
        for (const t of thead.querySelectorAll("th[data-key]")) widths[t.dataset.key] = Math.round(t.getBoundingClientRect().width);      // freeze what is on screen, then change this column
        view = { ...view, widths };
        setWidths();
        const startX = e.clientX, startW = widths[key];
        grip.setPointerCapture(e.pointerId);
        grip.classList.add("dragging");
        const move = (ev) => { view.widths[key] = Math.max(col.min ? Math.min(col.min, MIN_WIDTH + 24) : MIN_WIDTH, Math.round(startW + ev.clientX - startX)); setWidths(); };
        const stop = () => { grip.classList.remove("dragging"); grip.removeEventListener("pointermove", move); grip.removeEventListener("pointerup", stop); grip.removeEventListener("pointercancel", stop); changed("widths"); };
        grip.addEventListener("pointermove", move); grip.addEventListener("pointerup", stop); grip.addEventListener("pointercancel", stop);
      });
      th.appendChild(grip);
      row.appendChild(th);
    }
    if (trailing) row.appendChild(h("th", { class: "tv-trailing", "aria-label": "Actions" }));        // the buttons at the end of a row: not a column, always there
    thead.replaceChildren(row);
    setWidths();
  }

  // ---------- rows ----------
  const ctx = () => ({ has: (key) => view.columns.includes(key) });
  function rowCells(row) {
    const context = ctx();
    return view.columns.map((key) => {
      const col = byKey.get(key);
      const value = col.cell ? col.cell(row, context) : (col.text ? col.text(row) : "");
      const td = h("td", { "data-col": key, class: `col-${key}${col.numeric ? " num" : ""}` });
      if (value instanceof Node) td.appendChild(value); else if (Array.isArray(value)) td.append(...value); else td.textContent = value == null ? "" : String(value);
      return td;
    });
  }
  // The lines of the table for these rows (sorted as the view says): each line is the chosen columns, then the buttons the page makes for it (`actions(row)`), and
  // optionally a second line below it (`detail(row)` returns a <tr> or null) for what unfolds. `line(row, tr)` can give the line its class and its click.
  function lines(items, { actions = null, detail = null, line = null } = {}) {
    const out = [];
    for (const row of sorted(items)) {
      const tr = h("tr", {}, ...rowCells(row));
      if (actions) { const a = actions(row); tr.appendChild(h("td", { class: "actions" }, ...(Array.isArray(a) ? a : [a]))); }
      if (line) line(row, tr);
      out.push(tr);
      const more = detail ? detail(row, view.columns.length + (trailing ? 1 : 0)) : null;
      if (more) out.push(more);
    }
    return out;
  }
  const sorted = (rows) => sortRows(rows, view.sort, (row, key) => byKey.get(key).sort(row));
  const needs = () => [...new Set(view.columns.map((k) => byKey.get(k).extra).filter(Boolean))];
  const csv = (rows) => tableCsv(sorted(rows), view.columns, (r, k) => { const c = byKey.get(k); return c.text ? c.text(r) : ""; }, (k) => byKey.get(k).label || k);

  // ---------- changes ----------
  function changed(reason) {
    buildHead();
    keepDraft();
    refreshControls();
    onChange(reason, view);
  }

  function select(id) {
    const def = find(id);
    if (!def) return;
    activeId = id;
    view = norm(def);
    base = view;
    setFilters(view.filters);
    try { localStorage.removeItem(draftKey); } catch (err) { /* nothing to drop */ }
    persistActive();
    changed("view");
  }

  async function store(views, shared) {
    if (!canSave) { toast("Your views cannot be saved here", "error"); return false; }
    try {
      const saved = await put(`/api/me/table-views/${table}`, { views, active: activeId });
      server.views = saved.views;
      if (shared) server.shared = (await put(`/api/table-views/${table}/shared`, { views: shared })).shared;
      return true;
    } catch (err) {
      toast(err.message || "Could not save the view", "error");
      return false;
    }
  }
  const asDef = (name, id) => ({ id, name, columns: view.columns, widths: view.widths, sort: view.sort, filters: currentFilters() });

  async function saveChanges() {
    const w = asDef(nameOf(activeId));
    if (activeId.startsWith("shared:")) {
      const id = activeId.slice(7);
      if (!(await store(server.views, server.shared.map((v) => (v.id === id ? { ...w, id } : v))))) return;
    } else {
      const next = server.views.map((v) => (v.id === activeId ? { ...w, id: v.id } : v));
      if (!(await store(next))) return;
    }
    base = norm(w);
    try { localStorage.removeItem(draftKey); } catch (err) { /* nothing to drop */ }
    refreshControls();
    toast("View saved", "success");
  }

  async function saveAsNew() {
    const got = await formDialog({ title: "Save as a new view", text: "It keeps the columns, their order and width, the sort order and the filters you have now.", fields: [{ key: "name", label: "Name of the view", required: true }], ok: "Save view" });
    if (!got) return;
    const fresh = { ...asDef(got.name.trim(), undefined) };
    delete fresh.id;
    const next = [...server.views, fresh];
    if (!(await store(next))) return;
    const added = server.views[server.views.length - 1];
    activeId = added.id;
    view = norm(added);
    base = view;
    try { localStorage.removeItem(draftKey); } catch (err) { /* nothing to drop */ }
    persistActive();
    changed("view");
    toast(`View “${added.name}” saved`, "success");
  }

  async function rename() {
    const def = find(activeId);
    if (!def || activeId.startsWith("builtin:")) return;
    const got = await formDialog({ title: "Rename the view", fields: [{ key: "name", label: "Name of the view", value: def.name, required: true }], ok: "Rename" });
    if (!got) return;
    if (activeId.startsWith("shared:")) {
      const id = activeId.slice(7);
      await store(server.views, server.shared.map((v) => (v.id === id ? { ...v, name: got.name.trim() } : v)));
    } else {
      await store(server.views.map((v) => (v.id === activeId ? { ...v, name: got.name.trim() } : v)));
    }
    refreshControls();
  }

  async function remove() {
    const def = find(activeId);
    if (!def || activeId.startsWith("builtin:")) return;
    if (!window.confirm(`Delete the view “${def.name}”?${activeId.startsWith("shared:") ? " Everybody loses it." : ""}`)) return;
    const was = activeId;
    activeId = `builtin:${builtins[0].id}`;
    const ok = was.startsWith("shared:") ? await store(server.views, server.shared.filter((v) => `shared:${v.id}` !== was)) : await store(server.views.filter((v) => v.id !== was));
    if (!ok) { activeId = was; return; }
    select(activeId);
  }

  async function share(on) {
    const def = find(activeId);
    if (!def) return;
    if (on) {
      const copy = { ...asDef(def.name, undefined) };
      delete copy.id;
      if (!(await store(server.views, [...server.shared, copy]))) return;
      toast(`“${def.name}” is now shared with everybody`, "success");
    } else {
      const id = activeId.slice(7);
      if (!(await store(server.views, server.shared.filter((v) => v.id !== id)))) return;
      activeId = `builtin:${builtins[0].id}`;
      select(activeId);
      toast("No longer shared", "success");
    }
    refreshControls();
  }

  function revert() {
    select(activeId);
  }

  function download(rows) {
    const url = URL.createObjectURL(new Blob([csv(rows)], { type: "text/csv" }));
    const a = h("a", { href: url, download: `${table}.csv` });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ---------- the controls in the toolbar ----------
  const menuButton = h("summary", { class: "btn tv-menu-btn", title: "Choose, save and share views of this table" });
  const list = h("div", { class: "row-menu-list pop-menu-list tv-menu-list" });
  const menu = h("details", { class: "row-menu pop-menu tv-menu" }, menuButton, list);
  const columnsButton = h("button", { type: "button", class: "btn", title: "Choose, order and size the columns", onclick: () => openColumns() }, "Columns");
  const state = h("span", { class: "tv-state hint", role: "status" });
  const controls = h("div", { class: "tv-controls keep" }, menu, columnsButton, state);
  let rowsProvider = () => [];

  function refreshControls() {
    const isDirty = dirty();
    menuButton.replaceChildren(`View: ${nameOf(activeId)}${isDirty ? " (changed)" : ""} ▾`);
    state.replaceChildren();
    if (isDirty) {
      if (writable()) state.appendChild(h("button", { type: "button", class: "btn tv-link", onclick: saveChanges }, "Update view"));
      state.appendChild(h("button", { type: "button", class: "btn tv-link", onclick: revert }, "Undo"));
    }
  }

  function buildList() {
    const item = (text, act, { current = false, danger = false } = {}) => h("button", { type: "button", class: `tv-item${current ? " current" : ""}${danger ? " danger" : ""}`, "aria-current": current ? "true" : null, onclick: () => { menu.open = false; act(); } }, text);
    const heading = (text) => h("div", { class: "tv-heading" }, text);
    const parts = [heading("Built in"), ...builtins.map((b) => item(b.name, () => select(`builtin:${b.id}`), { current: activeId === `builtin:${b.id}` }))];
    if (server.shared.length) parts.push(heading("Shared with everybody"), ...server.shared.map((v) => item(v.name, () => select(`shared:${v.id}`), { current: activeId === `shared:${v.id}` })));
    if (server.views.length) parts.push(heading("My views"), ...server.views.map((v) => item(v.name, () => select(v.id), { current: activeId === v.id })));
    const mine = !activeId.startsWith("builtin:") && !activeId.startsWith("shared:");
    const actions = [];
    if (dirty() && writable()) actions.push(item(`Update “${nameOf(activeId)}”`, saveChanges));
    if (canSave) actions.push(item("Save as a new view…", saveAsNew));
    if (!activeId.startsWith("builtin:") && (mine || isAdmin())) actions.push(item("Rename this view…", rename));
    if (mine && isAdmin()) actions.push(item("Share this view with everybody", () => share(true)));
    if (activeId.startsWith("shared:") && isAdmin()) actions.push(item("Stop sharing this view", () => share(false)));
    if (dirty()) actions.push(item("Undo my changes", revert));
    actions.push(item("Download this table as CSV", () => download(rowsProvider())));
    if (!activeId.startsWith("builtin:") && (mine || isAdmin())) actions.push(item("Delete this view", remove, { danger: true }));
    parts.push(heading("This view"), ...actions);
    list.replaceChildren(...parts);
  }
  menu.addEventListener("toggle", () => { if (menu.open) buildList(); });

  // ---------- the column editor ----------
  function openColumns() {
    const dialog = h("dialog", { class: "stepup-dialog tv-dialog", "aria-label": "Columns" });
    const body = h("div", { class: "tv-columns" });
    const close = () => { dialog.close(); dialog.remove(); };
    dialog.addEventListener("cancel", () => dialog.remove());
    const apply = (cols) => { view = { ...view, columns: cols, widths: Object.fromEntries(Object.entries(view.widths).filter(([k]) => cols.includes(k))) }; changed("columns"); paint(); };

    function paint() {
      const shown = view.columns.map((k) => byKey.get(k));
      const hidden = catalog.filter((c) => !view.columns.includes(c.key));
      const rowFor = (c, index) => {
        const isLocked = locked.includes(c.key);
        const on = h("input", { type: "checkbox", checked: true, disabled: isLocked, "aria-label": `Show ${c.title || c.label || c.key}` });
        on.addEventListener("change", () => apply(toggleColumn(view.columns, c.key, false, locked)));
        const move = (delta, text) => h("button", { type: "button", class: "btn tv-move", "aria-label": `Move ${c.title || c.label || c.key} ${delta < 0 ? "up" : "down"}`, title: text, disabled: isLocked || (delta < 0 ? index <= locked.length : index >= shown.length - 1), onclick: () => apply(moveColumn(view.columns, c.key, delta, locked)) }, delta < 0 ? "▲" : "▼");
        return h("li", { class: "tv-col" }, h("label", {}, on, " ", c.title || c.label || c.key, c.group ? h("span", { class: "hint" }, ` · ${c.group}`) : null), isLocked ? h("span", { class: "hint" }, "always shown") : h("span", { class: "tv-moves" }, move(-1, "Earlier"), move(1, "Later")));
      };
      const known_groups = [...groups, ...hidden.map((c) => c.group || "Basics").filter((g) => !groups.includes(g))];
      const groupsShown = [...new Set(known_groups)].map((g) => [g, hidden.filter((c) => (c.group || "Basics") === g)]).filter(([, cs]) => cs.length);
      body.replaceChildren(
        h("h3", {}, `Shown (${shown.length})`), h("ul", { class: "tv-col-list" }, ...shown.map(rowFor)),
        hidden.length ? h("h3", {}, "Not shown") : null,
        ...groupsShown.flatMap(([g, cs]) => [h("div", { class: "tv-heading" }, g), h("ul", { class: "tv-col-list" }, ...cs.map((c) => {
          const on = h("input", { type: "checkbox", "aria-label": `Show ${c.title || c.label || c.key}` });
          on.addEventListener("change", () => apply(toggleColumn(view.columns, c.key, true, locked)));
          return h("li", { class: "tv-col" }, h("label", {}, on, " ", c.title || c.label || c.key));
        }))]));
    }
    paint();
    dialog.append(h("h2", {}, "Columns"), h("p", { class: "hint" }, "Tick the columns you want and move them with the arrows. You can also drag a heading in the table, and drag the edge of a heading to resize it."), body,
      h("div", { class: "btn-row" }, h("button", { type: "button", class: "btn", onclick: close }, "Close"), h("button", { type: "button", class: "btn", onclick: () => { revert(); paint(); } }, "Undo my changes")));
    document.body.appendChild(dialog);
    dialog.showModal();
  }

  buildHead();
  refreshControls();
  setFilters(view.filters);
  return {
    table: table_, tbody, controls, rowCells, lines, sorted, needs, csv, width: () => view.columns.length + (trailing ? 1 : 0),
    get view() { return view; },
    columns: () => view.columns.slice(),
    refresh: refreshControls,                                                // a filter changed: the "changed" mark may have to appear
    filtersChanged() { keepDraft(); refreshControls(); },
    useRows(provider) { rowsProvider = provider; },
    sortedBy: () => view.sort,
    setSort(key, dir) { view = { ...view, sort: { key, dir } }; changed("sort"); },
  };
}
