// The window for making and changing a card of your own.
import { h, clear } from "./util.js";
import { FORMATS, TYPES, customCard, flatten, formatValue, guessFormat } from "./dashboard_cards.js";

const PAGES = [["", "Nowhere"], ["#/dashboard", "Dashboard"], ["#/map", "Map"], ["#/devices", "Devices"], ["#/hierarchy", "Hierarchy"], ["#/speedtest", "Speed tests"], ["#/uptime", "Uptime"],
  ["#/services", "Services"], ["#/stats", "Statistics"], ["#/scans", "Scans & events"], ["#/settings", "Settings"]];
const newId = () => `c-${Math.random().toString(36).slice(2, 8).replace(/[^a-z0-9]/g, "x")}`;
const num = (input) => (input.value.trim() === "" ? null : Number(input.value));
const field = (label, input, hint) => h("div", { class: "field" }, h("label", {}, label), input, hint ? h("p", { class: "hint" }, hint) : null);
const select = (options, value) => { const s = h("select", {}, options.map(([v, t]) => h("option", { value: v }, t))); s.value = value; return s; };

// def: an existing card to change, or null to make one. data: the dashboard data (what the pickers offer). onSave(def): the page stores it.
export function openEditor({ def, data, onSave }) {
  const dialog = h("dialog", { class: "d-editor", "aria-labelledby": "d-editor-title" });
  const close = () => { dialog.close(); dialog.remove(); };
  dialog.addEventListener("cancel", () => dialog.remove());
  document.body.appendChild(dialog);
  dialog.showModal();
  if (def) form(def.type, def); else chooser();

  function chooser() {
    clear(dialog);
    dialog.append(h("h2", { id: "d-editor-title" }, "What should the card show?"),
      h("div", { class: "d-types" }, TYPES.map(([type, name, about]) => h("button", { class: "d-type", type: "button", onclick: () => form(type, null) }, h("strong", {}, name), h("span", { class: "hint" }, about)))),
      h("div", { class: "cl-actions" }, h("button", { class: "btn", type: "button", onclick: close }, "Cancel")));
  }

  function form(type, existing) {
    clear(dialog);
    const kind = TYPES.find((t) => t[0] === type);
    const title = h("input", { type: "text", maxlength: "60", value: existing?.title || "", placeholder: "Name of the card" });
    const body = h("div", {});
    const preview = h("div", { class: "d-preview" });
    const error = h("p", { class: "error", role: "alert" });
    let read = () => ({});

    if (type === "value") read = valueForm(body, existing, update);
    else if (type === "device") read = pickForm(body, "Device", [...data.summary.device_list].sort((a, b) => a.name.localeCompare(b.name)).map((d) => [d.id, `${d.name}${d.ip ? ` (${d.ip})` : ""}`]), existing?.device_id, "device_id", update);
    else if (type === "group") {
      const groups = [...new Set(data.summary.device_list.map((d) => d.group || "(no group)"))].sort();
      read = pickForm(body, "Group", groups.map((g) => [g, g]), existing?.group, "group", update);
    } else if (type === "service") read = pickForm(body, "Service check", (data.service_checks || []).map((c) => [c.id, c.name]), existing?.check_id, "check_id", update);
    else read = notesForm(body, existing, update);

    function current() {
      const out = { id: existing?.id || newId(), type, title: title.value.trim(), ...read() };
      return out;
    }
    function update() {
      clear(preview);
      try {
        const d = current();
        const card = customCard(d, data);
        preview.append(h("section", { class: "dcard size-s" }, h("div", { class: "d-head" }, h("h2", { class: "d-title" }, card.title)), card.build(data)));
      } catch (e) {
        preview.append(h("p", { class: "hint" }, "Fill in the details to see a preview."));
      }
    }
    title.addEventListener("input", update);
    const save = h("button", { class: "btn primary", type: "button", onclick: async () => {
      error.textContent = "";
      const d = current();
      try { await onSave(d); close(); } catch (e) { error.textContent = e.message || "Could not save the card"; }
    } }, existing ? "Save" : "Add card");
    dialog.append(h("h2", { id: "d-editor-title" }, `${existing ? "Change" : "New"} card: ${kind[1]}`), h("p", { class: "hint" }, kind[2]),
      field("Title", title), body, h("h3", {}, "Preview"), preview, error,
      h("div", { class: "cl-actions" }, existing ? null : h("button", { class: "btn", type: "button", onclick: chooser }, "Back"), h("button", { class: "btn", type: "button", onclick: close }, "Cancel"), save));
    update();
  }

  // a value from the data, with colours
  function valueForm(body, existing, update) {
    let source = existing?.source || "";
    const all = flatten(data);
    const search = h("input", { type: "search", placeholder: "Search the data, for example uptime, speed, containers", "aria-label": "Search the data" });
    const list = h("ul", { class: "d-pick", role: "listbox" });
    const picked = h("p", { class: "hint" });
    const fmt = select(FORMATS, existing?.format || "number");
    const display = select([["number", "Big number"], ["gauge", "Gauge bar"], ["status", "Status light"]], existing?.display || "number");
    const unit = h("input", { type: "text", maxlength: "12", value: existing?.unit || "", placeholder: "for example °C" });
    const decimals = select([["0", "No decimals"], ["1", "1 decimal"], ["2", "2 decimals"], ["3", "3 decimals"]], String(existing?.decimals ?? 0));
    const direction = select([["below", "below the limits"], ["above", "above the limits"]], existing?.direction || "below");
    const warn = h("input", { type: "number", step: "any", value: existing?.warn ?? "", placeholder: "none" });
    const bad = h("input", { type: "number", step: "any", value: existing?.bad ?? "", placeholder: "none" });
    const min = h("input", { type: "number", step: "any", value: existing?.min ?? "", placeholder: "0" });
    const max = h("input", { type: "number", step: "any", value: existing?.max ?? "", placeholder: "100" });
    const link = select(PAGES, existing?.href || "");
    const gaugeRow = h("div", { class: "d-two" }, field("Gauge from", min), field("to", max));

    const fill = () => {
      clear(list);
      const q = search.value.trim().toLowerCase();
      const shown = all.filter((x) => !q || `${x.label} ${x.path}`.toLowerCase().includes(q)).slice(0, 60);
      if (!shown.length) list.append(h("li", { class: "hint" }, "Nothing matches."));
      for (const x of shown) {
        list.append(h("li", { role: "option", "aria-selected": String(x.path === source) }, h("button", { type: "button", class: x.path === source ? "active" : "", onclick: () => {
          source = x.path;
          if (!existing) fmt.value = guessFormat(x.path);
          picked.textContent = `Showing: ${x.label}`;
          fill(); sync();
        } }, h("span", {}, x.label), h("span", { class: "d-note" }, formatValue(x.value, guessFormat(x.path), 1)))));
      }
    };
    const sync = () => { gaugeRow.hidden = display.value !== "gauge"; update(); };
    search.addEventListener("input", fill);
    for (const input of [fmt, display, unit, decimals, direction, warn, bad, min, max, link]) { input.addEventListener("input", sync); input.addEventListener("change", sync); }
    picked.textContent = source ? `Showing: ${all.find((x) => x.path === source)?.label || source}` : "Pick the value below.";
    body.append(field("What to show", search), picked, list,
      h("div", { class: "d-two" }, field("Format", fmt), field("Show it as", display)), h("div", { class: "d-two" }, field("Unit", unit), field("Decimals", decimals)),
      h("h3", {}, "Colours"), h("p", { class: "hint" }, "Leave the limits empty for no colour. A value is a problem when it is…"),
      field("", direction), h("div", { class: "d-two" }, field("Warning limit (amber)", warn), field("Problem limit (red)", bad)), gaugeRow, field("Clicking the card opens", link));
    fill(); sync();
    return () => ({ source, format: fmt.value, display: display.value, unit: unit.value.trim(), decimals: Number(decimals.value), direction: direction.value, warn: num(warn), bad: num(bad), min: num(min), max: num(max), href: link.value });
  }

  function pickForm(body, label, options, value, key, update) {
    const s = h("select", { "aria-label": label }, h("option", { value: "" }, `Choose…`), options.map(([v, t]) => h("option", { value: String(v) }, t)));
    if (value !== undefined && value !== null) s.value = String(value);
    s.addEventListener("change", update);
    body.append(field(label, s), options.length ? null : h("p", { class: "hint" }, "There is nothing to choose from yet."));
    return () => ({ [key]: s.value === "" ? null : key === "group" ? s.value : Number(s.value) });
  }

  function notesForm(body, existing, update) {
    const text = h("textarea", { rows: "5", maxlength: "2000", placeholder: "Notes, one paragraph per line" });
    text.value = existing?.text || "";
    const links = h("div", { class: "d-links-edit" });
    const lines = [];
    const addLine = (l = { label: "", url: "" }) => {
      const label = h("input", { type: "text", maxlength: "40", placeholder: "Name", value: l.label, "aria-label": "Link name" });
      const url = h("input", { type: "text", maxlength: "300", placeholder: "https://… or #/devices", value: l.url, "aria-label": "Link address" });
      const row = h("div", { class: "d-link-row" }, label, url, h("button", { class: "btn", type: "button", "aria-label": "Remove link", onclick: () => { lines.splice(lines.indexOf(entry), 1); row.remove(); update(); } }, "✕"));
      const entry = { label, url };
      lines.push(entry);
      label.addEventListener("input", update); url.addEventListener("input", update);
      links.append(row);
    };
    (existing?.links || []).forEach(addLine);
    const add = h("button", { class: "btn", type: "button", onclick: () => { if (lines.length < 8) addLine(); } }, "Add a link");
    text.addEventListener("input", update);
    body.append(field("Text", text), h("h3", {}, "Links"), links, add);
    return () => ({ text: text.value.trim(), links: lines.map((l) => ({ label: l.label.value.trim(), url: l.url.value.trim() })).filter((l) => l.label || l.url) });
  }
}
