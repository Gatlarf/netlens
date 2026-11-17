// Mass edit of the Devices page: a separate editable list, shown only after "Edit many". One row per listed device (the filters of the page
// decide which), one control per setting. Changes are only staged here (`staged`, by device id, only the fields that differ from what the
// server has); nothing is saved until Save. The staged changes survive a change of filter and the refresh of the list underneath.
import { post } from "../api.js";
import { formDialog } from "../formdialog.js";
import { h, clear, toast, statusDot, TYPE_LABELS, shortName } from "../util.js";

// the settings that are a tick box: [field of the API, column title, hint]
const FLAGS = [
  ["trusted", "Known device", "A device you know. Unknown devices are flagged as new."],
  ["always_on", "Always on", "Should always be online: it counts for the core availability."],
  ["notify_offline", "Alert when offline", "Send a notification when it goes offline."],
  ["report_exclude", "Leave out of reports", "Not listed in the weekly and monthly reports."],
  ["gentle", "Gentle scanning", "Scans only check its ports and never probe its services."]
];

export function createBulkEditor({ getDevices, getGroups, onSaved, onLeave }) {
  const staged = new Map();           // device id -> { field: new value }
  const marked = new Set();           // devices ticked for deletion (nothing is deleted before Save and a confirmation)
  const root = h("div", { class: "bulk-edit" });
  let rowsByDevice = new Map();       // device id -> { device, controls } of the rows on screen
  let bar;
  let saveBtn;
  let status;

  const original = (d, field) => {
    if (field === "custom_name") return d.custom_name || "";
    if (field === "type_override") return d.type;
    if (field === "group_id") return d.group_id ?? null;
    return !!d[field];
  };

  function stage(d, field, value) {
    const change = staged.get(d.id) || {};
    if (value === original(d, field)) delete change[field];
    else change[field] = value;
    if (Object.keys(change).length) staged.set(d.id, change);
    else staged.delete(d.id);
    paintRow(d.id);
    paintBar();
  }

  const valueOf = (d, field) => (staged.get(d.id) && field in staged.get(d.id) ? staged.get(d.id)[field] : original(d, field));

  function paintRow(id) {
    const entry = rowsByDevice.get(id);
    if (entry) { entry.tr.classList.toggle("bulk-changed", staged.has(id)); entry.tr.classList.toggle("bulk-delete", marked.has(id)); }
    paintHeads();
  }

  function paintBar() {
    const n = staged.size, m = marked.size;
    status.textContent = n || m ? [n ? `${n} device${n === 1 ? "" : "s"} changed` : "", m ? `${m} marked for deletion` : ""].filter(Boolean).join(", ") + ", not saved yet" : "No changes yet";
    saveBtn.disabled = !n && !m;
    saveBtn.classList.toggle("danger", m > 0);
  }

  // the tick box in a column title shows whether all listed rows are on, none, or a mix
  const heads = [];
  let deleteHead = null;
  function paintHeads() {
    const devices = getDevices();
    for (const { field, box } of heads) {
      const on = devices.filter((d) => valueOf(d, field)).length;
      box.checked = devices.length > 0 && on === devices.length;
      box.indeterminate = on > 0 && on < devices.length;
    }
    if (deleteHead) {
      const on = devices.filter((d) => marked.has(d.id)).length;
      deleteHead.checked = devices.length > 0 && on === devices.length;
      deleteHead.indeterminate = on > 0 && on < devices.length;
    }
  }

  function setAll(field, value) {
    for (const d of getDevices()) {
      stage(d, field, value);
      const entry = rowsByDevice.get(d.id);
      if (entry && entry.controls[field]) entry.controls[field].checked = value;
    }
  }

  // Deleting asks first, and asks before anything is saved, so cancelling leaves everything as it was.
  async function confirmDelete() {
    const devices = getDevices().filter((d) => marked.has(d.id));
    const names = devices.slice(0, 8).map((d) => d.name || d.primary_ip).join(", ") + (devices.length > 8 ? ` and ${devices.length - 8} more` : "");
    const online = devices.filter((d) => d.online).length;
    return formDialog({
      title: `Delete ${devices.length} device${devices.length === 1 ? "" : "s"}?`,
      text: `${names}. This removes them with their ports, names, uptime history and links, and it cannot be undone.`,
      fields: [{ key: "ignore", label: "Also ignore them in future scans", type: "checkbox", value: online > 0,
        hint: online ? `${online} of them ${online === 1 ? "is" : "are"} online right now, so without this the next scan adds ${online === 1 ? "it" : "them"} again.` : "They are all offline. Tick this if they should never be added back, even when they appear again." }],
      ok: `Delete ${devices.length}`,
    });
  }

  async function save() {
    let ignore = false;
    if (marked.size) {
      const answer = await confirmDelete();
      if (!answer) return;
      ignore = !!answer.ignore;
    }
    const changes = [...staged].filter(([id]) => !marked.has(id)).map(([id, fields]) => ({ id, ...fields }));
    saveBtn.disabled = true;
    try {
      if (changes.length) {
        const res = await post("/api/devices/bulk", { changes });
        const failed = new Set(res.errors.map((e) => e.id));
        for (const id of [...staged.keys()]) if (!failed.has(id) && !marked.has(id)) staged.delete(id);
        if (res.errors.length) toast(`${res.changed} saved, ${res.errors.length} could not be saved: ${res.errors[0].detail}`, "error");
        else if (!marked.size) toast(`${res.changed} device${res.changed === 1 ? "" : "s"} saved`, "success");
      }
      if (marked.size) {
        const res = await post("/api/devices/bulk-delete", { ids: [...marked], ignore });
        const failed = new Set(res.errors.map((e) => e.id));
        for (const id of [...marked]) if (!failed.has(id)) { marked.delete(id); staged.delete(id); }
        if (res.errors.length) toast(`${res.deleted} deleted, ${res.errors.length} could not be deleted: ${res.errors[0].detail}`, "error");
        else toast(`${res.deleted} device${res.deleted === 1 ? "" : "s"} deleted`, "success");
      }
      await onSaved(!staged.size && !marked.size);       // the page reloads the list; with everything saved it also leaves the editor
    } catch (err) {
      toast(err.message || "Could not save the changes", "error");
    }
    paintBar();
  }

  function cancel() {
    const pending = staged.size + marked.size;
    if (pending && !window.confirm(`Throw away the changes to ${pending} device(s)?`)) return;
    staged.clear();
    marked.clear();
    onLeave();
  }

  function build() {
    clear(root);
    heads.length = 0;
    rowsByDevice = new Map();
    const devices = getDevices().slice().sort((a, b) => String(a.primary_ip || "").localeCompare(String(b.primary_ip || ""), undefined, { numeric: true }))      // the order of the list;
    const groups = getGroups();

    saveBtn = h("button", { type: "button", class: "btn primary" }, "Save changes");
    saveBtn.addEventListener("click", save);
    const cancelBtn = h("button", { type: "button", class: "btn" }, "Back to the list");
    cancelBtn.addEventListener("click", cancel);
    status = h("span", { class: "bulk-status keep", role: "status" });
    bar = h("div", { class: "toolbar bulk-bar keep" }, saveBtn, cancelBtn, status,
      h("span", { class: "hint" }, `${devices.length} device${devices.length === 1 ? "" : "s"} listed; the filters above choose which. The tick box in a column title sets all of them.`));
    root.appendChild(bar);

    const table = h("table", { class: "data bulk-table" });
    const headRow = h("tr", {}, h("th", {}, "Status"), h("th", {}, "Name"));
    for (const [field, title, hint] of FLAGS) {
      const box = h("input", { type: "checkbox", "aria-label": `${title}: set for all listed devices` });
      box.addEventListener("change", () => setAll(field, box.checked));
      heads.push({ field, box });
      headRow.appendChild(h("th", { class: "bulk-flag", title: hint }, h("label", {}, box, " ", title)));
    }
    deleteHead = h("input", { type: "checkbox", "aria-label": "Delete: mark all listed devices" });
    deleteHead.addEventListener("change", () => {
      for (const d of getDevices()) {
        if (deleteHead.checked) marked.add(d.id); else marked.delete(d.id);
        const entry = rowsByDevice.get(d.id);
        if (entry) { entry.controls.delete.checked = deleteHead.checked; paintRow(d.id); }
      }
      paintBar();
    });
    const typeAll = h("select", { "aria-label": "Type for all listed devices" }, h("option", { value: "" }, "Type: set all…"));
    for (const key of Object.keys(TYPE_LABELS)) typeAll.appendChild(h("option", { value: key }, TYPE_LABELS[key]));
    typeAll.addEventListener("change", () => {
      const value = typeAll.value;
      typeAll.value = "";
      if (!value) return;
      for (const d of getDevices()) {
        stage(d, "type_override", value);
        const entry = rowsByDevice.get(d.id);
        if (entry) entry.controls.type_override.value = value;
      }
    });
    const groupAll = h("select", { "aria-label": "Group for all listed devices" }, h("option", { value: "" }, "Group: set all…"), h("option", { value: "none" }, "(no group)"));
    for (const g of groups) groupAll.appendChild(h("option", { value: String(g.id) }, g.name));
    groupAll.addEventListener("change", () => {
      const value = groupAll.value;
      groupAll.value = "";
      if (!value) return;
      const id = value === "none" ? null : Number(value);
      for (const d of getDevices()) {
        stage(d, "group_id", id);
        const entry = rowsByDevice.get(d.id);
        if (entry) entry.controls.group_id.value = id === null ? "" : String(id);
      }
    });
    headRow.append(h("th", {}, typeAll), h("th", {}, groupAll), h("th", { class: "bulk-flag bulk-delete-head", title: "Mark devices to delete. Nothing is deleted until you press Save and confirm." }, h("label", {}, deleteHead, " Delete")));
    table.appendChild(h("thead", {}, headRow));

    const body = h("tbody");
    for (const d of devices) {
      const controls = {};
      const tr = h("tr");
      tr.appendChild(h("td", {}, statusDot(d.online)));

      const name = h("input", { type: "text", maxlength: "100", value: valueOf(d, "custom_name"), placeholder: shortName(d.hostname || d.primary_ip || "") || "name", "aria-label": `Name of ${d.name}`, title: "Leave empty for the automatic name" });
      name.addEventListener("input", () => stage(d, "custom_name", name.value.trim()));
      controls.custom_name = name;
      tr.appendChild(h("td", { class: "bulk-name" }, name, h("div", { class: "hint mono" }, d.primary_ip || d.mac || "")));

      for (const [field, title] of FLAGS) {
        const box = h("input", { type: "checkbox", checked: valueOf(d, field), "aria-label": `${title}: ${d.name}` });
        box.addEventListener("change", () => stage(d, field, box.checked));
        controls[field] = box;
        tr.appendChild(h("td", { class: "bulk-flag" }, box));
      }

      const type = h("select", { "aria-label": `Type of ${d.name}` });
      const current = valueOf(d, "type_override");
      for (const key of Object.keys(TYPE_LABELS)) type.appendChild(h("option", { value: key }, TYPE_LABELS[key]));
      if (!(current in TYPE_LABELS)) type.appendChild(h("option", { value: current }, current));
      type.value = current;
      type.addEventListener("change", () => stage(d, "type_override", type.value));
      controls.type_override = type;
      tr.appendChild(h("td", {}, type));

      const group = h("select", { "aria-label": `Group of ${d.name}` }, h("option", { value: "" }, "—"));
      for (const g of groups) group.appendChild(h("option", { value: String(g.id) }, g.name));
      const wanted = valueOf(d, "group_id");
      group.value = wanted === null ? "" : String(wanted);
      group.addEventListener("change", () => stage(d, "group_id", group.value === "" ? null : Number(group.value)));
      controls.group_id = group;
      tr.appendChild(h("td", {}, group));

      const del = h("input", { type: "checkbox", checked: marked.has(d.id), "aria-label": `Delete ${d.name}` });
      del.addEventListener("change", () => { if (del.checked) marked.add(d.id); else marked.delete(d.id); paintRow(d.id); paintBar(); });
      controls.delete = del;
      tr.appendChild(h("td", { class: "bulk-flag bulk-delete-cell" }, del));

      tr.classList.toggle("bulk-changed", staged.has(d.id));
      tr.classList.toggle("bulk-delete", marked.has(d.id));
      rowsByDevice.set(d.id, { tr, controls });
      body.appendChild(tr);
    }
    if (!devices.length) body.appendChild(h("tr", {}, h("td", { class: "empty", colspan: String(5 + FLAGS.length) }, "No devices match the filters.")));
    table.appendChild(body);
    root.appendChild(h("div", { class: "table-wrap" }, table));
    paintHeads();
    paintBar();
  }

  // leaving the editor: take every field out of the page, or the "unsaved changes" question of the page still sees the ticks that were just saved
  function reset() {
    staged.clear();
    marked.clear();
    clear(root);
    heads.length = 0;
    rowsByDevice = new Map();
  }

  return { el: root, refresh: build, reset, pending: () => staged.size + marked.size };
}
