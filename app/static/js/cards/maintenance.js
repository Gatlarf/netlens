import { get, post, put, del } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone;

// <input type="datetime-local"> works in the browser's own time; the server keeps UTC
const toUtc = (local) => (local ? new Date(local).toISOString().replace(/\.\d+Z$/, "Z") : "");
function toLocalInput(iso) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function scopeText(w, groups, devices) {
  const s = w.scope;
  if (s.all) return "everything";
  const parts = [];
  const g = s.groups.map((id) => (groups.find((x) => x.id === id) || {}).name).filter(Boolean);
  if (g.length) parts.push(`group${g.length > 1 ? "s" : ""} ${g.join(", ")}`);
  const d = s.devices.map((id) => (devices.find((x) => x.id === id) || {}).name).filter(Boolean);
  if (d.length) parts.push(d.length > 3 ? `${d.slice(0, 3).join(", ")} and ${d.length - 3} more` : d.join(", "));
  return parts.join(" + ") + (s.behind ? ", and the devices behind them" : "");
}

function windowForm(existing, groups, devices, onDone, onCancel) {
  const w = existing || { name: "", enabled: true, scope: { all: false, groups: [], devices: [], behind: true }, schedule: { type: "weekly", days: [0, 2, 5, 6], start: "03:00", end: "04:00" } };
  const form = h("form", { class: "edit-form maintenance-form" });
  const name = h("input", { type: "text", name: "name", required: true, maxlength: "80", value: w.name, placeholder: "AiMesh nightly reboot" });

  // what it covers
  const mode = w.scope.all ? "all" : w.scope.groups.length && !w.scope.devices.length ? "groups" : "devices";
  const modeSel = h("select", { name: "mode" },
    h("option", { value: "devices" }, "Chosen devices"), h("option", { value: "groups" }, "Groups"), h("option", { value: "all" }, "Everything"));
  modeSel.value = mode;
  const deviceSel = h("select", { name: "devices", multiple: true, size: "8", "aria-label": "Devices" });
  for (const d of devices) deviceSel.appendChild(h("option", { value: String(d.id), selected: w.scope.devices.includes(d.id) }, `${d.name}${d.primary_ip && d.primary_ip !== d.name ? ` (${d.primary_ip})` : ""}`));
  const groupBox = h("div", { class: "event-boxes" });
  for (const g of groups) groupBox.appendChild(h("label", { class: "check-row" }, h("input", { type: "checkbox", "data-group": String(g.id), checked: w.scope.groups.includes(g.id) }), " ", g.name));
  if (!groups.length) groupBox.appendChild(h("span", { class: "hint" }, "No groups yet (Settings → Groups)."));
  const behind = h("input", { type: "checkbox", name: "behind", checked: w.scope.behind });
  const scopeBox = h("div", {});
  const syncScope = () => {
    clear(scopeBox);
    if (modeSel.value === "devices") scopeBox.append(deviceSel, h("p", { class: "hint" }, "Hold Ctrl (or Cmd) to choose several."));
    if (modeSel.value === "groups") scopeBox.appendChild(groupBox);
    behindRow.hidden = modeSel.value === "all";
  };
  const behindRow = h("label", { class: "check-row" }, behind, " Also the devices behind them (a mesh node that reboots takes its clients with it)");

  // when it happens
  const typeSel = h("select", { name: "type" }, h("option", { value: "weekly" }, "Every week"), h("option", { value: "once" }, "Once"));
  typeSel.value = w.schedule.type;
  const dayBoxes = DAYS.map((label, i) => h("label", { class: "check-row" }, h("input", { type: "checkbox", "data-day": String(i), checked: (w.schedule.days || []).includes(i) }), " ", label));
  const start = h("input", { type: "time", name: "start", value: w.schedule.start || "03:00" });
  const end = h("input", { type: "time", name: "end", value: w.schedule.end || "04:00" });
  const onceStart = h("input", { type: "datetime-local", name: "once-start", value: w.schedule.type === "once" ? toLocalInput(w.schedule.start) : "" });
  const onceEnd = h("input", { type: "datetime-local", name: "once-end", value: w.schedule.type === "once" ? toLocalInput(w.schedule.end) : "" });
  const weekly = h("div", { class: "edit-form" },
    h("div", { class: "field" }, h("label", {}, "Days"), h("div", { class: "days" }, dayBoxes)),
    h("div", { class: "field" }, h("label", {}, "From"), start),
    h("div", { class: "field" }, h("label", {}, "Until (an earlier time than From means it runs past midnight)"), end));
  const once = h("div", { class: "edit-form" }, h("div", { class: "field" }, h("label", {}, "From"), onceStart), h("div", { class: "field" }, h("label", {}, "Until"), onceEnd));
  const syncType = () => { weekly.hidden = typeSel.value !== "weekly"; once.hidden = typeSel.value !== "once"; };
  modeSel.addEventListener("change", syncScope);
  typeSel.addEventListener("change", syncType);
  syncScope();
  syncType();

  form.append(
    h("div", { class: "field" }, h("label", {}, "Name"), name),
    h("div", { class: "field" }, h("label", {}, "Covers"), modeSel, scopeBox, behindRow),
    h("div", { class: "field" }, h("label", {}, "When"), typeSel),
    weekly, once,
    h("p", { class: "hint" }, `Times are in your time zone (${ZONE}).`),
  );
  const save = h("button", { type: "submit", class: "btn" }, existing ? "Save window" : "Add window");
  const cancel = h("button", { type: "button", class: "btn" }, "Cancel");
  cancel.addEventListener("click", onCancel);
  form.appendChild(h("div", { class: "row-actions" }, save, " ", cancel));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const mode2 = modeSel.value;
    const body = {
      name: name.value, enabled: w.enabled, tz: ZONE, offset_min: -new Date().getTimezoneOffset(),
      scope: {
        all: mode2 === "all",
        groups: mode2 === "groups" ? [...groupBox.querySelectorAll("input[data-group]:checked")].map((i) => Number(i.dataset.group)) : [],
        devices: mode2 === "devices" ? [...deviceSel.selectedOptions].map((o) => Number(o.value)) : [],
        behind: behind.checked && mode2 !== "all",
      },
      schedule: typeSel.value === "weekly"
        ? { type: "weekly", days: dayBoxes.map((l) => l.querySelector("input")).filter((i) => i.checked).map((i) => Number(i.dataset.day)), start: start.value, end: end.value }
        : { type: "once", start: toUtc(onceStart.value), end: toUtc(onceEnd.value) },
    };
    if (body.schedule.type === "once" && (!onceStart.value || !onceEnd.value)) {
      toast("Fill in when the window starts and ends", "error");
      return;
    }
    try {
      const overview = existing ? await put(`/api/maintenance/${existing.id}`, body) : await post("/api/maintenance", body);
      toast(existing ? "Window saved" : "Window added", "success");
      onDone(overview);
    } catch (err) {
      toast(err.message || "Could not save the window", "error");
    }
  });
  return form;
}

export async function buildMaintenanceCard() {
  const card = h("div", { class: "card" });
  const [overview, groupData, deviceList] = await Promise.all([get("/api/maintenance"), get("/api/groups"), get("/api/devices")]);
  const groups = groupData.groups || [];
  const devices = [...deviceList].sort((a, b) => (a.name || "").localeCompare(b.name || ""));

  function draw(data, editing) {
    clear(card);
    card.appendChild(h("h2", {}, "Maintenance windows"));
    card.appendChild(h("p", { class: "hint" },
      "Times when devices are expected to be unreachable, such as a mesh node that reboots at 3 a.m. Netlens keeps scanning and recording, " +
      "but the \"offline\", \"online\" and \"service down/up\" events of a covered device are marked as maintenance and are not sent to e-mail " +
      "or notification channels. If a device is still offline when its window ends, you get the normal offline message then."));

    if (data.windows.length) {
      const table = h("table", { class: "data" });
      table.appendChild(h("thead", {}, h("tr", {}, ["Window", "When", "Covers", "Status", ""].map((t) => h("th", {}, t)))));
      const body = h("tbody");
      for (const w of data.windows) {
        let status;
        if (!w.enabled) status = h("span", { class: "hint" }, "off");
        else if (w.active) status = h("span", { class: "badge" }, `active until ${fmtTime(w.ends)}`);
        else status = h("span", { class: "hint" }, w.next ? `next ${fmtTime(w.next)}` : "finished");
        const edit = h("button", { type: "button", class: "btn" }, "Edit");
        const toggle = h("button", { type: "button", class: "btn" }, w.enabled ? "Turn off" : "Turn on");
        const remove = h("button", { type: "button", class: "btn danger" }, w.active ? "End" : "Delete");
        const call = async (request, done) => {
          try {
            draw(await request());
            toast(done, "success");
          } catch (err) {
            toast(err.message || "Failed", "error");
          }
        };
        const bodyOf = () => ({ name: w.name, enabled: !w.enabled, scope: w.scope, schedule: w.schedule, tz: w.tz, offset_min: w.offset_min });
        edit.addEventListener("click", () => draw(data, w));
        toggle.addEventListener("click", () => call(() => put(`/api/maintenance/${w.id}`, bodyOf()), w.enabled ? "Turned off" : "Turned on"));
        remove.addEventListener("click", () => {
          if (window.confirm(w.active ? `End the window "${w.name}" now? A recurring window is removed completely.` : `Delete the window "${w.name}"?`)) call(() => del(`/api/maintenance/${w.id}`), "Window removed");
        });
        body.appendChild(h("tr", {}, h("td", {}, w.name), h("td", {}, w.summary), h("td", {}, scopeText(w, groups, devices), h("div", { class: "hint" }, `${w.devices_covered} device(s)`)), h("td", {}, status), h("td", {}, edit, " ", toggle, " ", remove)));
      }
      table.appendChild(body);
      card.appendChild(h("div", { class: "table-wrap" }, table));
    } else if (!editing) {
      card.appendChild(h("p", { class: "hint" }, "No maintenance windows yet."));
    }

    if (editing === true || (editing && editing.id)) {
      card.appendChild(h("h3", {}, editing === true ? "New window" : `Edit "${editing.name}"`));
      card.appendChild(windowForm(editing === true ? null : editing, groups, devices, (o) => draw(o), () => draw(data)));
    } else {
      const add = h("button", { type: "button", class: "btn" }, "+ Add maintenance window");
      add.addEventListener("click", () => draw(data, true));
      card.appendChild(add);
    }
  }
  draw(overview);
  return card;
}
