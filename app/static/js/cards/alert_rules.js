import { get, post, put, del } from "../api.js";
import { h, clear, toast, TYPE_LABELS, fmtTime } from "../util.js";
import { eventLabel } from "../event_labels.js";
import { loadDevices, deviceLabel } from "../devicelist.js";
import { describeRule } from "../alert_rules_text.js";

// Settings -> Notifications -> Alert rules: which events are recorded but not sent. A muted event still shows up in Scans & events, marked as muted.
const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const TYPE_TEXT = {
  mute: ["Ignore these events", "For the devices you choose, optionally only at certain times (for example a camera that is switched off every night)."],
  while_down: ["Ignore them while a device is offline", "For things that depend on another device the map does not know about (cameras and their recorder, a NAS and its backup job)."],
  repeat: ["Ignore repeats", "When the same event keeps coming back (a device that flaps), pass the first few, ignore the rest and tell me once."],
};
const STARTERS = [
  { title: "Quiet nights", text: "Ignore a device that is switched off every night.", rule: { name: "Quiet nights", type: "mute", kinds: ["device_offline"], recoveries: true, scope: { type: "all" }, when: { days: [0, 1, 2, 3, 4, 5, 6], from: "22:00", to: "07:00" } } },
  { title: "Behind a device that is down", text: "Ignore what hangs on a device while that device is offline.", rule: { name: "While it is down", type: "while_down", kinds: ["device_offline", "service_down"], recoveries: true, scope: { type: "all" }, keep_critical: false } },
  { title: "Stop flapping alerts", text: "After three offline messages for a device in ten minutes, ignore the rest.", rule: { name: "Flapping devices", type: "repeat", kinds: ["device_offline", "device_online"], recoveries: false, scope: { type: "all" }, count: 3, minutes: 10, per: "device" } },
];

export async function buildAlertRulesCard() {
  const card = h("div", { class: "card admin-only alert-rules" });
  let data = await get("/api/alert-rules");
  const devices = await loadDevices();
  let editing = null;                                   // null (the list), or the rule being made or changed

  const kindName = (kind) => (data.kinds.find((k) => k.kind === kind) ? eventLabel(kind) : kind).toLowerCase();
  const describe = (rule) => describeRule(rule, {
    kindName,
    groupName: (id) => (data.groups.find((g) => g.id === id) || {}).name || `group ${id}`,
    deviceName: (id) => (devices.find((d) => d.id === id) || {}).name || `device ${id}`,
  });

  async function refresh() { data = await get("/api/alert-rules"); }

  // ---------- the list ----------
  function list() {
    const box = h("div", {});
    if (!data.rules.length) {
      box.appendChild(h("p", { class: "hint" }, "No rules yet. Every event that is not held back by a maintenance window or a snooze is sent."));
      box.appendChild(h("h3", {}, "Start from an example"));
      box.appendChild(h("div", { class: "ar-starters" }, ...STARTERS.map((s) => h("button", { type: "button", class: "ar-starter", onclick: () => { editing = JSON.parse(JSON.stringify(s.rule)); draw(); } }, h("strong", {}, s.title), h("span", { class: "hint" }, s.text)))));
      return box;
    }
    const rows = data.rules.map((r) => {
      const on = h("input", { type: "checkbox", checked: r.enabled, "aria-label": `Rule ${r.name} is on` });
      on.addEventListener("change", async () => {
        try { await put(`/api/alert-rules/${r.id}/enabled`, { enabled: on.checked }); r.enabled = on.checked; draw(); } catch (err) { toast(err.message || "Could not change the rule", "error"); on.checked = !on.checked; }
      });
      return h("tr", { class: r.enabled ? "" : "ar-off" },
        h("td", {}, on),
        h("td", {}, h("strong", {}, r.name), h("div", { class: "hint" }, describe(r))),
        h("td", { class: "num" }, r.muted_7d ? h("a", { href: "#/scans?held=1", title: "See the muted events" }, String(r.muted_7d)) : "0"),
        h("td", {}, h("div", { class: "row-actions" },
          h("button", { type: "button", class: "btn", onclick: () => { editing = JSON.parse(JSON.stringify(r)); draw(); } }, "Change"),
          h("button", { type: "button", class: "btn danger", onclick: async () => {
            if (!window.confirm(`Delete the rule “${r.name}”? Events it muted stay in the list.`)) return;
            try { await del(`/api/alert-rules/${r.id}`); await refresh(); draw(); } catch (err) { toast(err.message || "Could not delete", "error"); }
          } }, "Delete"))));
    });
    box.appendChild(h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["On", "Rule", "Muted, 7 days", ""].map((t) => h("th", {}, t)))), h("tbody", {}, rows))));
    return box;
  }

  // ---------- the form ----------
  function form(rule) {
    const isNew = !rule.id;
    const f = h("form", { class: "ar-form" });
    const name = h("input", { type: "text", maxlength: 60, value: rule.name || "", placeholder: "for example: Garden camera at night", "aria-label": "Name of the rule" });

    // what kind of rule
    let type = rule.type || "mute";
    const typeBox = h("div", { class: "ar-types", role: "radiogroup", "aria-label": "Kind of rule" });
    const typeRadios = {};
    for (const t of data.types) {
      const radio = h("input", { type: "radio", name: "ar-type", value: t, checked: type === t });
      typeRadios[t] = radio;
      radio.addEventListener("change", () => { type = t; show(); });
      typeBox.appendChild(h("label", { class: "ar-type" }, radio, h("span", {}, h("strong", {}, TYPE_TEXT[t][0]), h("span", { class: "hint" }, TYPE_TEXT[t][1]))));
    }

    // which events
    let any = (rule.kinds || []).includes("*");
    const picked = new Set(any ? [] : rule.kinds || []);
    const anyBox = h("input", { type: "checkbox", checked: any });
    const search = h("input", { type: "search", placeholder: "Find an event", autocomplete: "off", "aria-label": "Find an event" });
    const kindList = h("div", { class: "ar-kinds" });
    const count = h("span", { class: "hint" });
    const drawKinds = () => {
      clear(kindList);
      const q = search.value.trim().toLowerCase();
      const row = (k) => h("label", { class: "check-row", title: k.label + (k.critical ? " (critical: kept unless you allow it below)" : "") },
        h("input", { type: "checkbox", checked: picked.has(k.kind), onchange: (e) => { if (e.target.checked) picked.add(k.kind); else picked.delete(k.kind); count.textContent = `${picked.size} chosen`; } }),
        ` ${eventLabel(k.kind)}`, k.critical ? h("span", { class: "hint" }, " · critical") : null);
      const shown = data.kinds.filter((k) => !k.recovery_of && (picked.has(k.kind) || !q || eventLabel(k.kind).toLowerCase().includes(q) || k.label.toLowerCase().includes(q)));
      const problems = shown.filter((k) => k.problem), others = shown.filter((k) => !k.problem);
      if (problems.length) kindList.append(h("div", { class: "tv-heading" }, "Problems"), ...problems.map(row));
      if (others.length) kindList.append(h("div", { class: "tv-heading" }, "Other events"), ...others.map(row));
      if (!shown.length) kindList.appendChild(h("p", { class: "hint" }, "Nothing matches."));
      count.textContent = `${picked.size} chosen`;
    };
    search.addEventListener("input", drawKinds);
    const allProblems = h("button", { type: "button", class: "btn", onclick: () => { for (const k of data.kinds) if (k.problem) picked.add(k.kind); drawKinds(); } }, "All problems");
    const none = h("button", { type: "button", class: "btn", onclick: () => { picked.clear(); drawKinds(); } }, "None");
    const kindsBox = h("div", {}, h("div", { class: "ar-kind-tools" }, search, allProblems, none, count), kindList);
    anyBox.addEventListener("change", () => { any = anyBox.checked; kindsBox.hidden = any; });
    kindsBox.hidden = any;
    drawKinds();
    const recoveries = h("input", { type: "checkbox", checked: rule.recoveries !== false });
    const keepCritical = h("input", { type: "checkbox", checked: rule.keep_critical !== false });

    // which devices
    const scopeSel = h("select", { "aria-label": "Which devices" }, [["all", "Every device"], ["group", "Devices in a group"], ["devices", "These devices"], ["below", "Everything behind a device"], ["tier", "Devices of an importance"], ["type", "Devices of a type"]].map(([v, t]) => h("option", { value: v }, t)));
    scopeSel.value = (rule.scope || {}).type || "all";
    const scope = rule.scope || { type: "all" };
    const groupPicked = new Set(scope.type === "group" ? scope.ids : []);
    const devicePicked = new Set(scope.type === "devices" ? scope.ids : []);
    const scopeBox = h("div", { class: "ar-scope" });
    let belowId = scope.type === "below" ? scope.device_id : null;
    let downId = rule.device_id || null;
    const tierSel = h("select", { "aria-label": "Importance" }, [["critical", "Critical"], ["normal", "Normal"], ["low", "Low"]].map(([v, t]) => h("option", { value: v }, t)));
    tierSel.value = scope.type === "tier" ? scope.value : "low";
    const typeSel = h("select", { "aria-label": "Device type" }, Object.entries(TYPE_LABELS).map(([v, t]) => h("option", { value: v }, t)));
    typeSel.value = scope.type === "type" ? scope.value : "camera";
    const listId = `ar-dev-${Math.random().toString(36).slice(2, 7)}`;
    const datalist = h("datalist", { id: listId }, ...devices.map((d) => h("option", { value: deviceLabel(d) })));
    const devicePick = (current, onPick, label) => {
      const input = h("input", { type: "text", list: listId, autocomplete: "off", placeholder: "Start typing a device name", "aria-label": label, value: current ? deviceLabel(devices.find((d) => d.id === current) || { name: `device ${current}` }) : "" });
      input.addEventListener("change", () => { const d = devices.find((x) => deviceLabel(x) === input.value || x.name === input.value); onPick(d ? d.id : null); if (!d && input.value) toast("Choose a device from the list", "error"); });
      return input;
    };
    const deviceSearch = h("input", { type: "search", placeholder: "Find a device", autocomplete: "off", "aria-label": "Find a device" });
    const deviceList = h("div", { class: "filter-devices" });
    const drawDevices = () => {
      clear(deviceList);
      const q = deviceSearch.value.trim().toLowerCase();
      for (const d of devices.filter((x) => devicePicked.has(x.id) || !q || x.name.toLowerCase().includes(q) || (x.ip || "").includes(q)).slice(0, 60)) {
        deviceList.appendChild(h("label", { class: "check-row" }, h("input", { type: "checkbox", checked: devicePicked.has(d.id), onchange: (e) => { if (e.target.checked) devicePicked.add(d.id); else devicePicked.delete(d.id); } }), ` ${d.name}`, h("span", { class: "hint" }, ` ${d.ip || ""}`)));
      }
    };
    deviceSearch.addEventListener("input", drawDevices);
    const drawScope = () => {
      clear(scopeBox);
      const t = scopeSel.value;
      if (t === "group") scopeBox.appendChild(data.groups.length ? h("div", { class: "event-boxes" }, data.groups.map((g) => h("label", { class: "check-row" }, h("input", { type: "checkbox", checked: groupPicked.has(g.id), onchange: (e) => { if (e.target.checked) groupPicked.add(g.id); else groupPicked.delete(g.id); } }), ` ${g.name}`))) : h("p", { class: "hint" }, "There are no groups yet. Make one under Devices."));
      if (t === "devices") { drawDevices(); scopeBox.append(deviceSearch, deviceList); }
      if (t === "below") scopeBox.append(devicePick(belowId, (id) => { belowId = id; }, "Device whose devices the rule is about"), h("p", { class: "hint" }, "The devices that hang below it in the network hierarchy (not the device itself)."));
      if (t === "tier") scopeBox.appendChild(tierSel);
      if (t === "type") scopeBox.appendChild(typeSel);
    };
    scopeSel.addEventListener("change", drawScope);
    drawScope();

    // the device that has to be offline
    const downBox = h("div", { class: "ar-row" }, h("label", {}, "While this device is offline"), devicePick(downId, (id) => { downId = id; }, "Device that has to be offline"), datalist);

    // repeats
    const countIn = h("input", { type: "number", min: 2, max: 100, value: rule.count || 3, "aria-label": "Number of events" });
    const minutesIn = h("input", { type: "number", min: 1, max: 1440, value: rule.minutes || 10, "aria-label": "Minutes" });
    const perSel = h("select", { "aria-label": "Counted per" }, [["device", "for the same device"], ["scope", "for the chosen devices together"]].map(([v, t]) => h("option", { value: v }, t)));
    perSel.value = rule.per || "device";
    const repeatBox = h("div", { class: "ar-row ar-repeat" }, h("label", {}, "Pass this many, ignore the rest"), h("div", { class: "ar-inline" }, countIn, " events within ", minutesIn, " minutes, ", perSel),
      h("p", { class: "hint" }, "One message tells you when it starts, and the muted events are still listed in Scans & events."));

    // when
    const hasWhen = Boolean(rule.when);
    const whenBox = h("input", { type: "checkbox", checked: hasWhen });
    const dayBoxes = DAY_NAMES.map((d, i) => h("label", { class: "check-row ar-day" }, h("input", { type: "checkbox", checked: hasWhen ? rule.when.days.includes(i) : true, "data-day": i }), ` ${d}`));
    const fromIn = h("input", { type: "time", value: hasWhen ? rule.when.from : "22:00", "aria-label": "From" });
    const toIn = h("input", { type: "time", value: hasWhen ? rule.when.to : "07:00", "aria-label": "To" });
    const whenDetail = h("div", { class: "ar-when" }, h("div", { class: "ar-days" }, dayBoxes), h("div", { class: "ar-inline" }, "from ", fromIn, " to ", toIn, h("span", { class: "hint" }, " (in the time zone of the quiet hours; past midnight counts for the day it started)")));
    whenDetail.hidden = !hasWhen;
    whenBox.addEventListener("change", () => { whenDetail.hidden = !whenBox.checked; });

    const preview = h("div", { class: "ar-preview", "aria-live": "polite" });
    const error = h("p", { class: "error", role: "alert", hidden: true });

    function read() {
      const t = scopeSel.value;
      const body = {
        name: name.value, type, kinds: any ? ["*"] : [...picked], recoveries: recoveries.checked, keep_critical: keepCritical.checked, enabled: rule.enabled !== false,
        scope: t === "group" ? { type: t, ids: [...groupPicked] } : t === "devices" ? { type: t, ids: [...devicePicked] } : t === "below" ? { type: t, device_id: belowId } : t === "tier" ? { type: t, value: tierSel.value } : t === "type" ? { type: t, value: typeSel.value } : { type: "all" },
        when: whenBox.checked ? { days: dayBoxes.map((l) => l.firstChild).filter((i) => i.checked).map((i) => Number(i.dataset.day)), from: fromIn.value, to: toIn.value } : null,
      };
      if (type === "while_down") body.device_id = downId;
      if (type === "repeat") Object.assign(body, { count: Number(countIn.value), minutes: Number(minutesIn.value), per: perSel.value });
      if (rule.id) body.id = rule.id;
      return body;
    }
    function show() {
      downBox.hidden = type !== "while_down";
      repeatBox.hidden = type !== "repeat";
      recoveriesRow.hidden = type === "repeat";
    }

    const recoveriesRow = h("div", { class: "ar-row" }, h("label", { class: "check-row" }, recoveries, " Also ignore the “back online” and similar messages of those events"));
    const testBtn = h("button", { type: "button", class: "btn" }, "What would this have done?");
    testBtn.addEventListener("click", async () => {
      error.hidden = true;
      preview.replaceChildren(h("p", { class: "hint" }, "Replaying the last 7 days…"));
      try {
        const r = await post("/api/alert-rules/preview", { rule: read(), days: 7 });
        preview.replaceChildren(...[
          h("p", {}, h("strong", {}, `In the last 7 days this rule would have muted ${r.muted} of ${r.events} events`), r.muted ? "." : ". Nothing matched: check the events, the devices and the times."),
          Object.keys(r.by_kind).length ? h("p", { class: "hint" }, Object.entries(r.by_kind).map(([k, n]) => `${n} × ${eventLabel(k)}`).join(", ")) : null,
          r.examples.length ? h("ul", { class: "ar-examples" }, ...r.examples.map((e) => h("li", {}, h("span", { class: "hint" }, `${fmtTime(e.ts)} `), `${e.device || ""} ${eventLabel(e.kind)}`))) : null,
          r.truncated ? h("p", { class: "hint" }, "Only the newest events could be replayed.") : null].filter(Boolean));
      } catch (err) {
        preview.replaceChildren(h("p", { class: "error" }, err.message || "Could not replay the events"));
      }
    });
    const save = h("button", { type: "submit", class: "btn primary" }, isNew ? "Add the rule" : "Save the rule");
    const cancel = h("button", { type: "button", class: "btn", onclick: () => { editing = null; draw(); } }, "Cancel");
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      error.hidden = true;
      try {
        if (isNew) await post("/api/alert-rules", read()); else await put(`/api/alert-rules/${rule.id}`, read());
        await refresh();
        editing = null;
        toast("Saved", "success");
        draw();
      } catch (err) {
        error.textContent = err.message || "Could not save the rule";
        error.hidden = false;
      }
    });

    f.append(
      h("div", { class: "ar-row" }, h("label", {}, "Name"), name),
      h("div", { class: "ar-row" }, h("label", {}, "What kind of rule"), typeBox),
      h("div", { class: "ar-row" }, h("label", {}, "Which events"), h("label", { class: "check-row" }, anyBox, " Any event"), kindsBox),
      recoveriesRow,
      h("div", { class: "ar-row" }, h("label", {}, "Which devices"), scopeSel, scopeBox),
      downBox, repeatBox,
      h("div", { class: "ar-row" }, h("label", { class: "check-row" }, whenBox, " Only at certain times"), whenDetail),
      h("div", { class: "ar-row" }, h("label", { class: "check-row" }, keepCritical, " Never ignore critical events"), h("p", { class: "hint" }, "Critical events (a service down, a critical reading, an unknown DHCP server) break through quiet hours too. Untick to let this rule mute them as well.")),
      preview, error,
      h("div", { class: "form-actions" }, save, " ", testBtn, " ", cancel));
    show();
    return f;
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Alert rules"));
    card.appendChild(h("p", { class: "hint" }, "Rules decide which events are not sent. A muted event is still recorded and listed in Scans & events, marked as muted. Security events can never be muted."));
    if (editing) {
      card.appendChild(h("h3", {}, editing.id ? `Change “${editing.name}”` : "Add a rule"));
      card.appendChild(form(editing));
      return;
    }
    card.appendChild(list());
    const toolbar = h("div", { class: "form-actions" });
    if (data.rules.length < data.max_rules) toolbar.appendChild(h("button", { type: "button", class: "btn primary", onclick: () => { editing = { type: "mute", kinds: [], scope: { type: "all" } }; draw(); } }, "Add a rule"));
    if (data.rules.length) toolbar.appendChild(h("a", { class: "btn", href: "#/scans?held=1" }, "See muted events"));
    card.appendChild(toolbar);
  }
  draw();
  return card;
}
