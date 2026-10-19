import { api, get } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const PRESETS = {
  view: ["summary", "services", "map", "devices"],
  status: ["summary", "services"],
  full: ["summary", "services", "uptime", "map", "devices", "events"],
};
const PRESET_TEXT = { view: "Map and device list", status: "Status page only (counts and services)", full: "Everything" };
const SECTION_TEXT = {
  summary: "Counts of devices online and offline", services: "Services and their state", uptime: "Availability history",
  map: "Map of the network", devices: "Device list", events: "Recent events (devices going offline or online)",
};
const FIELD_TEXT = { type: "Type", vendor: "Vendor", last_seen: "Last seen" };

function linkUrl(link) {
  return `${location.origin}/share/${link.token}`;
}

function describe(link) {
  const o = link.options;
  const parts = o.sections.map((s) => SECTION_TEXT[s].split(" (")[0].toLowerCase());
  const extra = [link.show_ips ? "IPs" : null, link.show_macs ? "MACs" : null, o.group_ids.length ? `${o.group_ids.length} group${o.group_ids.length === 1 ? "" : "s"} only` : null,
    link.has_pin ? "PIN" : null].filter(Boolean);
  return { parts: parts.join(", "), extra: extra.join(", ") };
}

// the browser's own time for the date field, UTC on the server
function localInput(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function checkRow(input, text) {
  return h("label", { class: "check" }, input, ` ${text}`);
}

function buildForm(card, state, existing) {
  const o = existing ? existing.options : { sections: PRESETS.view, service_ids: [], group_ids: [], fields: ["type", "last_seen"], generic_names: false, event_limit: 10, uptime_days: 7, title: "", message: "", brand: "", accent: "", theme: "auto" };
  const form = h("form", { class: "edit-form", id: "new-share-form" });
  const paid = state.sharing_allowed;
  const text = (name, value, attrs = {}) => h("input", { type: "text", name, value: value || "", ...attrs });
  const field = (label, ...inputs) => h("div", { class: "field" }, h("label", {}, label), ...inputs);

  const name = text("name", existing?.name, { required: true, maxlength: "60", placeholder: "Family" });
  const preset = h("select", { name: "preset" }, h("option", { value: "" }, "Custom"), ...Object.entries(PRESET_TEXT).map(([k, t]) => h("option", { value: k }, t)));
  const sections = {};
  const sectionBoxes = Object.entries(SECTION_TEXT).map(([key, label]) => {
    sections[key] = h("input", { type: "checkbox", checked: o.sections.includes(key) });
    sections[key].addEventListener("change", () => { preset.value = ""; });
    return checkRow(sections[key], label);
  });
  preset.addEventListener("change", () => {
    if (!preset.value) return;
    for (const key of Object.keys(sections)) sections[key].checked = PRESETS[preset.value].includes(key);
  });
  const fields = Object.fromEntries(Object.keys(FIELD_TEXT).map((k) => [k, h("input", { type: "checkbox", checked: o.fields.includes(k) })]));
  const ips = h("input", { type: "checkbox", checked: !!existing?.show_ips });
  const macs = h("input", { type: "checkbox", checked: !!existing?.show_macs });
  const generic = h("input", { type: "checkbox", checked: o.generic_names });

  const serviceBoxes = state.services.map((s) => [s, h("input", { type: "checkbox", checked: o.service_ids.includes(s.id) })]);
  const groupBoxes = state.groups.map((g) => [g, h("input", { type: "checkbox", checked: o.group_ids.includes(g.id), disabled: !paid && !o.group_ids.includes(g.id) })]);
  const events = h("input", { type: "number", min: "1", max: "50", value: String(o.event_limit) });
  const days = h("select", {}, h("option", { value: "7", selected: o.uptime_days === 7 }, "7 days"), h("option", { value: "30", selected: o.uptime_days === 30 }, "30 days"));
  const title = text("title", o.title, { maxlength: "60", placeholder: "Shown on the page; the name above is only for you" });
  const message = h("textarea", { rows: "3", maxlength: "500", placeholder: "For example: the router will be replaced on Tuesday." }, o.message);
  const theme = h("select", {}, ...["auto", "light", "dark"].map((t) => h("option", { value: t, selected: o.theme === t }, t === "auto" ? "Follow the visitor's device" : t[0].toUpperCase() + t.slice(1))));
  const brand = text("brand", o.brand, { maxlength: "30", placeholder: "Netlens", disabled: !paid && !o.brand });
  const accent = h("input", { type: "color", value: o.accent || "#2563eb", disabled: !paid && !o.accent });
  const accentOn = h("input", { type: "checkbox", checked: !!o.accent, disabled: !paid && !o.accent });
  const pin = h("input", { type: "password", name: "pin", autocomplete: "new-password", maxlength: "64", placeholder: existing?.has_pin ? "Leave empty to keep the PIN" : "No PIN" });
  const removePin = h("input", { type: "checkbox" });
  const from = h("input", { type: "datetime-local", value: localInput(existing?.valid_from) });
  const expires = h("select", { name: "expires" });
  const choices = [["", existing?.expires ? "Keep the current end" : "Never"], ...(existing?.expires ? [["none", "Never"]] : []), ["1", "1 day"], ["7", "7 days"], ["30", "30 days"], ["90", "90 days"]];
  for (const [value, label] of choices) expires.appendChild(h("option", { value }, label));

  form.appendChild(h("h3", {}, existing ? `Edit "${existing.name}"` : "New link"));
  form.appendChild(field("Name (for you, so you know who has it)", name));
  form.appendChild(h("fieldset", {}, h("legend", {}, "What it shows"), field("Start from", preset), h("div", { class: "field" }, ...sectionBoxes)));
  form.appendChild(h("fieldset", {}, h("legend", {}, "Devices"),
    h("div", { class: "field" }, ...Object.entries(FIELD_TEXT).map(([k, t]) => checkRow(fields[k], `Show ${t.toLowerCase()}`)), checkRow(ips, "Show IP addresses"), checkRow(macs, "Show MAC addresses"),
      checkRow(generic, "Hide device names (show Device 12 instead)"))));
  form.appendChild(h("fieldset", {}, h("legend", {}, "Choose what is included"),
    state.services.length ? h("div", { class: "field" }, h("label", {}, "Services (none ticked = all)"), ...serviceBoxes.map(([s, box]) => checkRow(box, s.name))) : h("p", { class: "hint" }, "There are no service checks to pick from yet."),
    h("div", { class: "field" }, h("label", {}, "Only these groups (none ticked = all devices)"),
      state.groups.length ? groupBoxes.map(([g, box]) => checkRow(box, g.name)) : h("span", { class: "hint" }, "No device groups yet."),
      paid ? null : h("span", { class: "hint" }, "Showing only some groups is part of the Small business and Enterprise editions (or the free trial).")),
    field("Recent events to show", events), field("Availability history covers", days)));
  form.appendChild(h("fieldset", {}, h("legend", {}, "Look"),
    field("Title on the page", title), field("Message to visitors (optional)", message), field("Theme", theme),
    field("Brand name instead of Netlens (business editions)", brand),
    h("div", { class: "field" }, checkRow(accentOn, "Own accent colour (business editions)"), accent)));
  form.appendChild(h("fieldset", {}, h("legend", {}, "Access"),
    field("PIN (asked before anything is shown)", pin, existing?.has_pin ? checkRow(removePin, "Remove the PIN") : null),
    field("Works from (empty = right away)", from), field(existing ? "Valid for (counted from now)" : "Valid for", expires)));

  const save = h("button", { type: "submit", class: "btn" }, existing ? "Save changes" : "Create link");
  const cancel = existing ? h("button", { type: "button", class: "btn" }, "Cancel") : null;
  cancel?.addEventListener("click", () => fill(card, state));
  form.appendChild(h("div", { class: "field" }, save, " ", cancel));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const chosen = Object.keys(sections).filter((k) => sections[k].checked);
    const options = {
      sections: chosen, service_ids: serviceBoxes.filter(([, b]) => b.checked).map(([s]) => s.id), group_ids: groupBoxes.filter(([, b]) => b.checked).map(([g]) => g.id),
      fields: Object.keys(fields).filter((k) => fields[k].checked), generic_names: generic.checked, event_limit: Number(events.value) || 10, uptime_days: Number(days.value),
      title: title.value, message: message.value, theme: theme.value, brand: brand.value, accent: accentOn.checked ? accent.value : "",
    };
    const validFrom = from.value ? new Date(from.value).toISOString() : null;
    try {
      let res;
      if (existing) {
        const body = { name: name.value, show_ips: ips.checked, show_macs: macs.checked, options, valid_from: validFrom };
        if (removePin.checked) body.pin = "";
        else if (pin.value) body.pin = pin.value;
        if (expires.value === "none") body.expires_days = null;
        else if (expires.value) body.expires_days = Number(expires.value);
        res = await api(`/api/shares/${existing.id}`, { method: "PATCH", body });
        toast("Link saved", "success");
      } else {
        res = await api("/api/shares", { method: "POST", body: { name: name.value, mode: chosen.some((k) => k === "map" || k === "devices") ? "view" : "status", show_ips: ips.checked, show_macs: macs.checked,
          expires_days: expires.value ? Number(expires.value) : null, valid_from: validFrom, pin: pin.value || null, options } });
        toast("Link created", "success");
      }
      fill(card, res);
    } catch (err) {
      toast(err.message || "Could not save the link", "error");
    }
  });
  return form;
}

function fill(card, state, editing = null) {
  clear(card);
  const links = state.links;
  card.appendChild(h("h2", {}, "Share links"));
  card.appendChild(h("p", { class: "hint" },
    "A share link shows the network read-only to anyone who has the address, without a login: a family member, a landlord, a screen on the wall. " +
    "You choose which parts to show and whether to include addresses, protect it with a PIN, and give it a start and an end. Delete a link and it stops working at once. " +
    "Only share a link over a connection you trust: Netlens itself should not be reachable from the internet unprotected."));

  if (!links.length) {
    card.appendChild(h("p", { class: "hint" }, "No share links yet."));
  } else {
    const table = h("table", { class: "table shares" });
    table.appendChild(h("thead", {}, h("tr", {}, ["Name", "Shows", "Valid", "Visits", ""].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    for (const link of links) {
      const copy = h("button", { type: "button", class: "btn" }, "Copy link");
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(linkUrl(link));
          toast("Link copied", "success");
        } catch (e) {
          window.prompt("Copy this link:", linkUrl(link));
        }
      });
      const open = h("a", { class: "btn", href: `/share/${link.token}`, target: "_blank", rel: "noopener" }, "Open");
      const edit = h("button", { type: "button", class: "btn" }, "Edit");
      edit.addEventListener("click", () => {
        const old = card.querySelector("#new-share-form");
        old?.replaceWith(buildForm(card, state, link));
        card.querySelector("#new-share-form")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
      const fresh = h("button", { type: "button", class: "btn" }, "New address");
      fresh.addEventListener("click", async () => {
        if (!window.confirm(`Give "${link.name}" a new address? The old address stops working at once; send the new one to whoever should keep access.`)) return;
        try {
          fill(card, await api(`/api/shares/${link.id}`, { method: "PATCH", body: { new_token: true } }));
          toast("New address made", "success");
        } catch (err) {
          toast(err.message || "Could not change the address", "error");
        }
      });
      const del = h("button", { type: "button", class: "btn danger" }, "Delete");
      del.addEventListener("click", async () => {
        if (!window.confirm(`Delete the link "${link.name}"? Anyone using it loses access.`)) return;
        try {
          fill(card, await api(`/api/shares/${link.id}`, { method: "DELETE" }));
          toast("Link deleted", "success");
        } catch (err) {
          toast(err.message || "Could not delete the link", "error");
        }
      });
      const d = describe(link);
      const valid = link.expired ? h("span", { class: "error" }, "expired")
        : link.waiting ? `from ${fmtTime(link.valid_from)}${link.expires ? ` until ${fmtTime(link.expires)}` : ""}`
        : link.expires ? `until ${fmtTime(link.expires)}` : "no end";
      body.appendChild(h("tr", {},
        h("td", {}, h("strong", {}, link.name)),
        h("td", {}, d.parts, d.extra ? h("span", { class: "hint" }, ` + ${d.extra}`) : null),
        h("td", {}, valid),
        h("td", {}, `${link.views}`, link.last_used ? h("span", { class: "hint" }, ` (last ${fmtTime(link.last_used)})`) : null),
        h("td", {}, open, " ", copy, " ", edit, " ", fresh, " ", del)));
    }
    table.appendChild(body);
    card.appendChild(table);
  }
  card.appendChild(buildForm(card, state, editing));
}

export async function buildSharesCard() {
  const card = h("div", { class: "card" });
  fill(card, await get("/api/shares"));
  return card;
}
