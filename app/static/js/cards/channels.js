import { get, post, put, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

function statusText(c) {
  if (!c.status) return h("span", { class: "hint" }, c.enabled ? "nothing sent yet" : "off");
  if (c.status.ok) return h("span", { class: "hint" }, `sent ${timeAgo(c.status.ts)}: ${c.status.title || ""}`);
  return h("span", { class: "error" }, `failed ${timeAgo(c.status.ts)}: ${c.status.error}`);
}

function eventBoxes(overview, selected) {
  const box = h("div", { class: "event-boxes" });
  for (const ev of overview.events) {
    const input = h("input", { type: "checkbox", name: `event-${ev.key}`, "data-event": ev.key, checked: selected.includes(ev.key) });
    box.appendChild(h("label", { class: "check-row" }, input, " ", ev.label));
  }
  return box;
}

// "Only when": a minimum severity, and optionally only some groups and devices (none ticked = all of them)
function filterBox(filters, groups, devices) {
  const f = filters || { min_severity: "info", devices: [], groups: [] };
  const level = h("select", { name: "min_severity" }, [["info", "Everything selected above"], ["warning", "Warnings and serious problems"], ["critical", "Serious problems only"]].map(([v, label]) => h("option", { value: v }, label)));
  level.value = f.min_severity;
  const tier = h("select", { name: "min_tier" }, [["any", "Every device and service"], ["normal", "Not the ones marked low"], ["critical", "Only the ones marked critical"]].map(([v, label]) => h("option", { value: v }, label)));
  tier.value = f.min_tier || "any";
  const alwaysOn = h("input", { type: "checkbox", checked: !!f.always_on_only });
  const groupBoxes = groups.map((g) => h("label", { class: "check-row" }, h("input", { type: "checkbox", "data-group": g.id, checked: f.groups.includes(g.id) }), " ", g.name));
  const picked = new Set(f.devices);
  const search = h("input", { type: "search", placeholder: "Find a device", autocomplete: "off" });
  const list = h("div", { class: "filter-devices" });
  const draw = () => {
    clear(list);
    const q = search.value.trim().toLowerCase();
    for (const d of devices.filter((x) => picked.has(x.id) || !q || x.name.toLowerCase().includes(q) || (x.ip || "").includes(q)).slice(0, 60)) {
      list.appendChild(h("label", { class: "check-row" }, h("input", { type: "checkbox", checked: picked.has(d.id), onchange: (e) => { if (e.target.checked) picked.add(d.id); else picked.delete(d.id); } }), " ", d.name, h("span", { class: "hint" }, ` ${d.ip || ""}`)));
    }
  };
  search.addEventListener("input", draw);
  draw();
  const box = h("div", { class: "filter-box" },
    h("div", { class: "field" }, h("label", {}, "How serious"), level),
    h("div", { class: "field" }, h("label", {}, "How important"), tier, h("p", { class: "hint" }, "The importance is set on each device (its Settings tab) and each service check.")),
    h("div", { class: "field" }, h("label", { class: "check-row" }, alwaysOn, " Only for always-on devices"), h("p", { class: "hint" }, "“Went offline” and “back online” are sent only for devices marked always-on (their Settings tab), so a phone leaving the Wi-Fi stays quiet. Everything else (disks, services, backups) is not affected.")),
    groups.length ? h("div", { class: "field" }, h("label", {}, "Only these groups"), h("div", { class: "event-boxes" }, groupBoxes)) : null,
    devices.length ? h("div", { class: "field" }, h("label", {}, "Only these devices"), search, list, h("p", { class: "hint" }, "Leave all unticked to hear about every device. With groups and devices both ticked, an event counts when it is about one of them.")) : null);
  box.read = () => ({ min_severity: level.value, min_tier: tier.value, always_on_only: alwaysOn.checked, groups: groupBoxes.map((l) => l.firstChild).filter((i) => i.checked).map((i) => Number(i.dataset.group)), devices: [...picked] });
  return box;
}

function channelForm(overview, channel, onDone, defaultType, extra = { groups: [], devices: [] }) {
  const form = h("form", { class: "edit-form" });
  const typeSel = h("select", { name: "type" });
  for (const [key, spec] of Object.entries(overview.types)) typeSel.appendChild(h("option", { value: key }, spec.label));
  typeSel.value = channel ? channel.type : (defaultType || "email");
  typeSel.disabled = Boolean(channel);
  const nameInput = h("input", { type: "text", name: "name", value: channel ? channel.name : "", placeholder: "My phone" });
  const fieldsBox = h("div", {});
  form.append(h("div", { class: "field" }, h("label", {}, "Service"), typeSel), h("div", { class: "field" }, h("label", {}, "Name"), nameInput), fieldsBox);

  function renderFields() {
    clear(fieldsBox);
    for (const f of overview.types[typeSel.value].fields) {
      const secretSet = channel && channel.secrets_set && channel.secrets_set[f.key];
      const value = channel && channel.type === typeSel.value && !f.secret ? channel.settings[f.key] : undefined;
      let input;
      if (f.kind === "select") {
        input = h("select", { name: `setting-${f.key}` }, f.options.map(([v, label]) => h("option", { value: v }, label)));
        input.value = value ?? f.default ?? f.options[0][0];
      } else {
        input = h("input", {
          type: f.secret ? "password" : f.kind === "number" ? "number" : "text", name: `setting-${f.key}`, autocomplete: "off",
          value: value ?? (f.secret ? "" : f.default || ""), placeholder: f.secret && secretSet ? "unchanged" : "",
        });
      }
      fieldsBox.appendChild(h("div", { class: "field" }, h("label", {}, f.label + (f.required ? " *" : "")), input, f.help ? h("p", { class: "hint" }, f.help) : null));
    }
  }
  typeSel.addEventListener("change", renderFields);
  renderFields();

  form.appendChild(h("h3", {}, "Tell me when"));
  const events = eventBoxes(overview, channel ? channel.events : overview.default_events);
  form.appendChild(events);
  form.appendChild(h("h3", {}, "Only when"));
  const filters = filterBox(channel && channel.filters, extra.groups, extra.devices);
  form.appendChild(filters);
  form.appendChild(h("h3", {}, "Own quiet hours"));
  const q = (channel && channel.quiet) || { enabled: false, start: "23:00", end: "07:00", bypass_critical: true };
  const qOn = h("input", { type: "checkbox", checked: Boolean(q.enabled) });
  const qStart = h("input", { type: "time", value: q.start });
  const qEnd = h("input", { type: "time", value: q.end });
  const qBypass = h("input", { type: "checkbox", checked: q.bypass_critical !== false });
  form.appendChild(h("div", { class: "field" }, h("label", {}, qOn, " This channel has its own quiet hours"),
    h("p", { class: "hint" }, "For one person's sleep: a channel per person, each with their own hours. They replace the general quiet hours for this channel only. Held messages arrive as one digest afterwards."),
    h("label", {}, "From ", qStart, " until ", qEnd), h("label", { class: "check-row" }, qBypass, " Still send when a service goes down"),
    h("p", { class: "hint" }, `Times are in your time zone (${Intl.DateTimeFormat().resolvedOptions().timeZone}).`)));
  const error = h("p", { class: "error" }, "");
  const save = h("button", { type: "submit", class: "btn" }, channel ? "Save" : "Add channel");
  const cancel = h("button", { type: "button", class: "btn" }, "Cancel");
  form.append(error, save, cancel);
  cancel.addEventListener("click", () => onDone(false));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.textContent = "";
    const settings = {};
    for (const f of overview.types[typeSel.value].fields) settings[f.key] = form.querySelector(`[name="setting-${f.key}"]`).value;
    const body = {
      name: nameInput.value, settings, filters: filters.read(),
      quiet: qOn.checked ? { enabled: true, start: qStart.value, end: qEnd.value, bypass_critical: qBypass.checked, tz: Intl.DateTimeFormat().resolvedOptions().timeZone, offset_min: -new Date().getTimezoneOffset() } : null,
      events: [...events.querySelectorAll("input[data-event]")].filter((i) => i.checked).map((i) => i.dataset.event),
    };
    save.disabled = true;
    try {
      if (channel) await put(`/api/notify-channels/${channel.id}`, body);
      else await post("/api/notify-channels", { ...body, type: typeSel.value });
      toast(channel ? "Channel saved" : "Channel added", "success");
      onDone(true);
    } catch (err) {
      error.textContent = err.message || "Could not save";
      save.disabled = false;
    }
  });
  return form;
}

function quietCard(overview, reload) {
  const q = overview.quiet;
  const card = h("div", { class: "card" }, h("h2", {}, "Quiet hours"));
  card.appendChild(h("p", { class: "hint" }, "In quiet hours Netlens holds messages back and sends them afterwards as one digest. A service check going down can still break through."));
  const form = h("form", { class: "edit-form" });
  const enabled = h("input", { type: "checkbox", name: "enabled", checked: q.enabled });
  const start = h("input", { type: "time", name: "start", value: q.start });
  const end = h("input", { type: "time", name: "end", value: q.end });
  const bypass = h("input", { type: "checkbox", name: "bypass_critical", checked: q.bypass_critical });
  const cause = h("input", { type: "checkbox", name: "group_by_cause", checked: q.group_by_cause !== false });
  form.append(
    h("div", { class: "field" }, h("label", {}, enabled, " Use quiet hours")),
    h("div", { class: "field" }, h("label", {}, "From"), start), h("div", { class: "field" }, h("label", {}, "Until"), end),
    h("div", { class: "field" }, h("label", {}, bypass, " Still send when a service goes down")),
    h("p", { class: "hint" }, `Times are in your time zone (${Intl.DateTimeFormat().resolvedOptions().timeZone}).`),
    h("div", { class: "field" }, h("label", {}, cause, " Group alerts by cause"),
      h("p", { class: "hint" }, "When a switch or a host goes offline, send one message (\u201cX is offline, 4 devices behind it cannot be reached\u201d) instead of one for each device behind it.")));
  const save = h("button", { type: "submit", class: "btn" }, "Save");
  form.appendChild(save);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await put("/api/notify-quiet", {
        enabled: enabled.checked, start: start.value, end: end.value, bypass_critical: bypass.checked, group_by_cause: cause.checked,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone, offset_min: -new Date().getTimezoneOffset(),
      });
      toast("Quiet hours saved", "success");
      reload();
    } catch (err) {
      toast(err.message || "Could not save", "error");
    }
  });
  card.appendChild(form);
  return card;
}

async function lookups() {
  const [g, d] = await Promise.all([get("/api/groups").catch(() => ({ groups: [] })), get("/api/devices").catch(() => [])]);
  return { groups: g.groups || [], devices: d.map((x) => ({ id: x.id, name: x.custom_name || x.hostname || x.primary_ip || `device ${x.id}`, ip: x.primary_ip })).sort((a, b) => a.name.localeCompare(b.name)) };
}

export async function buildChannelsCard() {
  const wrap = h("div", {});
  async function load() {
    const overview = await get("/api/notify-channels");
    clear(wrap);
    const card = h("div", { class: "card" }, h("h2", {}, "Notification channels"));
    card.appendChild(h("p", { class: "hint" },
      "Send alerts by e-mail, to your phone or to a chat: e-mail (SMTP), ntfy, Telegram, Discord, Pushover or any webhook (n8n, OpenClaw, Home Assistant). Each channel picks the events it wants, how serious they are and which devices or groups they are about."));
    const gaps = overview.coverage && overview.coverage.gaps || [];
    if (gaps.length) {                                  // nobody would be told about these: say so, and offer the fix
      const first = overview.channels.find((c) => c.enabled);
      const fix = first ? h("button", { class: "btn", type: "button" }, `Add them to ${first.name}`) : null;
      if (fix) fix.addEventListener("click", async () => {
        try {
          await put(`/api/notify-channels/${first.id}`, { events: [...new Set([...first.events, ...gaps.map((g) => g.kind)])] });
          toast("Added", "success");
        } catch (err) {
          toast(err.message || "Could not save", "error");
        }
        load();
      });
      card.appendChild(h("div", { class: "card warning", role: "alert" }, h("strong", {}, first ? `You would not be told about ${gaps.length} event${gaps.length === 1 ? "" : "s"}` : "No channel is on: nobody is told about anything"),
        h("details", { class: "gap-list" }, h("summary", {}, "Show which"), h("ul", {}, gaps.map((g) => h("li", {}, g.label, h("span", { class: "hint" }, ` (${g.why})`))))), fix));
    }
    const slot = h("div", {});
    const add = h("button", { class: "btn", type: "button" }, "Add channel");
    add.addEventListener("click", async () => {
      const extra = await lookups();
      clear(slot);
      slot.appendChild(channelForm(overview, null, (changed) => { if (changed) load(); else clear(slot); }, undefined, extra));
    });
    if (!overview.channels.length) card.appendChild(h("p", {}, "No channels yet."));
    for (const c of overview.channels) {
      const row = h("div", { class: "kv channel-row" });
      const toggle = h("input", { type: "checkbox", checked: c.enabled, title: "Enabled" });
      toggle.addEventListener("change", async () => {
        try {
          await put(`/api/notify-channels/${c.id}`, { enabled: toggle.checked });
        } catch (err) {
          toast(err.message || "Could not change the channel", "error");
        }
        load();
      });
      const test = h("button", { class: "btn", type: "button" }, "Send test");
      test.addEventListener("click", async () => {
        test.disabled = true;
        try {
          await post(`/api/notify-channels/${c.id}/test`, {});
          toast(`Test message sent to ${c.name}`, "success");
        } catch (err) {
          toast(err.message || "The test failed", "error");
        }
        test.disabled = false;
      });
      const edit = h("button", { class: "btn", type: "button" }, "Edit");
      edit.addEventListener("click", async () => {
        const extra = await lookups();
        clear(slot);
        slot.appendChild(channelForm(overview, c, (changed) => { if (changed) load(); else clear(slot); }, undefined, extra));
      });
      const remove = h("button", { class: "btn danger", type: "button" }, "Delete");
      remove.addEventListener("click", async () => {
        if (!window.confirm(`Delete the channel "${c.name}"?`)) return;
        await del(`/api/notify-channels/${c.id}`);
        load();
      });
      row.append(h("span", { class: "kv-label" }, toggle, " ", h("strong", {}, c.name), ` (${overview.types[c.type].label})`), statusText(c), test, edit, remove);
      card.appendChild(row);
    }
    card.append(add, slot);
    wrap.append(card, quietCard(overview, load));
  }
  await load();
  return wrap;
}
