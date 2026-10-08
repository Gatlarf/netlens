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

function channelForm(overview, channel, onDone) {
  const form = h("form", { class: "edit-form" });
  const typeSel = h("select", { name: "type" });
  for (const [key, spec] of Object.entries(overview.types)) typeSel.appendChild(h("option", { value: key }, spec.label));
  typeSel.value = channel ? channel.type : "ntfy";
  typeSel.disabled = Boolean(channel);
  const nameInput = h("input", { type: "text", name: "name", value: channel ? channel.name : "", placeholder: "My phone" });
  const fieldsBox = h("div", {});
  form.append(h("div", { class: "field" }, h("label", {}, "Service"), typeSel), h("div", { class: "field" }, h("label", {}, "Name"), nameInput), fieldsBox);

  function renderFields() {
    clear(fieldsBox);
    for (const f of overview.types[typeSel.value].fields) {
      const secretSet = channel && channel.secrets_set && channel.secrets_set[f.key];
      const value = channel && channel.type === typeSel.value && !f.secret ? channel.settings[f.key] : undefined;
      const input = h("input", {
        type: f.secret ? "password" : "text", name: `setting-${f.key}`, autocomplete: "off",
        value: value ?? (f.secret ? "" : f.default || ""), placeholder: f.secret && secretSet ? "unchanged" : "",
      });
      fieldsBox.appendChild(h("div", { class: "field" }, h("label", {}, f.label + (f.required ? " *" : "")), input, f.help ? h("p", { class: "hint" }, f.help) : null));
    }
  }
  typeSel.addEventListener("change", renderFields);
  renderFields();

  form.appendChild(h("h3", {}, "Tell me when"));
  const events = eventBoxes(overview, channel ? channel.events : overview.default_events);
  form.appendChild(events);
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
      name: nameInput.value, settings,
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
  form.append(
    h("div", { class: "field" }, h("label", {}, enabled, " Use quiet hours")),
    h("div", { class: "field" }, h("label", {}, "From"), start), h("div", { class: "field" }, h("label", {}, "Until"), end),
    h("div", { class: "field" }, h("label", {}, bypass, " Still send when a service goes down")),
    h("p", { class: "hint" }, `Times are in your time zone (${Intl.DateTimeFormat().resolvedOptions().timeZone}).`));
  const save = h("button", { type: "submit", class: "btn" }, "Save");
  form.appendChild(save);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await put("/api/notify-quiet", {
        enabled: enabled.checked, start: start.value, end: end.value, bypass_critical: bypass.checked,
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

export async function buildChannelsCard() {
  const wrap = h("div", {});
  async function load() {
    const overview = await get("/api/notify-channels");
    clear(wrap);
    const card = h("div", { class: "card" }, h("h2", {}, "Notification channels"));
    card.appendChild(h("p", { class: "hint" },
      "Send alerts to your phone or chat: ntfy, Telegram, Discord, Pushover or any webhook (for example Home Assistant). E-mail is set up on its own page. Each channel picks the events it wants."));
    const slot = h("div", {});
    const add = h("button", { class: "btn", type: "button" }, "Add channel");
    add.addEventListener("click", () => {
      clear(slot);
      slot.appendChild(channelForm(overview, null, (changed) => { if (changed) load(); else clear(slot); }));
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
      edit.addEventListener("click", () => {
        clear(slot);
        slot.appendChild(channelForm(overview, c, (changed) => { if (changed) load(); else clear(slot); }));
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
