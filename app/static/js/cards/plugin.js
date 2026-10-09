import { get, put, post, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const KIND_LABEL = { hypervisor: "Hypervisor", topology: "Network topology" };

function statusText(plugin) {
  const s = plugin.status;
  if (!s) return null;
  if (!s.ok) {
    const paused = s.auth_failed ? ". Automatic syncing is paused until you save or sync again." : "";
    return { error: true, text: `Last sync failed (${timeAgo(s.ts)}): ${s.error}${paused}` };
  }
  const parts = [];
  for (const [key, label] of [["hosts", "hosts"], ["guests", "guests"], ["guests_matched", "matched"], ["nodes", "network nodes"], ["clients", "online clients"], ["links", "links"]]) {
    if (s[key] !== undefined) parts.push(`${s[key]} ${label}`);
  }
  return { error: false, text: `Last sync ${timeAgo(s.ts)}: ${parts.join(", ")}` };
}

// One input for one field of the plugin's settings form
function fieldInput(field, plugin) {
  const saved = plugin.config[field.key];
  if (field.type === "bool") {
    return h("input", { type: "checkbox", name: field.key, checked: saved === true });
  }
  if (field.type === "select") {
    const select = h("select", { name: field.key });
    for (const opt of field.options) select.appendChild(h("option", { value: opt.value }, opt.label));
    select.value = saved ?? field.default;
    return select;
  }
  if (field.type === "number") {
    return h("input", {
      type: "number", name: field.key, step: "any", min: field.min, max: field.max,
      value: saved === null || saved === undefined ? "" : String(saved), placeholder: field.placeholder,
    });
  }
  if (field.type === "password") {
    return h("input", {
      type: "password", name: field.key, autocomplete: "new-password",
      placeholder: plugin.secrets_set[field.key] ? "unchanged" : field.placeholder,
    });
  }
  return h("input", { type: "text", name: field.key, value: saved ?? "", placeholder: field.placeholder, autocomplete: "off" });
}

function readConfig(form, manifest) {
  const config = {};
  for (const field of manifest.config) {
    const input = form.querySelector(`[name="${field.key}"]`);
    if (!input) continue;
    if (field.type === "bool") config[field.key] = input.checked;
    else if (field.type === "number") config[field.key] = input.value === "" ? null : Number(input.value);
    else if (field.type === "password") {
      if (input.value) config[field.key] = input.value; // empty keeps the saved secret
    } else config[field.key] = input.value;
  }
  return config;
}

function fillPluginCard(card, plugin, onChange) {
  clear(card);
  const manifest = plugin.manifest;
  if (!manifest) {
    card.appendChild(h("h2", {}, plugin.id));
    card.appendChild(h("p", { class: "error" }, `This plugin is broken: ${plugin.problem}`));
    if (!plugin.builtin) card.appendChild(removeButton(plugin, onChange));
    return;
  }

  card.appendChild(h("h2", {}, manifest.name));
  const meta = [KIND_LABEL[manifest.kind] || manifest.kind, `version ${manifest.version}`, plugin.builtin ? "built in" : "uploaded"];
  if (manifest.author) meta.push(`by ${manifest.author}`);
  card.appendChild(h("p", { class: "hint" }, meta.join(" · ")));
  if (manifest.description) card.appendChild(h("p", { class: "hint" }, manifest.description));
  if (plugin.problem) card.appendChild(h("p", { class: "error" }, plugin.problem));

  const form = h("form", { class: "edit-form" });
  const enabledField = h("div", { class: "field" });
  enabledField.appendChild(h("label", {}, "Enable this plugin"));
  enabledField.appendChild(h("input", { type: "checkbox", name: "__enabled", checked: plugin.enabled }));
  enabledField.appendChild(h("p", { class: "hint" }, "When on, it syncs now and after every scan. Turning it off removes its links from the map and keeps these settings."));
  form.appendChild(enabledField);

  let section = null;
  for (const field of manifest.config) {
    if (field.section && field.section !== section) form.appendChild(h("h3", {}, field.section));
    section = field.section;
    const wrap = h("div", { class: "field" });
    wrap.appendChild(h("label", {}, field.label + (field.required && field.type !== "bool" ? " *" : "")));
    wrap.appendChild(fieldInput(field, plugin));
    if (field.help) wrap.appendChild(h("p", { class: "hint" }, field.help));
    form.appendChild(wrap);
  }

  const testBtn = h("button", { type: "button", class: "btn" }, "Test connection");
  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const syncBtn = h("button", { type: "button", class: "btn" }, "Sync now");
  syncBtn.disabled = !plugin.configured;
  form.appendChild(testBtn);
  form.appendChild(saveBtn);
  form.appendChild(syncBtn);
  if (!plugin.builtin) form.appendChild(removeButton(plugin, onChange));
  const resultEl = h("p", { class: "hint" }, "");
  form.appendChild(resultEl);

  // plugins that offer a diagnostic get a button that produces a report to send to the plugin's author
  const diagnoseBox = h("div", { class: "diagnose-box", id: "diagnose-box" });
  if (manifest.diagnose) {
    const diagBtn = h("button", { type: "button", class: "btn", id: "diagnose-run" }, "Run diagnostic");
    form.insertBefore(diagBtn, resultEl);
    diagBtn.addEventListener("click", async () => {
      diagBtn.disabled = true;
      diagBtn.textContent = "Running…";
      clear(diagnoseBox);
      try {
        const res = await post(`/api/plugins/${plugin.id}/diagnose`, { config: readConfig(form, manifest) });
        const text = JSON.stringify({ plugin: res.plugin, version: res.version, ...res.report }, null, 2);
        const area = h("textarea", { readonly: true, rows: "14", class: "diagnose-text", "aria-label": "Diagnostic report" });
        area.value = text;
        const copy = h("button", { type: "button", class: "btn" }, "Copy");
        copy.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(text);
            toast("Copied", "success");
          } catch (e) {
            area.select();
            toast("Press Ctrl+C to copy the selected text", "info");
          }
        });
        const link = h("a", { class: "btn", href: URL.createObjectURL(new Blob([text], { type: "application/json" })), download: `${plugin.id}-diagnostic.json` }, "Download");
        diagnoseBox.append(
          h("p", { class: "hint" }, "This describes what the device answered (field names and types). Names, addresses, MAC addresses and your settings are left out. Read it, then send it to whoever maintains the plugin."),
          area, copy, " ", link);
      } catch (err) {
        diagnoseBox.appendChild(h("p", { class: "error" }, err.message || "The diagnostic failed"));
      }
      diagBtn.disabled = false;
      diagBtn.textContent = "Run diagnostic";
    });
  }
  form.appendChild(diagnoseBox);

  const status = statusText(plugin);
  if (status) card.appendChild(h("p", { class: status.error ? "error" : "hint" }, status.text));

  testBtn.addEventListener("click", async () => {
    testBtn.disabled = true;
    resultEl.textContent = "";
    try {
      const res = await post(`/api/plugins/${plugin.id}/test`, { config: readConfig(form, manifest) });
      resultEl.textContent = res.message;
      resultEl.className = "hint";
      toast("Connection test successful", "success");
    } catch (err) {
      resultEl.textContent = err.message || "Test failed";
      resultEl.className = "error";
      toast(err.message || "Test failed", "error");
    }
    testBtn.disabled = false;
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    saveBtn.disabled = true;
    try {
      const updated = await put(`/api/plugins/${plugin.id}`, {
        enabled: form.querySelector('[name="__enabled"]').checked,
        config: readConfig(form, manifest),
      });
      toast(`${manifest.name} saved`, "success");
      fillPluginCard(card, updated, onChange);
      if (onChange) onChange(updated);
    } catch (err) {
      toast(err.message || "Failed to save", "error");
      saveBtn.disabled = false;
    }
  });

  syncBtn.addEventListener("click", async () => {
    syncBtn.disabled = true;
    try {
      await post(`/api/plugins/${plugin.id}/sync`, {});
      toast("Synced", "success");
    } catch (err) {
      toast(err.message || "Sync failed", "error");
    }
    const updated = await get(`/api/plugins/${plugin.id}`);
    fillPluginCard(card, updated, onChange);
  });

  card.appendChild(form);
}

function removeButton(plugin, onChange) {
  const btn = h("button", { type: "button", class: "btn danger" }, "Remove plugin");
  btn.addEventListener("click", async () => {
    if (!window.confirm(`Remove the plugin "${plugin.id}" and its saved settings?`)) return;
    try {
      await del(`/api/plugins/${plugin.id}`);
      toast("Plugin removed", "success");
      location.hash = "#/settings/plugins";
    } catch (err) {
      toast(err.message || "Failed to remove", "error");
    }
  });
  return btn;
}

export async function buildPluginCard(pluginId) {
  const card = h("div", { class: "card" });
  fillPluginCard(card, await get(`/api/plugins/${pluginId}`));
  return card;
}
