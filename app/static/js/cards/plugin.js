import { get, put, post, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const KIND_LABEL = { hypervisor: "Hypervisor", topology: "Network topology", dns: "DNS" };

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

// The list of servers: one line per server with its own test button, and a plus button for another line
function serverRow(field, plugin, saved, testRow) {
  const row = h("div", { class: "server-row" });
  row.dataset.id = saved.id || "";
  const grid = h("div", { class: "server-fields" });
  const more = h("div", { class: "server-more" });
  for (const col of field.columns) {
    const isSecret = col.type === "password";
    const input = h("input", {
      type: isSecret ? "password" : "text", name: col.key, autocomplete: isSecret ? "new-password" : "off",
      value: isSecret ? "" : saved[col.key] ?? "",
      placeholder: isSecret && saved[col.key + "_set"] ? "unchanged" : col.placeholder || "",
      "aria-label": col.label, title: col.help ? `${col.label}: ${col.help}` : col.label,
    });
    const cell = h("label", { class: "server-cell" }, h("span", {}, col.label + (col.required ? " *" : "")), input);
    (col.optional ? more : grid).appendChild(cell);
  }
  row.appendChild(grid);
  const hasMore = more.children.length > 0;
  if (hasMore) {
    const details = h("details", { class: "server-optional" }, h("summary", {}, "More"), more);
    details.open = field.columns.some((c) => c.optional && (c.type === "password" ? saved[c.key + "_set"] : saved[c.key]));
    row.appendChild(details);
  }
  const result = h("span", { class: "server-result hint", "aria-live": "polite" });
  const testBtn = h("button", { type: "button", class: "btn server-test" }, "Test");
  const removeBtn = h("button", { type: "button", class: "btn server-remove", title: "Remove this server", "aria-label": "Remove this server" }, "−");
  row.appendChild(h("div", { class: "server-actions" }, testBtn, removeBtn, result));
  testBtn.addEventListener("click", () => testRow(row));
  removeBtn.addEventListener("click", () => {
    const list = row.parentElement;
    row.remove();
    if (!list.querySelector(".server-row")) list.appendChild(serverRow(field, plugin, {}, testRow));
  });
  return row;
}

function readServers(wrap, field) {
  return [...wrap.querySelectorAll(".server-row")].map((row) => {
    const out = { id: row.dataset.id || "" };
    for (const col of field.columns) out[col.key] = row.querySelector(`[name="${col.key}"]`).value;
    return out;
  });
}

function serversInput(field, plugin, testRow) {
  const wrap = h("div", { class: "servers", "data-field": field.key });
  const list = h("div", { class: "server-list" });
  const saved = plugin.config[field.key] || [];
  for (const entry of saved.length ? saved : [{}]) list.appendChild(serverRow(field, plugin, entry, testRow));
  const add = h("button", { type: "button", class: "btn server-add", title: "Add another server", "aria-label": "Add another server" }, "+ Add server");
  add.addEventListener("click", () => {
    const row = serverRow(field, plugin, {}, testRow);
    list.appendChild(row);
    row.querySelector("input").focus();
  });
  wrap.append(list, add);
  return wrap;
}

// One input for one field of the plugin's settings form
function fieldInput(field, plugin, testRow) {
  if (field.type === "servers") return serversInput(field, plugin, testRow);
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
    if (field.type === "servers") {
      config[field.key] = readServers(form.querySelector(`.servers[data-field="${field.key}"]`), field);
      continue;
    }
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

  // A clear on/off banner: an installed plugin does nothing until it is turned on
  const banner = h("div", { class: `plugin-state ${plugin.enabled ? "on" : "off"}`, id: "plugin-state" });
  banner.appendChild(h("strong", {}, plugin.enabled ? "This plugin is ON" : "This plugin is OFF"));
  banner.appendChild(h("span", {}, plugin.enabled
    ? " It syncs after every scan."
    : plugin.configured ? " It does nothing until you turn it on." : " Fill in the settings below, save, then turn it on."));
  const stateBtn = h("button", { type: "button", class: "btn", id: "plugin-state-toggle" }, plugin.enabled ? "Turn off" : "Turn on");
  stateBtn.addEventListener("click", async () => {
    stateBtn.disabled = true;
    try {
      const updated = await put(`/api/plugins/${plugin.id}`, { enabled: !plugin.enabled });
      toast(`${manifest.name} turned ${updated.enabled ? "on" : "off"}`, "success");
      fillPluginCard(card, updated, onChange);
      if (onChange) onChange(updated);
    } catch (err) {
      toast(err.message || "Failed", "error");
      stateBtn.disabled = false;
    }
  });
  banner.appendChild(stateBtn);
  card.appendChild(banner);

  const form = h("form", { class: "edit-form" });
  const enabledField = h("div", { class: "field" });
  enabledField.appendChild(h("label", {}, "Enabled"));
  enabledField.appendChild(h("input", { type: "checkbox", name: "__enabled", checked: plugin.enabled }));
  enabledField.appendChild(h("p", { class: "hint" }, "When on, it syncs now and after every scan. Turning it off removes its links from the map and keeps these settings."));
  form.appendChild(enabledField);

  // Tests one line of a server list with the other settings of the form; the answer is shown on that line
  const serversField = manifest.config.find((f) => f.type === "servers");
  async function testRow(row) {
    const result = row.querySelector(".server-result");
    const button = row.querySelector(".server-test");
    button.disabled = true;
    result.className = "server-result hint";
    result.textContent = "Testing…";
    let ok = false;
    try {
      const entry = { id: row.dataset.id || "" };
      for (const col of serversField.columns) entry[col.key] = row.querySelector(`[name="${col.key}"]`).value;
      const res = await post(`/api/plugins/${plugin.id}/test`, { config: { ...readConfig(form, manifest), [serversField.key]: [entry] } });
      result.textContent = "✓ " + res.message;
      result.className = "server-result ok";
      ok = true;
    } catch (err) {
      result.textContent = "✗ " + (err.message || "Test failed");
      result.className = "server-result error";
    }
    button.disabled = false;
    return ok;
  }

  let section = null;
  for (const field of manifest.config) {
    if (field.section && field.section !== section) form.appendChild(h("h3", {}, field.section));
    section = field.section;
    const wrap = h("div", { class: "field" });
    wrap.appendChild(h("label", {}, field.label + (field.required && field.type !== "bool" ? " *" : "")));
    wrap.appendChild(fieldInput(field, plugin, testRow));
    if (field.help) wrap.appendChild(h("p", { class: "hint" }, field.help));
    form.appendChild(wrap);
  }

  const testBtn = h("button", { type: "button", class: "btn" }, serversField ? "Test all connections" : "Test connection");
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
    if (serversField) {
      // every line in turn, each answer next to its own line
      const rows = [...form.querySelectorAll(".server-row")].filter((r) => [...r.querySelectorAll("input")].some((i) => i.value) || r.dataset.id);
      if (!rows.length) {
        resultEl.textContent = `fill in: ${serversField.label}`;
        resultEl.className = "error";
        testBtn.disabled = false;
        return;
      }
      let good = 0;
      for (const row of rows) if (await testRow(row)) good += 1;
      resultEl.textContent = good === rows.length ? `All ${rows.length} connection${rows.length === 1 ? "" : "s"} work` : `${good} of ${rows.length} connections work`;
      resultEl.className = good === rows.length ? "hint" : "error";
      toast(resultEl.textContent, good === rows.length ? "success" : "error");
      testBtn.disabled = false;
      return;
    }
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
