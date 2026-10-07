import { get, put } from "../api.js";
import { h, clear, toast } from "../util.js";

function sourceHint(source, envVarName, envValue, unit) {
  if (source !== "ui") return `From the environment (${envVarName})`;
  let def = "";
  if (unit === "min") def = `${Math.round(envValue / 60)} min`;
  else if (unit === "hours") def = `${Math.round((envValue / 3600) * 100) / 100} hours`;
  else def = envValue ? "enabled" : "disabled";
  return `Changed here; environment default: ${def}`;
}

function fillGeneralCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "Scan schedule and terminal"));

  const form = h("form", { class: "edit-form" });

  const quickField = h("div", { class: "field" });
  quickField.appendChild(h("label", {}, "Quick scan every (minutes)"));
  const quickInput = h("input", {
    type: "number",
    name: "quick_minutes",
    min: "1",
    step: "1",
    value: String(Math.round(cfg.quick_interval / 60)),
  });
  quickField.appendChild(quickInput);
  quickField.appendChild(h("p", { class: "hint" }, sourceHint(cfg.quick_interval_source, "NETLENS_QUICK_INTERVAL", cfg.env_quick_interval, "min")));
  form.appendChild(quickField);

  const deepField = h("div", { class: "field" });
  deepField.appendChild(h("label", {}, "Deep scan every (hours)"));
  const deepInput = h("input", {
    type: "number",
    name: "deep_hours",
    min: "0.05",
    step: "any",
    value: String(Math.round(cfg.deep_interval / 3600 * 100) / 100),
  });
  deepField.appendChild(deepInput);
  deepField.appendChild(h("p", { class: "hint" }, sourceHint(cfg.deep_interval_source, "NETLENS_DEEP_INTERVAL", cfg.env_deep_interval, "hours")));
  form.appendChild(deepField);

  const termField = h("div", { class: "field" });
  termField.appendChild(h("label", {}, "Enable the web terminal (SSH/Telnet from the device page)"));
  const termCheck = h("input", {
    type: "checkbox",
    name: "terminal_enabled",
    checked: cfg.terminal_enabled,
  });
  termField.appendChild(termCheck);
  termField.appendChild(h("p", { class: "hint" }, sourceHint(cfg.terminal_source, "NETLENS_TERMINAL", cfg.env_terminal_enabled, "bool")));
  form.appendChild(termField);

  const errorEl = h("p", { class: "error" }, "");
  form.appendChild(errorEl);

  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const resetBtn = h("button", { type: "button", class: "btn" }, "Reset to defaults");
  form.appendChild(saveBtn);
  form.appendChild(resetBtn);

  async function submit(body, doneMessage) {
    errorEl.textContent = "";
    saveBtn.disabled = true;
    resetBtn.disabled = true;
    try {
      const updated = await put("/api/config/general", body);
      toast(doneMessage, "success");
      fillGeneralCard(card, updated);
    } catch (err) {
      errorEl.textContent = err.message || "Failed to save";
      saveBtn.disabled = false;
      resetBtn.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const minutes = parseFloat(quickInput.value);
    const hours = parseFloat(deepInput.value);
    if (isNaN(minutes) || minutes < 1) {
      errorEl.textContent = "Enter a number of minutes";
      return;
    }
    if (isNaN(hours) || hours < 0.05) {
      errorEl.textContent = "Enter a number of hours";
      return;
    }
    submit({
      quick_interval: Math.round(minutes * 60),
      deep_interval: Math.round(hours * 3600),
      terminal_enabled: termCheck.checked,
    }, "Settings saved");
  });

  resetBtn.addEventListener("click", () => {
    submit({ quick_interval: null, deep_interval: null, terminal_enabled: null }, "Settings reset");
  });

  card.appendChild(form);
  card.appendChild(h("p", { class: "hint" }, "Takes effect from the next scheduler cycle; no restart needed."));
}

export async function buildGeneralCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Scan schedule and terminal"));
  card.appendChild(h("p", {}, "Loading..."));
  try {
    const cfg = await get("/api/config");
    fillGeneralCard(card, cfg);
  } catch (err) {
    clear(card);
    card.appendChild(h("h2", {}, "Scan schedule and terminal"));
    card.appendChild(h("p", { class: "error" }, err.message || "Failed to load"));
  }
  return card;
}