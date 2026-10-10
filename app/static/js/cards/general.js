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

// Two cards over the same settings: the scan schedule, and the web terminal. Each one saves and resets only its own part.
function fillScheduleCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "Scan schedule"));
  const form = h("form", { class: "edit-form" });

  const quickField = h("div", { class: "field" });
  quickField.appendChild(h("label", {}, "Quick scan every (minutes)"));
  const quickInput = h("input", { type: "number", name: "quick_minutes", min: "1", step: "1", value: String(Math.round(cfg.quick_interval / 60)) });
  quickField.appendChild(quickInput);
  quickField.appendChild(h("p", { class: "hint" }, sourceHint(cfg.quick_interval_source, "NETLENS_QUICK_INTERVAL", cfg.env_quick_interval, "min")));
  form.appendChild(quickField);

  const deepField = h("div", { class: "field" });
  deepField.appendChild(h("label", {}, "Deep scan every (hours)"));
  const deepInput = h("input", { type: "number", name: "deep_hours", min: "0.05", step: "any", value: String(Math.round(cfg.deep_interval / 3600 * 100) / 100) });
  deepField.appendChild(deepInput);
  deepField.appendChild(h("p", { class: "hint" }, sourceHint(cfg.deep_interval_source, "NETLENS_DEEP_INTERVAL", cfg.env_deep_interval, "hours")));
  form.appendChild(deepField);

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
      fillScheduleCard(card, updated);
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
    submit({ quick_interval: Math.round(minutes * 60), deep_interval: Math.round(hours * 3600) }, "Schedule saved");
  });
  resetBtn.addEventListener("click", () => submit({ quick_interval: null, deep_interval: null }, "Schedule reset"));

  card.appendChild(form);
  card.appendChild(h("p", { class: "hint" }, "Takes effect from the next scheduler cycle; no restart needed."));
}

function fillTerminalCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "Web terminal"));
  const form = h("form", { class: "edit-form" });

  const termField = h("div", { class: "field" });
  termField.appendChild(h("label", {}, "Enable the web terminal (SSH/Telnet from the device page)"));
  const termCheck = h("input", { type: "checkbox", name: "terminal_enabled", checked: cfg.terminal_enabled });
  termField.appendChild(termCheck);
  termField.appendChild(h("p", { class: "hint" }, sourceHint(cfg.terminal_source, "NETLENS_TERMINAL", cfg.env_terminal_enabled, "bool")));
  const remoteText = {
    off: "The terminal only works on a direct connection from the local network (http://<this machine>:8080). Through a reverse proxy / HTTPS address it is blocked.",
    lan: "The terminal works on a direct local connection and through a reverse proxy when the proxy reports a local client address (NETLENS_TERMINAL_REMOTE=lan).",
    any: "The terminal works from anywhere (NETLENS_TERMINAL_REMOTE=any). Make sure something else protects Netlens, such as a VPN.",
  }[cfg.terminal_remote] || "";
  termField.appendChild(h("p", { class: "hint", id: "terminal-reach" }, remoteText + " This is set with the environment variable NETLENS_TERMINAL_REMOTE (off, lan or any) and cannot be changed here, so nobody who reaches the web interface from outside can open it up."));
  if (!cfg.terminal_allowed_here) {
    termCheck.disabled = true;
    termField.appendChild(h("p", { class: "error" }, `You are connected from outside the local network (${cfg.terminal_here}); the terminal switch can only be changed from the local network.`));
  }
  form.appendChild(termField);

  const errorEl = h("p", { class: "error" }, "");
  form.appendChild(errorEl);
  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const resetBtn = h("button", { type: "button", class: "btn" }, "Reset to default");
  form.appendChild(saveBtn);
  form.appendChild(resetBtn);

  async function submit(body, doneMessage) {
    errorEl.textContent = "";
    saveBtn.disabled = true;
    resetBtn.disabled = true;
    try {
      const updated = await put("/api/config/general", body);
      toast(doneMessage, "success");
      fillTerminalCard(card, updated);
    } catch (err) {
      errorEl.textContent = err.message || "Failed to save";
      saveBtn.disabled = false;
      resetBtn.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    submit({ terminal_enabled: termCheck.checked }, "Terminal setting saved");
  });
  resetBtn.addEventListener("click", () => submit({ terminal_enabled: null }, "Terminal setting reset"));
  card.appendChild(form);
}

async function build(title, fill) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, title));
  card.appendChild(h("p", {}, "Loading..."));
  try {
    fill(card, await get("/api/config"));
  } catch (err) {
    clear(card);
    card.appendChild(h("h2", {}, title));
    card.appendChild(h("p", { class: "error" }, err.message || "Failed to load"));
  }
  return card;
}

export const buildScheduleCard = () => build("Scan schedule", fillScheduleCard);
export const buildTerminalCard = () => build("Web terminal", fillTerminalCard);
