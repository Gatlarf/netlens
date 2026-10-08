import { get, put, post, ApiError } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const SECURITY_DEFAULTS = { starttls: 587, ssl: 465, none: 25 };

function buildStatusLine(status) {
  if (!status) return null;
  const p = h("p", { class: status.ok ? "hint" : "error" });
  if (status.ok) {
    p.textContent = `Last notification mail: ${timeAgo(status.ts)} (${status.sent} event(s))`;
  } else {
    p.textContent = `Last problem (${timeAgo(status.ts)}): ${status.error}`;
  }
  return p;
}

function fillCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "E-mail notifications"));

  const form = h("form", { class: "edit-form" });
  const errorEl = h("p", { class: "error" }, "");

  const enabledField = h("div", { class: "field" });
  const enabledInput = h("input", {
    type: "checkbox",
    name: "enabled",
    checked: cfg.enabled,
  });
  enabledField.appendChild(h("label", {}, "Send e-mail notifications"));
  enabledField.appendChild(enabledInput);
  form.appendChild(enabledField);

  const smtpHostField = h("div", { class: "field" });
  smtpHostField.appendChild(h("label", {}, "SMTP server"));
  const smtpHostInput = h("input", {
    type: "text",
    name: "smtp_host",
    value: cfg.smtp_host,
  });
  smtpHostField.appendChild(smtpHostInput);
  form.appendChild(smtpHostField);

  const portField = h("div", { class: "field" });
  portField.appendChild(h("label", {}, "Port"));
  const portInput = h("input", {
    type: "number",
    name: "smtp_port",
    value: cfg.smtp_port,
  });
  portField.appendChild(portInput);
  form.appendChild(portField);

  const securityField = h("div", { class: "field" });
  securityField.appendChild(h("label", {}, "Security"));
  const securitySelect = h("select", { name: "security" });
  const options = [
    { value: "starttls", text: "STARTTLS (port 587)" },
    { value: "ssl", text: "SSL/TLS (port 465)" },
    { value: "none", text: "None (port 25)" },
  ];
  for (const opt of options) {
    const option = h("option", { value: opt.value }, opt.text);
    if (cfg.security === opt.value) option.selected = true;
    securitySelect.appendChild(option);
  }
  securityField.appendChild(securitySelect);
  form.appendChild(securityField);

  const usernameField = h("div", { class: "field" });
  usernameField.appendChild(h("label", {}, "Username"));
  const usernameInput = h("input", {
    type: "text",
    name: "username",
    value: cfg.username,
  });
  usernameField.appendChild(usernameInput);
  form.appendChild(usernameField);

  const passwordField = h("div", { class: "field" });
  passwordField.appendChild(h("label", {}, "Password"));
  const passwordInput = h("input", {
    type: "password",
    name: "password",
    autocomplete: "new-password",
    placeholder: cfg.password_set ? "unchanged" : "",
  });
  passwordField.appendChild(passwordInput);
  form.appendChild(passwordField);

  const fromField = h("div", { class: "field" });
  fromField.appendChild(h("label", {}, "From address"));
  const fromInput = h("input", {
    type: "text",
    name: "from_addr",
    value: cfg.from_addr,
  });
  fromField.appendChild(fromInput);
  form.appendChild(fromField);

  const toField = h("div", { class: "field" });
  toField.appendChild(h("label", {}, "To address(es)"));
  const toInput = h("input", {
    type: "text",
    name: "to_addrs",
    value: cfg.to_addrs.join(", "),
  });
  toField.appendChild(toInput);
  form.appendChild(toField);

  const notifyNewField = h("div", { class: "field" });
  const notifyNewInput = h("input", {
    type: "checkbox",
    name: "notify_new",
    checked: cfg.notify_new,
  });
  notifyNewField.appendChild(h("label", {}, "Notify when a new device appears"));
  notifyNewField.appendChild(notifyNewInput);
  form.appendChild(notifyNewField);

  const notifyOfflineField = h("div", { class: "field" });
  const notifyOfflineInput = h("input", {
    type: "checkbox",
    name: "notify_offline",
    checked: cfg.notify_offline,
  });
  notifyOfflineField.appendChild(h("label", {}, "Notify when a device goes offline"));
  notifyOfflineField.appendChild(notifyOfflineInput);
  notifyOfflineField.appendChild(h("p", { class: "hint" },
    "You can switch this off for individual devices on their device page."));
  form.appendChild(notifyOfflineField);

  const notifyServicesField = h("div", { class: "field" });
  const notifyServicesInput = h("input", { type: "checkbox", name: "notify_services", checked: cfg.notify_services !== false });
  notifyServicesField.appendChild(h("label", {}, "Notify when a service check goes down or comes back"));
  notifyServicesField.appendChild(notifyServicesInput);
  form.appendChild(notifyServicesField);

  form.appendChild(errorEl);

  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const testBtn = h("button", { type: "button", class: "btn" }, "Send test email");
  form.appendChild(saveBtn);
  form.appendChild(testBtn);

  securitySelect.addEventListener("change", () => {
    const newDefault = SECURITY_DEFAULTS[securitySelect.value];
    const currentPort = parseInt(portInput.value, 10);
    const oldDefault = SECURITY_DEFAULTS[cfg.security];
    if (currentPort === oldDefault) {
      portInput.value = newDefault;
    }
  });

  async function submit(body, doneMessage) {
    errorEl.textContent = "";
    saveBtn.disabled = true;
    testBtn.disabled = true;
    try {
      const updated = await put("/api/notifications", body);
      toast(doneMessage, "success");
      fillCard(card, updated);
    } catch (err) {
      errorEl.textContent = err.message || "Failed to save";
      saveBtn.disabled = false;
      testBtn.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const body = {
      enabled: enabledInput.checked,
      smtp_host: smtpHostInput.value,
      smtp_port: parseInt(portInput.value, 10),
      security: securitySelect.value,
      username: usernameInput.value,
      from_addr: fromInput.value,
      to_addrs: toInput.value,
      notify_new: notifyNewInput.checked,
      notify_offline: notifyOfflineInput.checked,
      notify_services: notifyServicesInput.checked,
    };
    if (passwordInput.value) {
      body.password = passwordInput.value;
    }
    submit(body, "Settings saved");
  });

  testBtn.addEventListener("click", async () => {
    errorEl.textContent = "";
    saveBtn.disabled = true;
    testBtn.disabled = true;
    try {
      const body = {
        enabled: enabledInput.checked,
        smtp_host: smtpHostInput.value,
        smtp_port: parseInt(portInput.value, 10),
        security: securitySelect.value,
        username: usernameInput.value,
        from_addr: fromInput.value,
        to_addrs: toInput.value,
        notify_new: notifyNewInput.checked,
        notify_offline: notifyOfflineInput.checked,
        notify_services: notifyServicesInput.checked,
      };
      if (passwordInput.value) {
        body.password = passwordInput.value;
      }
      await put("/api/notifications", body);
      const result = await post("/api/notifications/test");
      toast(`Test email sent to ${result.to.join(", ")}`, "success");
    } catch (err) {
      errorEl.textContent = err.message || "Failed to send test email";
    }
    saveBtn.disabled = false;
    testBtn.disabled = false;
  });

  card.appendChild(form);

  const statusLine = buildStatusLine(cfg.status);
  if (statusLine) card.appendChild(statusLine);
}

export async function buildNotificationsCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "E-mail notifications"));
  card.appendChild(h("p", { class: "hint" }, "Loading..."));

  try {
    const cfg = await get("/api/notifications");
    fillCard(card, cfg);
  } catch (err) {
    clear(card);
    card.appendChild(h("h2", {}, "E-mail notifications"));
    card.appendChild(h("p", { class: "error" }, err.message || "Failed to load"));
  }

  return card;
}