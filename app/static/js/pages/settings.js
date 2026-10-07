import { get, post, put } from "../api.js";
import { h, clear, toast } from "../util.js";
import { buildScanOptionsCard } from "../cards/scan_options.js";
import { buildGeneralCard } from "../cards/general.js";
import { buildNotificationsCard } from "../cards/notifications.js";
import { buildProxmoxCard } from "../cards/proxmox.js";
import { buildBackupCard } from "../cards/backup.js";

function kvRow(label, value) {
  const row = h("div", { class: "kv" });
  row.appendChild(h("span", { class: "kv-key" }, label));
  row.appendChild(h("span", { class: "kv-value" }, value));
  return row;
}

function downloadLink(href, label) {
  const a = h("a", { class: "export-link", href, download: "" }, label);
  return a;
}

const SOURCE_TEXT = {
  ui: "set on this page",
  env: "from the NETLENS_RANGES environment variable",
  auto: "auto-detected from this host's network interfaces",
};

function fillRangesCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "Scan ranges"));

  const current = cfg.ranges && cfg.ranges.length > 0
    ? cfg.ranges.join(", ")
    : (cfg.detected_ranges && cfg.detected_ranges.length > 0
      ? cfg.detected_ranges.join(", ")
      : "none found");
  card.appendChild(kvRow("Scanning", current));
  card.appendChild(kvRow("Source", SOURCE_TEXT[cfg.ranges_source] || ""));
  if (cfg.ranges_source !== "auto" && cfg.detected_ranges && cfg.detected_ranges.length > 0) {
    card.appendChild(kvRow("Detected on this host", cfg.detected_ranges.join(", ")));
  }

  const form = h("form", { class: "edit-form" });
  const field = h("div", { class: "field" });
  field.appendChild(h("label", {}, "Ranges to scan"));
  const input = h("input", {
    type: "text",
    name: "ranges",
    placeholder: "e.g. 192.168.1.0/24, 10.0.0.0/22",
    value: cfg.ranges_source === "ui" ? cfg.ranges.join(", ") : "",
  });
  field.appendChild(input);
  field.appendChild(h("p", { class: "hint" },
    "Separate several ranges with commas. Private IPv4 only (10.x, 172.16-31.x, 192.168.x), " +
    "each /20 or smaller. Applies from the next scan. It also limits which devices the web " +
    "terminal may connect to. Leave empty and save, or use Reset, to go back to the default."));
  form.appendChild(field);

  const errorEl = h("p", { class: "error" }, "");
  form.appendChild(errorEl);

  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  const resetBtn = h("button", { type: "button", class: "btn" }, "Reset to default");
  form.appendChild(saveBtn);
  form.appendChild(resetBtn);

  async function submit(ranges, doneMessage) {
    errorEl.textContent = "";
    saveBtn.disabled = true;
    resetBtn.disabled = true;
    try {
      const updated = await put("/api/config/ranges", { ranges });
      toast(doneMessage, "success");
      fillRangesCard(card, updated);
    } catch (err) {
      errorEl.textContent = err.message || "Failed to save";
      saveBtn.disabled = false;
      resetBtn.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const ranges = input.value.split(/[\s,;]+/).filter(Boolean);
    submit(ranges, ranges.length > 0 ? "Scan ranges saved" : "Scan ranges reset");
  });
  resetBtn.addEventListener("click", () => submit([], "Scan ranges reset"));

  card.appendChild(form);
}

export async function render(container, params) {
  clear(container);

  const configCard = h("div", { class: "card" });
  configCard.appendChild(h("h2", {}, "About"));

  const exportCard = h("div", { class: "card" });
  exportCard.appendChild(h("h2", {}, "Export"));
  exportCard.appendChild(downloadLink("/api/export/devices.csv", "Devices CSV"));
  exportCard.appendChild(downloadLink("/api/export/devices.json", "Devices JSON"));

  const sessionCard = h("div", { class: "card" });
  sessionCard.appendChild(h("h2", {}, "Session"));
  const logoutBtn = h("button", { class: "btn", type: "button" }, "Log out");
  logoutBtn.addEventListener("click", async () => {
    try {
      await post("/api/logout");
      toast("Logged out", "info");
      document.dispatchEvent(new CustomEvent("netlens:unauth"));
    } catch (err) {
      toast(err.message || "Logout failed", "error");
    }
  });
  sessionCard.appendChild(logoutBtn);

  const rangesCard = h("div", { class: "card" });
  container.appendChild(rangesCard);
  const scanSlot = h("div", {});
  const generalSlot = h("div", {});
  const notifySlot = h("div", {});
  const proxmoxSlot = h("div", {});
  container.appendChild(scanSlot);
  container.appendChild(generalSlot);
  container.appendChild(notifySlot);
  container.appendChild(proxmoxSlot);
  container.appendChild(buildBackupCard());
  container.appendChild(configCard);
  for (const [slot, build] of [[scanSlot, buildScanOptionsCard], [generalSlot, buildGeneralCard], [notifySlot, buildNotificationsCard], [proxmoxSlot, buildProxmoxCard]]) {
    build().then((card) => {
      slot.appendChild(card);
    }).catch((err) => {
      slot.appendChild(h("div", { class: "card" }, h("p", { class: "error" }, err.message || "Failed to load")));
    });
  }
  container.appendChild(exportCard);
  container.appendChild(sessionCard);

  try {
    const cfg = await get("/api/config");

    configCard.appendChild(kvRow("Version", cfg.version ?? ""));

    fillRangesCard(rangesCard, cfg);

    configCard.appendChild(kvRow("SNMP", cfg.snmp_enabled ? "enabled" : "disabled"));
    configCard.appendChild(kvRow("Listening on", cfg.bind ?? ""));
  } catch (err) {
    const errCard = h("div", { class: "card" });
    errCard.appendChild(h("h2", {}, "Configuration"));
    errCard.appendChild(h("p", { class: "error" }, err.message || "Failed to load configuration"));
    container.appendChild(errCard);
  }

  // "#/settings/nmap" (the header button) jumps straight to the nmap card. Done last so the
  // cards above it have their final height and the card stays at the top of the screen.
  if (params && params.section === "nmap") {
    const target = document.getElementById("nmap-settings");
    if (target) target.scrollIntoView({ block: "start" });
  }
}
