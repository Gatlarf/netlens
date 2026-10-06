import { get, post } from "../api.js";
import { h, clear, toast } from "../util.js";

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

export async function render(container, params) {
  clear(container);

  const configCard = h("div", { class: "card" });
  configCard.appendChild(h("h2", {}, "Configuration (read-only, set via environment variables)"));

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

  container.appendChild(configCard);
  container.appendChild(exportCard);
  container.appendChild(sessionCard);

  try {
    const cfg = await get("/api/config");

    configCard.appendChild(kvRow("Version", cfg.version ?? ""));

    const ranges = Array.isArray(cfg.ranges) && cfg.ranges.length > 0
      ? cfg.ranges.join(", ")
      : "auto-detected";
    configCard.appendChild(kvRow("Scan ranges", ranges));

    const quickMin = cfg.quick_interval != null
      ? (cfg.quick_interval / 60).toFixed(0)
      : "";
    configCard.appendChild(kvRow("Quick scan interval (minutes)", quickMin));

    const deepHours = cfg.deep_interval != null
      ? (cfg.deep_interval / 3600).toFixed(1)
      : "";
    configCard.appendChild(kvRow("Deep scan interval (hours)", deepHours));

    configCard.appendChild(kvRow("Web terminal", cfg.terminal_enabled ? "enabled" : "disabled"));
    configCard.appendChild(kvRow("SNMP", cfg.snmp_enabled ? "enabled" : "disabled"));
    configCard.appendChild(kvRow("Listening on", cfg.bind ?? ""));
  } catch (err) {
    const errCard = h("div", { class: "card" });
    errCard.appendChild(h("h2", {}, "Configuration"));
    errCard.appendChild(h("p", { class: "error" }, err.message || "Failed to load configuration"));
    container.appendChild(errCard);
  }
}