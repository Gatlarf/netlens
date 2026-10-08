import { get, post, put } from "../api.js";
import { h, clear, toast } from "../util.js";
import { buildScanOptionsCard } from "../cards/scan_options.js";
import { buildGeneralCard } from "../cards/general.js";
import { buildNotificationsCard } from "../cards/notifications.js";
import { buildPluginCard } from "../cards/plugin.js";
import { buildPluginsCard } from "../cards/plugins.js";
import { buildPluginGuideCard } from "../cards/plugin_guide.js";
import { buildMapCard } from "../cards/map_settings.js";
import { buildBackupCard } from "../cards/backup.js";
import { buildIgnoredCard } from "../cards/ignored.js";

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

async function buildRangesCard() {
  const card = h("div", { class: "card" });
  fillRangesCard(card, await get("/api/config"));
  return card;
}

async function buildAboutCard() {
  const cfg = await get("/api/config");
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "About"));
  card.appendChild(kvRow("Version", cfg.version ?? ""));
  card.appendChild(kvRow("SNMP", cfg.snmp_enabled ? "enabled" : "disabled"));
  card.appendChild(kvRow("Listening on", cfg.bind ?? ""));
  return card;
}

function buildExportCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Export"));
  card.appendChild(downloadLink("/api/export/devices.csv", "Devices CSV"));
  card.appendChild(downloadLink("/api/export/devices.json", "Devices JSON"));
  return card;
}

function buildSessionCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Session"));
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
  card.appendChild(logoutBtn);
  return card;
}

// The pages of Settings, grouped in the side menu. Every page is its own address ("#/settings/<key>") and shows
// only its card. A builder returns a card (or a promise of one). The Integrations group is built from the plugins
// that are installed: one page per plugin, plus the Plugins list and the guide.
const STATIC_GROUPS = [
  {
    title: "General",
    items: [
      { key: "ranges", label: "Scan ranges", build: buildRangesCard },
      { key: "nmap", label: "Scan performance", build: buildScanOptionsCard },
      { key: "schedule", label: "Schedule & terminal", build: buildGeneralCard },
      { key: "map", label: "Map", build: buildMapCard },
    ],
  },
  {
    title: "Notifications",
    items: [{ key: "notifications", label: "E-mail notifications", build: buildNotificationsCard }],
  },
  "integrations",
  {
    title: "Data",
    items: [
      { key: "ignored", label: "Ignored devices", build: buildIgnoredCard },
      { key: "backup", label: "Backup & restore", build: buildBackupCard },
      { key: "export", label: "Export", build: buildExportCard },
    ],
  },
  {
    title: "System",
    items: [
      { key: "about", label: "About", build: buildAboutCard },
      { key: "session", label: "Session", build: buildSessionCard },
    ],
  },
];

const DEFAULT_PAGE = "ranges";
// the connectors were plugins-to-be before: keep their old addresses working
const ALIASES = { proxmox: "plugin-proxmox", asus: "plugin-asus" };

function integrationsGroup(plugins) {
  const items = [
    { key: "plugins", label: "Plugins", build: buildPluginsCard },
    ...plugins.map((p) => ({ key: `plugin-${p.id}`, label: p.name, build: () => buildPluginCard(p.id) })),
    { key: "plugin-guide", label: "Plugin guide", build: buildPluginGuideCard },
  ];
  return { title: "Integrations", items };
}

async function loadGroups() {
  let plugins = [];
  try {
    plugins = (await get("/api/plugins")).plugins;
  } catch (err) {
    // the Plugins page shows the error itself; the rest of Settings still works
  }
  plugins = [...plugins].sort((a, b) => a.name.localeCompare(b.name));
  return STATIC_GROUPS.map((g) => (g === "integrations" ? integrationsGroup(plugins) : g));
}

function fillNav(nav, groups, activeKey) {
  clear(nav);
  for (const group of groups) {
    nav.appendChild(h("div", { class: "nav-group" }, group.title));
    for (const entry of group.items) {
      const link = h("a", { href: `#/settings/${entry.key}`, "data-section": entry.key }, entry.label);
      if (entry.key === activeKey) {
        link.classList.add("active");
        link.setAttribute("aria-current", "page");
      }
      nav.appendChild(link);
    }
  }
}

export async function render(container, params) {
  clear(container);
  let groups = await loadGroups();
  const items = () => groups.flatMap((g) => g.items);
  const requested = params && (ALIASES[params.section] || params.section);
  const item = items().find((i) => i.key === requested) || items().find((i) => i.key === DEFAULT_PAGE);
  if (params && params.section && item.key !== params.section) {
    // an address that does not exist (or an old one): show the right page under its own address, without a new history entry
    history.replaceState(null, "", `#/settings/${item.key}`);
  }

  const nav = h("nav", { class: "settings-nav", "aria-label": "Settings pages" });
  fillNav(nav, groups, item.key);
  const content = h("div", { class: "settings-content", id: `sec-${item.key}` });
  container.appendChild(h("div", { class: "settings-layout" }, nav, content));

  // installing or removing a plugin changes the menu
  let destroyed = false;
  const onPluginsChanged = async () => {
    const fresh = await loadGroups();
    if (destroyed) return;
    groups = fresh;
    fillNav(nav, groups, item.key);
  };
  document.addEventListener("netlens:plugins-changed", onPluginsChanged);

  content.appendChild(h("div", { class: "card" }, h("p", { class: "hint" }, "Loading...")));
  try {
    const card = await item.build();
    if (destroyed) return;
    clear(content);
    content.appendChild(card);
  } catch (err) {
    if (destroyed) return;
    clear(content);
    content.appendChild(h("div", { class: "card" }, h("h2", {}, item.label), h("p", { class: "error" }, err.message || "Failed to load")));
  }

  return () => {
    destroyed = true;
    document.removeEventListener("netlens:plugins-changed", onPluginsChanged);
  };
}
