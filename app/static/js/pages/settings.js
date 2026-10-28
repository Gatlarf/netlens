import { buildMaintenanceCard } from "../cards/maintenance.js";
import { get, post, put } from "../api.js";
import { groupButtons } from "../ui.js";
import { h, clear, toast, isAdmin, fmtTime } from "../util.js";
import { buildScanOptionsCard } from "../cards/scan_options.js";
import { buildScheduleCard, buildTerminalCard } from "../cards/general.js";
import { buildPluginCard } from "../cards/plugin.js";
import { buildPluginsCard } from "../cards/plugins.js";
import { buildPluginGuideCard } from "../cards/plugin_guide.js";
import { buildMapCard } from "../cards/map_settings.js";
import { buildChannelsCard } from "../cards/channels.js";
import { buildCentralCard } from "../cards/central.js";
import { buildAiModelCard, buildAiAgentsCard } from "../cards/ai.js";
import { buildHostProbeCard } from "../cards/hostprobe_settings.js";
import { buildIngestCard } from "../cards/ingest.js";
import { buildCredentialsCard } from "../cards/credentials.js";
import { buildHostsSetupCard } from "../cards/hosts_setup.js";
import { buildLicenceCard } from "../cards/licence.js";
import { buildIpv6Card } from "../cards/ipv6.js";
import { buildEscalationCard } from "../cards/escalation.js";
import { buildSsoCard } from "../cards/sso.js";
import { buildSiemCard } from "../cards/siem.js";
import { buildInboundCard } from "../cards/inbound.js";
import { buildOncallCard } from "../cards/oncall.js";
import { buildUsageCard } from "../cards/usage.js";
import { buildUpdateCard } from "../update.js";
import { buildBrowseCard } from "../cards/plugin_browse.js";
import { buildBackupCard } from "../cards/backup.js";
import { buildDatabaseCard } from "../cards/database.js";
import { buildAccountCard } from "../cards/account.js";
import { buildAuditCard } from "../cards/audit.js";
import { buildUsersCard } from "../cards/users.js";
import { buildSharesCard } from "../cards/shares.js";
import { buildNetchecksCard } from "../cards/netchecks.js";
import { buildCveCheckCard } from "../cards/cve_check.js";
import { buildDnsCard } from "../cards/dns.js";
import { buildReliabilityCard } from "../cards/reliability_settings.js";
import { buildInterfaceCard } from "../cards/interface_settings.js";
import { buildGroupsCard } from "../cards/groups.js";
import { buildIgnoredCard } from "../cards/ignored.js";
import { buildPassiveCard } from "../cards/passive.js";
import { buildChangelogCard } from "../changelog.js";
import { revealFound, openSearch } from "../search.js";

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

export async function buildRangesCard() {
  const card = h("div", { class: "card" });
  fillRangesCard(card, await get("/api/config"));
  return card;
}

// "Manufacturer database": which copy of the IEEE registry names the manufacturers, with an update button
async function buildVendorDbRow() {
  const info = await get("/api/vendor-db");
  const row = h("div", { id: "vendor-db-row" });
  const text = () => `${info.entries.toLocaleString()} manufacturers (${info.source}${info.refreshed ? `, updated ${fmtTime(info.refreshed)}` : ""}). It updates itself every month.`;
  const line = kvRow("Registry", text());
  const btn = h("button", { type: "button", class: "btn admin-only", id: "vendor-db-update" }, "Update now");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Downloading…";
    try {
      const res = await post("/api/vendor-db/refresh", {});
      Object.assign(info, res);
      toast(`Vendor database updated (${res.result.vendors_filled} vendor(s) filled in, ${res.result.types_changed} type(s) changed)`, "success");
      clear(row);
      row.append(kvRow("Registry", text()), btn);
    } catch (err) {
      toast(err.message || "Update failed", "error");
    }
    btn.disabled = false;
    btn.textContent = "Update now";
  });
  row.append(line, btn);
  if (info.error) row.appendChild(h("p", { class: "hint" }, `Last attempt failed: ${info.error}`));
  return row;
}

async function buildAboutCard() {
  const cfg = await get("/api/config");
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "About"));
  card.appendChild(kvRow("Version", cfg.version ?? ""));
  card.appendChild(kvRow("Listening on", cfg.bind ?? ""));
  card.appendChild(h("p", { class: "hint" }, "Netlens is free for noncommercial use and made in spare time. If it helps you, a coffee keeps the updates coming."));
  card.appendChild(h("a", { class: "btn", href: "https://buymeacoffee.com/Gatlarf", target: "_blank", rel: "noopener noreferrer" }, "\u2615 Buy me a coffee"));
  card.appendChild(h("a", { class: "btn", href: "#/wizard" }, "Open the setup guide"));
  if (isAdmin()) {
    // The bill of materials of this very installation (what it is made of, with versions, licences and hashes), for supply-chain and vulnerability reviews.
    const sbomButton = (label, format, file) => {
      const b = h("button", { class: "btn", type: "button", title: "The software bill of materials of this installation" }, label);
      b.addEventListener("click", async () => {
        try {
          const doc = await get(`/api/sbom?format=${format}`);
          const a = h("a", { href: URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" })), download: file });
          document.body.appendChild(a); a.click(); a.remove();
        } catch (err) { toast(err.message || "Could not make the SBOM", "error"); }
      });
      return b;
    };
    card.appendChild(h("p", { class: "hint" }, "Software bill of materials (SBOM): every package this installation is made of, with versions, licences and hashes, for supply-chain and vulnerability reviews."));
    card.appendChild(h("div", { class: "btn-row" }, sbomButton("Download SBOM (CycloneDX)", "cyclonedx", `netlens-${cfg.version || "sbom"}.cdx.json`), sbomButton("Download SBOM (SPDX)", "spdx", `netlens-${cfg.version || "sbom"}.spdx.json`)));
  }
  const wrap = h("div", {}, card);
  try {
    wrap.appendChild(await buildUpdateCard());
  } catch (err) {
    // the About card still works without the update card
  }
  try {
    wrap.appendChild(await buildChangelogCard());
  } catch (err) {
    // ... nor without the changelog
  }
  return wrap;
}

// A way back into the getting-started guide
async function buildWizardCard() {
  let state = null;
  try { state = await get("/api/wizard"); } catch (err) { /* the button still works */ }
  const card = h("div", { class: "card" }, h("h2", {}, "Setup guide"));
  card.appendChild(h("p", { class: "hint" }, "A short guided tour of the settings that matter most: networks, names, always-on devices, alerts, checks and plugins. Nothing is changed unless you change it, and every step can be skipped."));
  if (state && state.status === "done") card.appendChild(h("p", { class: "hint" }, "You have been through it before; it opens with your current settings."));
  card.appendChild(h("a", { class: "btn primary", href: "#/wizard", id: "open-wizard" }, state && state.status === "done" ? "Open the setup guide again" : "Open the setup guide"));
  return card;
}

// The manufacturer registry belongs with the identification settings, not with the version information
async function buildVendorDbCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Manufacturer database"));
  card.appendChild(h("p", { class: "hint" }, "Netlens names the manufacturer of a device from its MAC address with the IEEE registry. A copy ships with Netlens and is refreshed from the IEEE website every month."));
  card.appendChild(await buildVendorDbRow());
  return card;
}

// "Scan performance" also holds what widens the identification beyond scans
async function buildScanPage() {
  const wrap = h("div", {});
  wrap.appendChild(await buildScanOptionsCard());
  if (isAdmin()) {
    try {
      wrap.appendChild(await buildVendorDbCard());
    } catch (err) {
      // the scan settings still work without it
    }
    try {
      wrap.appendChild(await buildPassiveCard());
    } catch (err) {
      // the scan settings still work without it
    }
  }
  return wrap;
}

function buildExportCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Export"));
  card.appendChild(downloadLink("/api/export/devices.csv", "Devices CSV"));
  card.appendChild(downloadLink("/api/export/devices.json", "Devices JSON"));
  return card;
}

// The pages of Settings, grouped in the side menu. Every page is its own address ("#/settings/<key>") and shows
// only its card. A builder returns a card (or a promise of one). The Integrations group is built from the plugins
// that are installed: one page per plugin, plus the Plugins list and the guide.
const STATIC_GROUPS = [
  {
    title: "Scanning",
    items: [
      { key: "ranges", label: "Scan ranges", build: buildRangesCard },
      { key: "nmap", label: "Scan performance", build: buildScanPage },
      { key: "schedule", label: "Scan schedule", build: buildScheduleCard },
      { key: "netchecks", label: "Network checks", build: buildNetchecksCard },
      { key: "ipv6", label: "IPv6", build: buildIpv6Card },
      { key: "dns", label: "DNS registration", build: () => buildDnsCard("settings") },
      { key: "reliability", label: "Reliability target", build: buildReliabilityCard },
      { key: "cvecheck", label: "Version check (CVE)", build: () => buildCveCheckCard() },
      { key: "ignored", label: "Ignored devices", build: buildIgnoredCard },
    ],
  },
  {
    title: "Display",
    items: [
      { key: "interface", label: "Interface", build: buildInterfaceCard },
      { key: "map", label: "Map", build: buildMapCard },
      { key: "groups", label: "Groups", build: buildGroupsCard },
    ],
  },
  {
    title: "Access",
    items: [
      { key: "users", label: "Users & tokens", build: buildUsersCard },
      { key: "sso", label: "Single sign-on", build: buildSsoCard },
      { key: "terminal", label: "Web terminal", build: buildTerminalCard },
    ],
  },
  {
    title: "Notifications",
    items: [
      { key: "channels", label: "Alert channels & quiet hours", build: buildChannelsCard },
      { key: "maintenance", label: "Maintenance windows", build: buildMaintenanceCard },
      { key: "escalation", label: "Escalation", build: buildEscalationCard },
      { key: "oncall", label: "On-call schedule", build: buildOncallCard },
      { key: "siem", label: "Log forwarding", build: buildSiemCard },
      { key: "inbound", label: "Device messages (traps, syslog)", build: buildInboundCard },
    ],
  },
  "integrations",
  {
    title: "Connections",
    items: [
      { key: "central", label: "Report to a central Netlens", build: buildCentralCard },
      { key: "engineer", label: "AI language model", build: buildAiModelCard },
      { key: "agents", label: "AI agents (assistant, MCP)", build: buildAiAgentsCard },
      { key: "hosts", label: "Hosts (monitoring set-up)", build: buildHostsSetupCard },
      { key: "credentials", label: "Credentials", build: buildCredentialsCard },
      { key: "hostprobes", label: "Host probes", build: buildHostProbeCard },
      { key: "ingest", label: "Host agents (locked-down hosts)", build: buildIngestCard },
    ],
  },
  {
    title: "Data",
    items: [
      { key: "backup", label: "Backup & restore", build: buildBackupCard },
      { key: "database", label: "Database", build: buildDatabaseCard },
      { key: "usage", label: "Traffic statistics", build: buildUsageCard },
      { key: "export", label: "Export", build: buildExportCard },
      { key: "shares", label: "Share links", build: buildSharesCard },
    ],
  },
  {
    title: "System",
    items: [
      { key: "wizard", label: "Setup guide", build: buildWizardCard },
      { key: "audit", label: "Audit log", build: buildAuditCard },
      { key: "licence", label: "Licence", build: buildLicenceCard },
      { key: "about", label: "About", build: buildAboutCard },
      { key: "session", label: "Account", build: buildAccountCard },
    ],
  },
];

const DEFAULT_PAGE = "ranges";
const VIEWER_PAGE = "session";
// the connectors were plugins-to-be before: keep their old addresses working
const ALIASES = { proxmox: "plugin-proxmox", asus: "plugin-asus", notifications: "channels", assistant: "agents", mcp: "agents" };  // e-mail is a channel now

function integrationsGroup(plugins, updates = 0) {
  const items = [
    { key: "plugins", label: "Plugin manager", build: buildPluginsCard },
    { key: "plugin-browse", label: updates ? `Plugin store (${updates} update${updates === 1 ? "" : "s"})` : "Plugin store", build: buildBrowseCard },
    // a plugin's own page is not in the menu: open it from the Plugin manager (its name is a link)
    ...plugins.map((p) => ({ key: `plugin-${p.id}`, label: p.name, hidden: true, parent: "plugins", build: () => buildPluginCard(p.id) })),
    { key: "plugin-guide", label: "Plugin guide", hidden: true, parent: "plugins", build: buildPluginGuideCard },
  ];
  return { title: "Integrations", items };
}

async function loadGroups() {
  if (!isAdmin()) return [{ title: "Account", items: [{ key: "session", label: "Account", build: buildAccountCard }] }];
  let plugins = [];
  let updates = 0;
  try {
    plugins = (await get("/api/plugins")).plugins;
  } catch (err) {
    // the Plugins page shows the error itself; the rest of Settings still works
  }
  try {
    updates = (await get("/api/plugin-index?cache_only=true")).updates || 0; // from the cache only: opening Settings never waits for the internet
  } catch (err) {
    updates = 0;
  }
  plugins = [...plugins].sort((a, b) => a.name.localeCompare(b.name));
  return STATIC_GROUPS.map((g) => (g === "integrations" ? integrationsGroup(plugins, updates) : g));
}

function fillNav(nav, groups, activeKey) {
  clear(nav);
  const all = groups.flatMap((g) => g.items);
  const here = all.find((e) => e.key === activeKey);
  const current = here && here.parent ? here.parent : activeKey;     // on a plugin's page the Plugin manager is the one lit up
  for (const group of groups) {
    nav.appendChild(h("div", { class: "nav-group" }, group.title));
    for (const entry of group.items) {
      if (entry.hidden) continue; // reachable by address (linked from the Plugin manager), not listed in the menu
      const link = h("a", { href: `#/settings/${entry.key}`, "data-section": entry.key }, entry.label);
      if (entry.key === current) {
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
  const item = items().find((i) => i.key === requested) || items().find((i) => i.key === DEFAULT_PAGE) || items().find((i) => i.key === VIEWER_PAGE);
  if (params && params.section && item.key !== params.section) {
    // an address that does not exist (or an old one): show the right page under its own address, without a new history entry
    history.replaceState(null, "", `#/settings/${item.key}`);
  }

  const nav = h("nav", { class: "settings-nav", "aria-label": "Settings pages" });
  fillNav(nav, groups, item.key);
  const content = h("div", { class: "settings-content", id: `sec-${item.key}` });
  // narrow screens: the page list folds into one button that names the current page
  const toggle = h("button", { type: "button", class: "btn settings-nav-toggle", "aria-expanded": "false", id: "settings-nav-toggle" },
    h("span", {}, `Settings: ${item.label}`), h("span", { class: "caret" }, "▾"));
  const finder = h("button", { type: "button", class: "btn settings-find", title: "Search pages, settings and devices (press /)", onclick: () => openSearch() }, "Search settings…  ( / )");
  const side = h("div", { class: "settings-side" }, toggle, finder, nav);
  toggle.addEventListener("click", () => {
    const open = !side.classList.contains("open");
    side.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", String(open));
    toggle.querySelector(".caret").textContent = open ? "▴" : "▾";
  });
  container.appendChild(h("div", { class: "settings-layout" }, side, content));
  // in the middle of the setup guide: a way back
  if (isAdmin()) {
    get("/api/wizard").then((w) => {
      if (destroyed || !w || w.status !== "pending") return;
      container.prepend(h("div", { class: "card wiz-banner", id: "wizard-back" },
        h("p", {}, "You are in the middle of the setup guide."), h("a", { class: "btn primary", href: "#/wizard" }, "Back to the setup guide")));
    }).catch(() => {});
  }

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
    const watch = new MutationObserver(() => { watch.disconnect(); groupButtons(content); watch.observe(content, { childList: true, subtree: true }); });
    groupButtons(content);
    watch.observe(content, { childList: true, subtree: true });
    setTimeout(() => revealFound(content), 150);    // a setting that was searched for is scrolled to and highlighted
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
