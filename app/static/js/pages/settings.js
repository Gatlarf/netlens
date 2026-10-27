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
import { levelShows, lowestLevel } from "../levels.js";

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

// The pages of Settings, grouped in the side menu. A page holds one or more tabs; every tab is its own address ("#/settings/<key>"),
// so all the old addresses still work and open the page they belong to, on the right tab. A builder returns a card (or a promise of one).
// "level" is the lowest menu level that lists the tab (basic < standard < advanced). The Integrations group is built from the plugins
// that are installed: a plugin's own page is a hidden tab of the Plugins page, opened from the Installed list.
function page(id, label, tabs) {
  const p = { id, label, tabs };
  for (const t of tabs) t.page = p;
  return p;
}
const tab = (key, label, build, level = "basic") => ({ key, label, build, level });

const STATIC_GROUPS = [
  {
    title: "Scanning",
    pages: [
      page("ranges", "Scanning", [
        tab("ranges", "Scan ranges", buildRangesCard),
        tab("schedule", "Schedule", buildScheduleCard, "standard"),
        tab("nmap", "Performance", buildScanPage, "advanced"),
        tab("ipv6", "IPv6", buildIpv6Card, "advanced"),
      ]),
      page("netchecks", "Checks & targets", [
        tab("netchecks", "Network checks", buildNetchecksCard, "standard"),
        tab("reliability", "Reliability target", buildReliabilityCard, "standard"),
        tab("cvecheck", "Version check (CVE)", () => buildCveCheckCard(), "advanced"),
      ]),
    ],
  },
  {
    title: "Devices & display",
    pages: [
      page("interface", "Appearance", [
        tab("interface", "Interface", buildInterfaceCard),
        tab("map", "Map", buildMapCard),
      ]),
      page("groups", "Devices", [
        tab("groups", "Device groups", buildGroupsCard, "standard"),
        tab("ignored", "Ignored devices", buildIgnoredCard, "standard"),
        tab("dns", "DNS registration", () => buildDnsCard("settings"), "advanced"),
      ]),
    ],
  },
  {
    title: "Notifications",
    pages: [
      page("channels", "Alerts", [
        tab("channels", "Channels & quiet hours", buildChannelsCard),
        tab("maintenance", "Maintenance windows", buildMaintenanceCard, "standard"),
        tab("escalation", "Escalation", buildEscalationCard, "advanced"),
        tab("oncall", "On-call schedule", buildOncallCard, "advanced"),
      ]),
      page("inbound", "Syslog, traps & forwarding", [
        tab("inbound", "Device messages (in)", buildInboundCard, "advanced"),
        tab("siem", "Log forwarding (out)", buildSiemCard, "advanced"),
      ]),
    ],
  },
  "integrations",
  {
    title: "Data",
    pages: [
      page("backup", "Backup & export", [
        tab("backup", "Backup & restore", buildBackupCard),
        tab("export", "Export", buildExportCard, "standard"),
      ]),
      page("database", "Database & statistics", [
        tab("database", "Database", buildDatabaseCard, "advanced"),
        tab("usage", "Traffic statistics", buildUsageCard, "advanced"),
      ]),
    ],
  },
  {
    title: "Access & system",
    pages: [
      page("users", "Users & access", [
        tab("users", "Users & tokens", buildUsersCard),
        tab("shares", "Share links", buildSharesCard, "standard"),
        tab("sso", "Single sign-on", buildSsoCard, "advanced"),
        tab("terminal", "Web terminal", buildTerminalCard, "advanced"),
      ]),
      page("audit", "Audit log", [tab("audit", "Audit log", buildAuditCard, "advanced")]),
      page("about", "About & licence", [
        tab("about", "About", buildAboutCard),
        tab("licence", "Licence", buildLicenceCard),
        { ...tab("wizard", "Setup guide", buildWizardCard), hidden: true },       // opened from About, not listed
      ]),
      page("session", "Account", [tab("session", "Account", buildAccountCard)]),
    ],
  },
];

const DEFAULT_PAGE = "ranges";
const VIEWER_PAGE = "session";
// the connectors were plugins-to-be before: keep their old addresses working
const ALIASES = { proxmox: "plugin-proxmox", asus: "plugin-asus", notifications: "channels", assistant: "agents", mcp: "agents" };  // e-mail is a channel now

function integrationsGroup(plugins, updates = 0) {
  const tabs = [
    tab("plugins", "Installed", buildPluginsCard),
    tab("plugin-browse", updates ? `Store (${updates} update${updates === 1 ? "" : "s"})` : "Store", buildBrowseCard),
    // a plugin's own page is not listed: open it from the Installed list (its name is a link)
    ...plugins.map((p) => ({ ...tab(`plugin-${p.id}`, p.name, () => buildPluginCard(p.id)), hidden: true })),
    { ...tab("plugin-guide", "Plugin guide", buildPluginGuideCard), hidden: true },
  ];
  return {
    title: "Integrations",
    pages: [
      page("plugins", updates ? `Plugins (${updates})` : "Plugins", tabs),
      page("engineer", "AI", [
        tab("engineer", "Language model", buildAiModelCard, "standard"),
        tab("agents", "Agents (assistant, MCP)", buildAiAgentsCard, "advanced"),
      ]),
      page("hosts", "Hosts & credentials", [
        tab("hosts", "Hosts", buildHostsSetupCard, "standard"),
        tab("credentials", "Credentials", buildCredentialsCard, "standard"),
        tab("hostprobes", "Host probes", buildHostProbeCard, "advanced"),
      ]),
      page("central", "Report to a central Netlens", [tab("central", "Central Netlens", buildCentralCard, "advanced")]),
    ],
  };
}

async function loadGroups() {
  if (!isAdmin()) return [{ title: "Account", pages: [page("session", "Account", [tab("session", "Account", buildAccountCard)])] }];
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

const listedTabs = (p) => p.tabs.filter((t) => !t.hidden);
const pageLevel = (p) => lowestLevel(listedTabs(p).map((t) => t.level));
// the menu level decides what is listed; the page being looked at always is
const tabsShown = (p, activeKey) => p.tabs.filter((t) => t.key === activeKey || (!t.hidden && levelShows(t.level)));

function fillNav(nav, groups, active) {
  clear(nav);
  for (const group of groups) {
    const pages = group.pages.filter((p) => p === active.page || levelShows(pageLevel(p)));
    if (!pages.length) continue;
    nav.appendChild(h("div", { class: "nav-group" }, group.title));
    for (const p of pages) {
      const first = tabsShown(p, active.key).find((t) => t.page === p) || p.tabs[0];
      const link = h("a", { href: `#/settings/${first.key}`, "data-section": first.key }, p.label);
      if (p === active.page) {
        link.classList.add("active");
        link.setAttribute("aria-current", "page");
      }
      nav.appendChild(link);
    }
  }
}

function fillTabs(bar, active) {
  clear(bar);
  const tabs = tabsShown(active.page, active.key);
  bar.hidden = tabs.length < 2;
  for (const t of tabs) {
    const a = h("a", { class: `tab${t.key === active.key ? " active" : ""}`, href: `#/settings/${t.key}`, role: "tab" }, t.label);
    if (t.key === active.key) a.setAttribute("aria-selected", "true");
    bar.appendChild(a);
  }
}

export async function render(container, params) {
  clear(container);
  let groups = await loadGroups();
  const items = () => groups.flatMap((g) => g.pages.flatMap((p) => p.tabs));
  const requested = params && (ALIASES[params.section] || params.section);
  const item = items().find((i) => i.key === requested) || items().find((i) => i.key === DEFAULT_PAGE) || items().find((i) => i.key === VIEWER_PAGE);
  if (params && params.section && item.key !== params.section) {
    // an address that does not exist (or an old one): show the right page under its own address, without a new history entry
    history.replaceState(null, "", `#/settings/${item.key}`);
  }

  const nav = h("nav", { class: "settings-nav", "aria-label": "Settings pages" });
  fillNav(nav, groups, item);
  const tabs = h("div", { class: "tabs settings-tabs", role: "tablist" });
  fillTabs(tabs, item);
  const body = h("div", { class: "settings-body" });
  const content = h("div", { class: "settings-content", id: `sec-${item.key}` }, tabs, body);
  // narrow screens: the page list folds into one button that names the current page
  const toggle = h("button", { type: "button", class: "btn settings-nav-toggle", "aria-expanded": "false", id: "settings-nav-toggle" },
    h("span", {}, `Settings: ${item.page.label}${item.page.tabs.length > 1 ? ` › ${item.label}` : ""}`), h("span", { class: "caret" }, "▾"));
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
    const again = items().find((i) => i.key === item.key) || item;
    fillNav(nav, groups, again);
    fillTabs(tabs, again);
  };
  document.addEventListener("netlens:plugins-changed", onPluginsChanged);

  body.appendChild(h("div", { class: "card" }, h("p", { class: "hint" }, "Loading...")));
  try {
    const card = await item.build();
    if (destroyed) return;
    clear(body);
    body.appendChild(card);
    const watch = new MutationObserver(() => { watch.disconnect(); groupButtons(content); watch.observe(content, { childList: true, subtree: true }); });
    groupButtons(content);
    watch.observe(content, { childList: true, subtree: true });
    setTimeout(() => revealFound(content), 150);    // a setting that was searched for is scrolled to and highlighted
  } catch (err) {
    if (destroyed) return;
    clear(body);
    body.appendChild(h("div", { class: "card" }, h("h2", {}, item.label), h("p", { class: "error" }, err.message || "Failed to load")));
  }

  return () => {
    destroyed = true;
    document.removeEventListener("netlens:plugins-changed", onPluginsChanged);
  };
}
