// Search: one box (press / or Ctrl+K) that finds pages, settings and devices.
// Settings are listed here by hand: a settings page is only built when it is opened, so it cannot be searched before that.
import { get } from "./api.js";
import { h, clear, isAdmin, shortName } from "./util.js";

const PAGES = [
  ["Dashboard", "#/dashboard", "overview home summary problems attention"],
  ["Map", "#/map", "network map topology layout"],
  ["Devices", "#/devices", "list hosts computers inventory table"],
  ["Hierarchy", "#/hierarchy", "tree parents switches uplinks"],
  ["DNS", "#/dns", "register names hostnames dns server records technitium zone"],
  ["Network health", "#/network-health", "ipv4 ipv6 gateway dns dhcp duplicate ip address subnet full range internet working check diagnose ipv6 addresses prefix subnet router advertisement slaac routable global link-local dhcpv6 working check"],
  ["Vulnerabilities", "#/vulnerabilities", "cve security scan greenbone openvas tenable nessus rapid7 insightvm exposed exploited patch critical findings vulnerability scanner"],
  ["Insights", "#/insights", "ask question incidents anomalies unusual predictions llm", true],
  ["Remediation", "#/remediation", "automatic fix rules restart wake webhook", true],
  ["Smart home", "#/smarthome", "home assistant battery devices"],
  ["Speed tests", "#/speedtest", "bandwidth internet iperf throughput latency"],
  ["Remote access", "#/remote", "rdp vnc ssh telnet console connect", true],
  ["Uptime", "#/uptime", "availability online offline history"],
  ["Health", "#/health", "cpu memory disk temperature limits snmp ssh winrm monitoring"],
  ["Remote sites", "#/remote-sites", "probes branch offices central sites"],
  ["Services", "#/services", "service checks http tcp dns certificate process"],
  ["Backups", "#/backups", "backup proxmox backup server pbs guests vm snapshot datastore failed late"],
  ["Statistics", "#/stats", "charts numbers vendors types"],
  ["Reports", "#/reports", "weekly monthly availability csv"],
  ["What changed", "#/changes", "timeline new devices alerts history last night changes"],
  ["Scans & events", "#/scans", "events log scan history"],
  ["Setup guide", "#/wizard", "wizard getting started tour"],
  ["Settings", "#/settings", "preferences configuration options admin", true],
];

// [title, settings page, extra words, text to scroll to on that page]
const SETTINGS = [
  ["Scan ranges", "ranges", "networks subnets cidr which addresses to scan", ""],
  ["Scan performance", "nmap", "nmap speed timing quick deep ports top ports", ""],
  ["Service version detection", "nmap", "nmap versions banners", "Service version detection"],
  ["OS detection", "nmap", "operating system fingerprint nmap", "OS detection"],
  ["Traceroute", "nmap", "hops path nmap", "Traceroute"],
  ["Look again before marking a device offline", "nmap", "second look flapping false offline retries", "Look again before marking"],
  ["Skip reverse DNS lookups", "nmap", "names resolve speed", "Skip reverse DNS"],
  ["Manufacturer database", "nmap", "vendor oui mac ieee registry", "Manufacturer database"],
  ["Passive listening", "nmap", "mdns ssdp announcements listen devices announce", "Passive listening"],
  ["Scan schedule", "schedule", "quick scan every minutes deep scan hours interval frequency", ""],
  ["Map layout", "map", "layout containers guests domain suffix hide names", ""],
  ["Domain suffix to hide", "map", "dns names local lan shorten", "Domain suffix"],
  ["Groups", "groups", "colours labels tags organise", ""],
  ["Network checks", "netchecks", "dhcp servers rogue gateway", ""],
  ["DHCP servers", "netchecks", "rogue dhcp look for", "DHCP servers"],
  ["Ignored devices", "ignored", "hide exclude ignore list", ""],
  ["IPv6 discovery", "ipv6", "neighbours addresses scan ipv6 find", ""],
  ["Single sign-on", "sso", "sso oidc openid login azure entra google keycloak authentik", ""],
  ["Escalation", "escalation", "on call oncall escalate unacknowledged alerts rota", ""],
  ["Device messages: SNMP traps and syslog", "inbound", "snmp trap syslog receive listen link down ups battery messages devices send port 162 514 1162 1514", ""],
  ["On-call schedule", "oncall", "on call oncall rota shifts who is notified override holiday swap fallback week rotation schedule", ""],
  ["Log forwarding", "siem", "syslog siem graylog splunk wazuh elastic rsyslog audit events forward logs", ""],
  ["AI", "engineer", "ai llm language model digital engineer assistant claude chatgpt token guide ollama openai openrouter free insights model anonymise", ""],
  ["Licence", "licence", "license key edition paid activate community trial", ""],
  ["Setup guide", "wizard", "wizard getting started tour first run", ""],
  ["Report to a central Netlens", "central", "probe remote site central accept configuration push", ""],
  ["Users & tokens", "users", "accounts passwords roles viewer administrator api token", ""],
  ["Add a user", "users", "new account password role", "Add a user"],
  ["Web terminal", "terminal", "ssh telnet console enable disable", ""],
  ["Alert channels", "channels", "notifications email smtp telegram ntfy pushover webhook discord slack gotify", ""],
  ["Forward events to n8n, OpenClaw or another tool", "channels", "n8n openclaw webhook automation workflow forward send events node-red zapier make home assistant json one message per event bearer token api key header", "Add channel"],
  ["Only send some alerts (severity, devices, groups)", "channels", "filter filters severity critical warning devices groups narrow channel only when", "Add channel"],
  ["Quiet hours", "channels", "night silence do not disturb notifications schedule", "Quiet hours"],
  ["Group alerts by cause", "channels", "root cause noise bundle", "Group alerts by cause"],
  ["Tell me when", "channels", "events which alerts notifications kinds", "Add channel"],
  ["Maintenance windows", "maintenance", "planned downtime reboot silence hold back schedule recurring", ""],
  ["Backup and restore", "backup", "export import restore copy database", ""],
  ["Scheduled backups", "backup", "automatic backup keep retention", "Scheduled backups"],
  ["Encryption key", "backup", "vault passwords key secrets", "Encryption key"],
  ["Export", "export", "csv json devices download", ""],
  ["Share links", "shares", "public read only link status page", ""],
  ["Audit log", "audit", "who changed what history security csv", ""],
  ["About and version", "about", "update changelog release notes version", ""],
  ["Updates", "about", "new version check docker pull", "Update"],
  ["Account", "session", "password change my profile start page preferences", ""],
  ["Start page", "session", "home page opens on landing default", "Start page"],
  ["Plugin manager", "plugins", "plugins install integrations proxmox unifi hyper-v synology npm turn on off running", ""],
  ["Plugin store", "plugin-browse", "plugins browse index catalogue download install new", ""],
];

let plugins = null;
let devices = null;
let devicesAt = 0;

async function loadDevices() {
  if (devices && Date.now() - devicesAt < 60000) return devices;
  try {
    const rows = await get("/api/devices");
    devices = (Array.isArray(rows) ? rows : rows.devices || []).map((d) => ({
      id: d.id, name: d.name || d.hostname || d.primary_ip || "", ip: d.primary_ip || "", mac: d.mac || "", vendor: d.vendor || "", type: d.type || "",
    }));
    devicesAt = Date.now();
  } catch (e) {
    devices = devices || [];
  }
  return devices;
}

async function loadPlugins() {
  if (plugins) return plugins;
  try { plugins = ((await get("/api/plugins")).plugins || []).map((p) => ({ id: p.id, name: p.name || p.id })); } catch (e) { plugins = []; }
  return plugins;
}

function score(query, text, extra = "") {
  const t = text.toLowerCase();
  const words = query.split(/\s+/).filter(Boolean);
  let total = 0;
  for (const w of words) {
    if (t.startsWith(w)) total += 6;
    else if (t.includes(` ${w}`)) total += 4;
    else if (t.includes(w)) total += 3;
    else if (extra.toLowerCase().includes(w)) total += 1;
    else return 0;       // every word has to match something
  }
  return total;
}

function search(query, devs, plugs = []) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const out = [];
  for (const [title, href, words, adminOnly] of PAGES) {
    if (adminOnly && !isAdmin()) continue;
    const s = score(q, title, words);
    if (s) out.push({ group: "Pages", title, hint: "", href, s: s + 1 });
  }
  for (const [title, section, words, find] of SETTINGS) {
    if (!isAdmin() && section !== "session") continue;
    const s = score(q, title, words);
    if (s) out.push({ group: "Settings", title, hint: `Settings · ${sectionName(section)}`, href: `#/settings/${section}`, find, s });
  }
  if (isAdmin()) {
    for (const p of plugs) {
      const s = score(q, p.name, `${p.id} plugin integration`);
      if (s) out.push({ group: "Settings", title: p.name, hint: "Settings · Plugin", href: `#/settings/plugin-${p.id}`, s });
    }
  }
  for (const d of devs) {
    const s = score(q, `${d.name} ${d.ip}`, `${d.mac} ${d.vendor} ${d.type}`);
    if (s) out.push({ group: "Devices", title: shortName(d.name) || d.ip, hint: [d.ip, d.vendor].filter(Boolean).join(" · "), href: `#/device/${d.id}`, s });
  }
  const order = { Pages: 0, Settings: 1, Devices: 2, "Remote sites": 3 };
  out.sort((a, b) => order[a.group] - order[b.group] || b.s - a.s || a.title.localeCompare(b.title));
  return out.slice(0, 40);
}

function sectionName(key) {
  const names = { ranges: "Scan ranges", nmap: "Scan performance", schedule: "Scan schedule", map: "Map", groups: "Groups", netchecks: "Network checks", dns: "DNS registration",
    ignored: "Ignored devices", ipv6: "IPv6", sso: "Single sign-on", escalation: "Escalation", oncall: "On-call schedule", siem: "Log forwarding", inbound: "Device messages", engineer: "AI", licence: "Licence", wizard: "Setup guide", central: "Central Netlens", users: "Users & tokens", terminal: "Web terminal", channels: "Alert channels & quiet hours", maintenance: "Maintenance windows",
    backup: "Backup & restore", export: "Export", shares: "Share links", audit: "Audit log", about: "About", session: "Account", plugins: "Plugin manager", "plugin-browse": "Plugin store" };
  return names[key] || key;
}

// Called by the settings page after it has built a section: scroll to the setting that was searched for.
export function revealFound(root) {
  let wanted = "";
  try { wanted = sessionStorage.getItem("netlens.find") || ""; sessionStorage.removeItem("netlens.find"); } catch (e) { /* no storage */ }
  if (!wanted || !root) return;
  const needle = wanted.toLowerCase();
  const target = [...root.querySelectorAll("h1, h2, h3, h4, label, legend, th, .kv-key, button")].find((el) => el.textContent.toLowerCase().includes(needle));
  if (!target) return;
  target.scrollIntoView({ block: "center", behavior: "smooth" });
  target.classList.add("search-found");
  setTimeout(() => target.classList.remove("search-found"), 2500);
}

let dialog = null;

function close() {
  if (dialog) { dialog.close(); dialog.remove(); dialog = null; }
}

export async function openSearch(initial = "") {
  if (dialog) { dialog.querySelector("input").focus(); return; }
  const input = h("input", { type: "search", class: "search-input", placeholder: "Search pages, settings and devices", "aria-label": "Search", autocomplete: "off", spellcheck: "false" });
  const list = h("div", { class: "search-results", role: "listbox" });
  const foot = h("div", { class: "search-foot hint" }, "↑ ↓ to choose, Enter to open, Esc to close");
  dialog = h("dialog", { class: "search-dialog", "aria-label": "Search" }, input, list, foot);
  document.body.append(dialog);
  let results = [];
  let index = 0;
  let devs = [];
  let plugs = [];

  const go = (r) => {
    if (!r) return;
    try { if (r.find) sessionStorage.setItem("netlens.find", r.find); else sessionStorage.removeItem("netlens.find"); } catch (e) { /* no storage */ }
    close();
    if (location.hash === r.href) window.dispatchEvent(new HashChangeEvent("hashchange"));
    else location.hash = r.href;
  };
  const draw = () => {
    clear(list);
    if (!input.value.trim()) { list.append(h("p", { class: "hint search-empty" }, "Type a name: “n8n”, “backup”, “smtp”, “winrm”, a device name or an address.")); return; }
    if (!results.length) { list.append(h("p", { class: "hint search-empty" }, "Nothing found.")); return; }
    let group = "";
    results.forEach((r, i) => {
      if (r.group !== group) { group = r.group; list.append(h("div", { class: "search-group" }, group)); }
      list.append(h("button", { type: "button", class: `search-item${i === index ? " active" : ""}`, role: "option", "aria-selected": String(i === index),
        onclick: () => go(r), onmousemove: () => { if (index !== i) { index = i; draw(); } } },
      h("span", { class: "search-title" }, r.title), r.hint ? h("span", { class: "search-hint" }, r.hint) : null));
    });
    const active = list.querySelector(".search-item.active");
    if (active) active.scrollIntoView({ block: "nearest" });
  };
  let remote = [];
  let remoteFor = "";
  const update = () => {
    results = [...search(input.value, devs, plugs), ...remote.map((r) => ({ group: "Remote sites", title: shortName(r.name) || r.ip, hint: [r.site, r.ip, r.vendor].filter(Boolean).join(" · "), href: `#/remote-sites?id=${r.probe_id}`, s: 1 }))];
    index = 0; draw();
    const q = input.value.trim();
    if (q.length >= 2 && q !== remoteFor && isAdmin()) {
      remoteFor = q;
      get(`/api/probes-search?q=${encodeURIComponent(q)}`).then((rows) => { if (dialog && input.value.trim() === q) { remote = rows; update(); } }).catch(() => {});
    } else if (q.length < 2) { remote = []; remoteFor = ""; }
  };
  input.addEventListener("input", update);
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); index = Math.min(results.length - 1, index + 1); draw(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); index = Math.max(0, index - 1); draw(); }
    else if (e.key === "Enter") { e.preventDefault(); go(results[index]); }
  });
  dialog.addEventListener("close", () => { if (dialog) { dialog.remove(); dialog = null; } });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) close(); });
  dialog.showModal();
  input.value = initial;
  input.focus();
  draw();
  [devs, plugs] = await Promise.all([loadDevices(), loadPlugins()]);
  if (dialog) update();
}

export function initSearch() {
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || "") || (e.target && e.target.isContentEditable);
    const inTerminal = e.target && e.target.closest && e.target.closest(".terminal-wrap, .xterm");
    if (inTerminal) return;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openSearch(); }
    else if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); openSearch(); }
  });
  const btn = document.getElementById("search-btn");
  if (btn) btn.addEventListener("click", () => openSearch());
}
