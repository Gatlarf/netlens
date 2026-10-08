import { get, post, put } from "../api.js";
import { h, clear, toast } from "../util.js";
import { buildScanOptionsCard } from "../cards/scan_options.js";
import { buildGeneralCard } from "../cards/general.js";
import { buildNotificationsCard } from "../cards/notifications.js";
import { buildProxmoxCard } from "../cards/proxmox.js";
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

// Sections of the page, in order. The side menu links to them and "#/settings/<key>" deep-links to one.
const SECTIONS = [
  { key: "ranges", label: "Scan ranges" },
  { key: "nmap", label: "Scan performance" },
  { key: "schedule", label: "Schedule & terminal" },
  { key: "notifications", label: "E-mail notifications" },
  { key: "proxmox", label: "Proxmox connector" },
  { key: "ignored", label: "Ignored devices" },
  { key: "backup", label: "Backup & restore" },
  { key: "about", label: "About" },
  { key: "export", label: "Export" },
  { key: "session", label: "Session" },
];

export async function render(container, params) {
  clear(container);

  // ---- layout: side menu + sections
  const nav = h("nav", { class: "settings-nav", "aria-label": "Settings sections" });
  const content = h("div", { class: "settings-content" });
  container.appendChild(h("div", { class: "settings-layout" }, nav, content));

  const sections = {};
  const links = {};
  for (const { key, label } of SECTIONS) {
    sections[key] = h("section", { class: "settings-section", id: `sec-${key}` });
    content.appendChild(sections[key]);
    links[key] = h("a", {
      href: `#/settings/${key}`,
      "data-section": key,
      onclick: (e) => {
        e.preventDefault();
        lockUntil = Date.now() + 600; // keep the clicked entry highlighted while the page scrolls there
        sections[key].scrollIntoView({ behavior: "smooth", block: "start" });
        setActive(key);
      },
    }, label);
    nav.appendChild(links[key]);
  }

  let active = null;
  let lockUntil = 0;
  function setActive(key) {
    if (key === active) return;
    active = key;
    for (const [k, link] of Object.entries(links)) {
      link.classList.toggle("active", k === key);
      if (k === key) link.setAttribute("aria-current", "true");
      else link.removeAttribute("aria-current");
    }
  }

  // Highlight the section being read: the last one whose top has reached the upper part of the screen.
  let frame = null;
  function updateActive() {
    frame = null;
    if (Date.now() < lockUntil) {
      lockUntil = Date.now() + 150; // still scrolling to the clicked section: let it settle
      return;
    }
    const bottomReached = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2;
    // a section counts as "being read" once its top is a little below the sticky top bar
    const barHeight = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--topbar-h"), 10) || 58;
    let current = SECTIONS[0].key;
    for (const { key } of SECTIONS) {
      if (sections[key].getBoundingClientRect().top <= barHeight + 80) current = key;
    }
    setActive(bottomReached ? SECTIONS[SECTIONS.length - 1].key : current);
  }
  function onScroll() {
    if (frame === null) frame = requestAnimationFrame(updateActive);
  }
  // the user scrolling by hand takes over from a menu click immediately
  const unlock = () => { lockUntil = 0; };
  window.addEventListener("scroll", onScroll, { passive: true });
  for (const type of ["wheel", "touchstart", "keydown"]) window.addEventListener(type, unlock, { passive: true });
  setActive(params && sections[params.section] ? params.section : SECTIONS[0].key);

  // ---- cards
  const rangesCard = h("div", { class: "card" });
  sections.ranges.appendChild(rangesCard);

  const configCard = h("div", { class: "card" });
  configCard.appendChild(h("h2", {}, "About"));
  sections.about.appendChild(configCard);

  const exportCard = h("div", { class: "card" });
  exportCard.appendChild(h("h2", {}, "Export"));
  exportCard.appendChild(downloadLink("/api/export/devices.csv", "Devices CSV"));
  exportCard.appendChild(downloadLink("/api/export/devices.json", "Devices JSON"));
  sections.export.appendChild(exportCard);

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
  sections.session.appendChild(sessionCard);

  sections.backup.appendChild(buildBackupCard());
  for (const [key, build] of [
    ["nmap", buildScanOptionsCard],
    ["schedule", buildGeneralCard],
    ["notifications", buildNotificationsCard],
    ["proxmox", buildProxmoxCard],
    ["ignored", buildIgnoredCard],
  ]) {
    build().then((card) => {
      sections[key].appendChild(card);
    }).catch((err) => {
      sections[key].appendChild(h("div", { class: "card" }, h("p", { class: "error" }, err.message || "Failed to load")));
    });
  }

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
    sections.about.appendChild(errCard);
  }

  // A deep link ("#/settings/proxmox", or the header's Scan settings button -> "#/settings/nmap")
  // jumps to its section. Done last so the cards above have their final height.
  if (params && sections[params.section]) {
    sections[params.section].scrollIntoView({ block: "start" });
  }

  // the router calls this when the user leaves the page
  return () => {
    window.removeEventListener("scroll", onScroll);
    for (const type of ["wheel", "touchstart", "keydown"]) window.removeEventListener(type, unlock);
    if (frame !== null) cancelAnimationFrame(frame);
  };
}
