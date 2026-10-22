import { get, post, patch, put, del } from "../api.js";
import { h, clear, toast, statusDot, shortName, timeAgo, isAdmin, fmtTime } from "../util.js";
import { pageHead, emptyState, previewHtml } from "../ui.js";
import { buildPerformanceCard } from "../cards/performance.js";
import { snoozeMenu, wakeButton, untilText } from "../snooze.js";
import { enterSite } from "../site.js";

const REFRESH_MS = 30000;
const STATE_TEXT = { connected: "Reporting", silent: "Not heard from", waiting: "Waiting for the first report" };
const STATE_TONE = { connected: "ok", silent: "bad", waiting: "warn" };

function queryId() {
  const m = /[?&]id=(\d+)/.exec(location.hash);
  return m ? Number(m[1]) : null;
}

function tile(title, value, sub, kind) {
  return h("section", { class: `dcard ${kind ? `tone-${kind}` : ""}` }, h("h2", { class: "d-title" }, title),
    h("div", { class: "d-body" }, h("div", { class: "d-value" }, value), h("div", { class: "d-sub" }, sub)));
}

function copyBox(text) {
  const pre = h("pre", { class: "remote-code" }, text);
  const btn = h("button", { class: "btn", type: "button" }, "Copy");
  btn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); btn.textContent = "Copied"; } catch (err) { /* select it by hand */ }
  });
  return h("div", { class: "remote-code-wrap" }, pre, btn);
}

function setupSteps(name, token) {
  return h("div", { class: "card rs-setup" },
    h("h2", {}, `Connect “${name}”`),
    h("p", { class: "hint" }, "Shown once. Keep the token secret: it lets a Netlens report as this site. You can make a new one at any time."),
    h("ol", {},
      h("li", {}, "Install Netlens at the other location (the same way as here) and finish its first-run setup. Let it scan its own network."),
      h("li", {}, "On that Netlens open ", h("strong", {}, "Settings → Report to a central Netlens"), " and enter:"),
      h("li", {}, "Press ", h("strong", {}, "Send a report now"), ". This page then fills with that location's devices and checks.")),
    h("p", {}, "Address of this Netlens (it must be reachable from the other location, over https:// or through a VPN):"),
    copyBox(location.origin),
    h("p", {}, "Token:"), copyBox(token),
    h("p", { class: "hint" }, "Nothing at the other location needs to be reachable from here: it always connects out. If this Netlens sits behind a reverse proxy, its public https address is the one to enter."));
}


const ALERT_MODES = [["auto", "Always-on devices when the site marks any, otherwise all devices"], ["core", "Only always-on devices"], ["all", "All devices"], ["none", "No device alerts"]];
const KEEP_CHOICES = [["", "The general retention (Settings → Database)"], ["30", "30 days"], ["90", "90 days"], ["180", "180 days"], ["365", "1 year"], ["730", "2 years"]];

// What this site alerts about and how long its history is kept here.
function buildSiteSettingsCard(probe, done) {
  const mode = h("select", { "aria-label": "Offline alerts for" }, ALERT_MODES.map(([v, t]) => h("option", { value: v }, t)));
  mode.value = probe.alert_mode || "auto";
  const keep = h("select", { "aria-label": "Keep the history for" }, KEEP_CHOICES.map(([v, t]) => h("option", { value: v }, t)));
  if (probe.keep_days && !KEEP_CHOICES.some(([v]) => v === String(probe.keep_days))) keep.appendChild(h("option", { value: String(probe.keep_days) }, `${probe.keep_days} days`));
  keep.value = probe.keep_days ? String(probe.keep_days) : "";
  const save = h("button", { class: "btn primary", type: "button" }, "Save");
  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      await patch(`/api/probes/${probe.id}`, { alert_mode: mode.value, keep_days: keep.value ? Number(keep.value) : null });
      toast("Saved", "success");
      done();
    } catch (err) {
      toast(err.message || "Could not save", "error");
      save.disabled = false;
    }
  });
  return h("details", { class: "card admin-only managed-fold" }, h("summary", {}, h("strong", {}, "Alerts and retention of this site"),
    h("span", { class: "hint" }, ` · ${(ALERT_MODES.find(([v]) => v === (probe.alert_mode || "auto")) || ALERT_MODES[0])[1].toLowerCase()}${probe.muted && probe.muted.length ? ` · ${probe.muted.length} muted` : ""}${probe.keep_days ? ` · history ${probe.keep_days} days` : ""}`)),
    h("div", { class: "edit-form" },
      h("div", { class: "field" }, h("label", {}, "Offline and back-online alerts for"), mode,
        h("p", { class: "hint" }, "Applies to “went offline” and “back online” of devices. Service checks, health problems and a silent site are always announced. You can also mute single devices in the device list below.")),
      h("div", { class: "field" }, h("label", {}, "Keep the history of this site for"), keep,
        h("p", { class: "hint" }, "Graph points and alerts older than this are removed by the weekly upkeep (or Settings → Database → Remove old data). The monthly availability can only go back as far as the history is kept.")),
      h("div", { class: "form-actions" }, save)));
}

const pct = (v) => (v === null || v === undefined ? "–" : `${v}%`.replace(".0%", "%"));
const monthName = (m) => new Date(`${m}-01T12:00:00Z`).toLocaleDateString(undefined, { month: "long", year: "numeric", timeZone: "UTC" });

// The monthly availability of one site: the same figures as Reports → Monthly availability, from the history the site reported.
async function buildAvailabilityCard(probe) {
  const card = h("div", { class: "card" }), body = h("div", {});
  let month = "", scope = "all";
  async function load() {
    clear(body);
    let r;
    try {
      r = await get(`/api/probes/${probe.id}/availability?scope=${scope}${month ? `&month=${month}` : ""}`);
    } catch (err) {
      body.appendChild(h("p", { class: "error" }, err.message || "Could not load the availability"));
      return;
    }
    month = r.month;
    const sum = r.summary;
    body.appendChild(h("p", {}, [scope === "core" ? null : `All devices: ${pct(sum.devices_availability)}`, sum.core_devices && scope !== "core" ? `Always-on devices: ${pct(sum.core_availability)}` : scope === "core" ? `Always-on devices: ${pct(sum.core_availability)}` : null,
      sum.services ? `Checks: ${pct(sum.services_availability)}` : null, `${sum.with_outages} with an outage`].filter(Boolean).join(" · ")));
    if (sum.silent_seconds >= 60) body.appendChild(h("p", { class: "hint" }, `The site did not report for ${sum.silent_text} this month. That time is not counted in the figures (nothing was measured), but nothing at that location was being watched.`));
    const rows = [...r.devices.map((d) => ({ ...d, kind: "Device" })), ...r.services.map((x) => ({ ...x, kind: "Check" }))].sort((a, b) => a.availability - b.availability || a.name.localeCompare(b.name));
    if (!rows.length) { body.appendChild(h("p", { class: "hint" }, "No measurements for this month yet.")); return; }
    const table = h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["", "Name", "Availability", "Outages", "Longest", "Time down"].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows.map((d) => h("tr", {}, h("td", { class: "hint" }, d.kind), h("td", {}, shortName(d.name), d.always_on ? h("span", { class: "hint" }, " (always on)") : null),
        h("td", { class: d.availability < 99 ? "d-bad" : d.availability < 100 ? "d-warn" : "" }, pct(d.availability), d.ongoing ? " (down now)" : ""), h("td", {}, String(d.outages || "")), h("td", {}, d.outages ? d.longest : ""), h("td", {}, d.outages ? d.down_text : "")))));
    body.appendChild(h("div", { class: "table-wrap" }, table));
    body.appendChild(h("p", {}, h("a", { class: "btn", href: `/api/probes/${probe.id}/availability.csv?month=${month}&scope=${scope}`, download: "" }, "Download as CSV")));
    body.appendChild(h("p", { class: "hint" }, "Measured at the resolution of the stored history: every 5 minutes for the last 90 days, hourly before that."));
  }
  const first = await get(`/api/probes/${probe.id}/availability`);
  month = first.month;
  const monthSel = h("select", { "aria-label": "Month" }, first.months.map((m) => h("option", { value: m }, monthName(m))));
  monthSel.value = month;
  monthSel.addEventListener("change", () => { month = monthSel.value; load(); });
  const scopeSel = h("select", { "aria-label": "Which devices" }, h("option", { value: "all" }, "All devices"), h("option", { value: "core" }, "Only always-on devices"));
  scopeSel.addEventListener("change", () => { scope = scopeSel.value; load(); });
  card.append(h("h2", {}, "Availability per month"), h("div", { class: "up-tools" }, monthSel, scopeSel), body);
  await load();
  return card;
}

let managedDirty = false;      // the "Managed from here" card has changes that are not saved: the page must not redraw itself
const KIND_TITLE = { http: "Website (HTTP/HTTPS)", tcp: "Port (TCP)", dns: "DNS lookup", cert: "Certificate" };

// "Managed from here": the checks and monitors this Netlens sets up at the remote site (the site must accept configuration).
async function buildManagedCard(probe, devices, state) {
  const card = h("div", { class: "card" });
  let cfg = await get(`/api/probes/${probe.id}/config`);
  let draft = JSON.parse(JSON.stringify(cfg));
  let dirty = false;
  let editSvc = null, editMon = null;          // index of the check or monitor being changed
  managedDirty = false;

  function status() {
    if (!state.accepts) return h("p", { class: "hint" }, "This site does not accept configuration yet. On the remote Netlens tick Settings → Report to a central Netlens → “Accept configuration and commands from the central Netlens”.");
    if (cfg.rev === state.site_rev) return h("p", { class: "hint" }, `The site has revision ${state.site_rev}: it is up to date.`);
    return h("p", { class: "hint" }, `Revision ${cfg.rev} is waiting; the site has ${state.site_rev}. It arrives with the next report.`);
  }

  function draw() {
    managedDirty = dirty;
    clear(card);
    card.appendChild(h("p", { class: "hint" }, "Service checks and health monitors that this Netlens sets up at the remote site. They run there, on its own network, and show on its devices. Logins are stored encrypted."));
    card.appendChild(status());
    card.appendChild(h("h3", {}, "Service checks"));
    if (!draft.services.length) card.appendChild(h("p", { class: "hint" }, "None."));
    for (const [i, s] of draft.services.entries()) {
      card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, s.name),
        h("span", {}, `${KIND_TITLE[s.kind] || s.kind} · ${s.host}${s.port ? `:${s.port}` : ""}${s.path || ""} · every ${s.interval_s || 60} s`, " ",
          h("button", { class: "btn", type: "button", onclick: () => { editSvc = i; draw(); } }, "Edit"), " ",
          h("button", { class: "btn", type: "button", onclick: () => { draft.services.splice(i, 1); editSvc = null; dirty = true; draw(); } }, "Remove"))));
    }
    const name = h("input", { type: "text", placeholder: "Name" }), kind = h("select", {}, Object.entries(KIND_TITLE).map(([k, t]) => h("option", { value: k }, t)));
    const host = h("input", { type: "text", placeholder: "Host or address" }), port = h("input", { type: "number", placeholder: "Port" }), path = h("input", { type: "text", placeholder: "Path or name (/ , example.com)" });
    const every = h("input", { type: "number", min: "10", max: "86400", placeholder: "Every (s)", title: "Seconds between checks", style: "width:6.5rem" });
    const was = editSvc !== null ? draft.services[editSvc] : null;
    if (was) { name.value = was.name; kind.value = was.kind; host.value = was.host; port.value = was.port || ""; path.value = was.path || ""; every.value = was.interval_s || 60; } else every.value = 60;
    const addService = h("button", { class: "btn", type: "button" }, was ? "Update the check" : "Add the check");
    addService.addEventListener("click", () => {
      if (!name.value.trim() || !host.value.trim()) { toast("Give the check a name and a host", "error"); return; }
      const item = { ...(was || {}), name: name.value.trim(), kind: kind.value, host: host.value.trim(), path: path.value.trim(), interval_s: Number(every.value) || 60, timeout_s: (was && was.timeout_s) || 5 };
      if (port.value) item.port = Number(port.value); else delete item.port;
      if (was) draft.services[editSvc] = item; else draft.services.push(item);
      editSvc = null;
      dirty = true;
      draw();
    });
    card.appendChild(h("div", { class: "rs-add" }, name, kind, host, port, path, every, addService, was ? h("button", { class: "btn", type: "button", onclick: () => { editSvc = null; draw(); } }, "Cancel") : null));

    card.appendChild(h("h3", {}, "Health monitors"));
    if (!draft.monitors.length) card.appendChild(h("p", { class: "hint" }, "None."));
    for (const [i, m] of draft.monitors.entries()) {
      const dev = devices.find((d) => d.key === m.device_key);
      card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, dev ? dev.name : m.device_key),
        h("span", {}, `${m.method.toUpperCase()}${m.version ? ` ${m.version}` : ""} · every ${m.interval_s} s${m.alerts === false ? " · no alerts" : ""}`, " ",
          h("button", { class: "btn", type: "button", onclick: () => { editMon = i; draw(); } }, "Edit"), " ",
          h("button", { class: "btn", type: "button", onclick: () => { draft.monitors.splice(i, 1); editMon = null; dirty = true; draw(); } }, "Remove"))));
    }
    if (editMon !== null) {
      const m = draft.monitors[editMon], dev = devices.find((d) => d.key === m.device_key);
      const every = h("input", { type: "number", min: "15", max: "86400", value: String(m.interval_s), style: "width:6.5rem", "aria-label": "Seconds between readings" });
      const alerts = h("input", { type: "checkbox" });
      alerts.checked = m.alerts !== false;
      const community = h("input", { type: "password", autocomplete: "off", placeholder: "New community (empty keeps the saved one)" });
      const pass = h("input", { type: "password", autocomplete: "new-password", placeholder: "New password (empty keeps the saved one)" });
      const apply = h("button", { class: "btn", type: "button" }, "Update the monitor");
      apply.addEventListener("click", () => {
        m.interval_s = Number(every.value) || 60;
        m.alerts = alerts.checked;
        if (m.method === "snmp" && community.value) m.community = community.value;
        if (m.method === "ssh" && pass.value) m.password = pass.value;
        editMon = null;
        dirty = true;
        draw();
      });
      card.appendChild(h("div", { class: "rs-add" }, h("strong", {}, `${dev ? dev.name : m.device_key}: `), every, h("label", {}, alerts, " alerts"), m.method === "snmp" ? community : pass, apply,
        h("button", { class: "btn", type: "button", onclick: () => { editMon = null; draw(); } }, "Cancel")));
    }
    const free = devices.filter((d) => !draft.monitors.some((m) => m.device_key === d.key));
    const device = h("select", {}, free.map((d) => h("option", { value: d.key }, `${d.name}${d.ip ? ` (${d.ip})` : ""}`)));
    const method = h("select", {}, h("option", { value: "snmp" }, "SNMP"), h("option", { value: "ssh" }, "SSH"));
    const community = h("input", { type: "password", autocomplete: "off", placeholder: "Community (SNMP)" });
    const user = h("input", { type: "text", autocomplete: "off", placeholder: "User (SSH)" }), pass = h("input", { type: "password", autocomplete: "new-password", placeholder: "Password (SSH)" });
    const addMonitor = h("button", { class: "btn", type: "button" }, "Add the monitor");
    addMonitor.addEventListener("click", () => {
      if (!device.value) return;
      const item = { device_key: device.value, method: method.value, interval_s: 60, alerts: true };
      if (method.value === "snmp") { item.version = "2c"; item.community = community.value || "public"; } else { item.username = user.value.trim(); item.password = pass.value; }
      draft.monitors.push(item);
      dirty = true;
      draw();
    });
    if (free.length) card.appendChild(h("div", { class: "rs-add" }, device, method, community, user, pass, addMonitor));
    const save = h("button", { class: "btn primary", type: "button", disabled: !dirty }, "Save and send to the site");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        cfg = await put(`/api/probes/${probe.id}/config`, { services: draft.services, monitors: draft.monitors });
        draft = JSON.parse(JSON.stringify(cfg));
        dirty = false;
        toast("Saved. The site picks it up with its next report.", "success");
        draw();
      } catch (err) {
        toast(err.message || "Could not save", "error");
        save.disabled = false;
      }
    });
    card.appendChild(h("div", { class: "form-actions" }, save));
  }
  draw();
  return card;
}

export async function render(container) {
  let disposed = false, timer = null;
  const top = h("div", {});
  const body = h("div", {});
  const form = h("div", {});
  container.append(top, form, body);

  async function showList() {
    const id = queryId();
    if (id) return showDetail(id);
    const probes = await get("/api/probes");
    if (disposed) return;
    clear(top); clear(body);
    const add = h("button", { class: "btn primary admin-only", type: "button" }, "Add a remote site");
    add.addEventListener("click", () => newSiteForm());
    top.append(pageHead("Remote sites", "Other locations that run Netlens and report here: devices, service checks, health and alerts of each in one place.", add));
    if (!probes.length) {
      body.appendChild(emptyState("No remote sites yet", "Run Netlens at the other location (a branch office, a second home, a customer), then add it here to get a token. It reports to this Netlens every minute and always connects out, so nothing at that location has to be reachable from the internet. Each site keeps working on its own if the connection drops, and this page tells you when a site stops reporting.", h("button", { class: "btn primary admin-only", type: "button", onclick: () => newSiteForm() }, "Add a remote site")));
      return;
    }
    const card = (p) => {
      if (p.locked) {
        return h("a", { class: "rs-card tone-off", href: `#/remote-sites?id=${p.id}` },
          h("div", { class: "rs-name" }, h("strong", {}, p.name), h("span", { class: "hl-badge warn" }, "Frozen")),
          h("div", { class: "hint" }, "Your licence takes in fewer remote sites. This one keeps its data but is not updated and raises no alerts."),
          isAdmin() ? h("div", { class: "hint" }, h("a", { href: "#/settings/licence" }, "Get more sites")) : null);
      }
      const tone = !p.enabled ? "off" : p.problems.critical || p.state === "silent" || p.devices.core_down ? "bad" : p.problems.count || p.services.down || p.state === "waiting" ? "warn" : "ok";
      return h("a", { class: `rs-card tone-${tone}`, href: `#/remote-sites?id=${p.id}` },
        h("div", { class: "rs-name" }, h("strong", {}, p.name), h("span", { class: `hl-badge ${STATE_TONE[p.state] === "ok" ? "" : STATE_TONE[p.state]}` }, p.enabled ? STATE_TEXT[p.state] : "Paused")),
        h("div", { class: "rs-stats" },
          h("span", {}, h("strong", {}, `${p.devices.online}/${p.devices.total}`), " devices online"),
          h("span", {}, h("strong", {}, String(p.services.down)), ` of ${p.services.total} checks down`),
          h("span", {}, h("strong", {}, String(p.problems.count)), " health problems"),
          p.vulns && p.vulns.configured ? h("span", { class: p.vulns.counts.critical ? "d-bad" : p.vulns.counts.high ? "d-warn" : "" }, h("strong", {}, String(p.vulns.counts.critical)), ` critical, ${p.vulns.counts.high} high vulnerabilities`) : null),
        h("div", { class: "hint" }, p.last_seen ? `Last report ${timeAgo(p.last_seen)}${p.version ? ` · Netlens ${p.version}` : ""}` : "Has not reported yet"));
    };
    const byCustomer = new Map();
    for (const p of probes) { const key = p.customer || ""; if (!byCustomer.has(key)) byCustomer.set(key, []); byCustomer.get(key).push(p); }
    const named = [...byCustomer.keys()].filter(Boolean).sort((a, b) => a.localeCompare(b));
    for (const key of byCustomer.has("") && !named.length ? [""] : [...named, ...(byCustomer.has("") ? [""] : [])]) {
      const sites = byCustomer.get(key), live = sites.filter((p) => !p.locked);
      if (named.length) {
        const down = live.filter((p) => p.state === "silent" || p.problems.critical || p.devices.core_down).length;
        const look = live.filter((p) => p.problems.count || p.services.down).length;
        body.appendChild(h("div", { class: "rs-customer" }, h("h2", {}, key || "Other sites"),
          h("span", { class: `hint rs-roll ${down ? "d-bad" : look ? "d-warn" : ""}` }, `${plural(sites.length, "site")} · ${live.reduce((a, p) => a + p.devices.online, 0)} / ${live.reduce((a, p) => a + p.devices.total, 0)} devices online · ${live.reduce((a, p) => a + p.services.down, 0)} checks down · ${live.reduce((a, p) => a + p.problems.count, 0)} health problems${live.some((p) => p.vulns && p.vulns.configured) ? ` · ${live.reduce((a, p) => a + (p.vulns && p.vulns.configured ? p.vulns.counts.critical : 0), 0)} critical vulnerabilities` : ""}${down ? ` · ${down} need attention` : ""}`)));
      }
      body.appendChild(h("div", { class: "rs-grid" }, sites.map(card)));
    }
  }

  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  function newSiteForm() {
    clear(form);
    const name = h("input", { type: "text", placeholder: "Branch office", maxlength: "60", required: true });
    const customer = h("input", { type: "text", placeholder: "Bakery Janssens", maxlength: "60", list: "rs-customers" });
    const known = h("datalist", { id: "rs-customers" });
    get("/api/probes").then((all) => { for (const c of [...new Set(all.map((x) => x.customer).filter(Boolean))]) known.appendChild(h("option", { value: c })); }).catch(() => {});
    const go = h("button", { class: "btn primary", type: "submit" }, "Create");
    form.appendChild(h("form", { class: "card edit-form", onsubmit: async (e) => {
      e.preventDefault();
      go.disabled = true;
      try {
        const r = await post("/api/probes", { name: name.value.trim() });
        if (customer.value.trim()) await patch(`/api/probes/${r.probe.id}`, { customer: customer.value.trim() });
        clear(form);
        form.appendChild(setupSteps(r.probe.name, r.token));
        showList();
      } catch (err) {
        toast(err.message || "Could not add the site", "error");
        if (err.status === 402) { clear(form); form.appendChild(h("div", { class: "card" }, h("h2", {}, "More sites need a licence"), h("p", {}, err.message), h("p", {}, h("a", { class: "btn primary", href: "#/settings/licence" }, "Open the licence page")))); }
        go.disabled = false;
      }
    } }, h("h2", {}, "Add a remote site"), h("div", { class: "field" }, h("label", {}, "Name of the location"), name),
    h("div", { class: "field" }, h("label", {}, "Customer (optional)"), customer, known, h("p", { class: "hint" }, "Sites of the same customer are shown together, with one line of totals.")),
    h("div", { class: "form-actions" }, go, h("button", { class: "btn", type: "button", onclick: () => clear(form) }, "Cancel"))));
    name.focus();
  }

  // Removing a site: everything this Netlens kept for it goes; the alerts raised about it can stay as history or go too.
  function removeForm(p) {
    clear(form);
    const events = h("input", { type: "checkbox" });
    const go = h("button", { class: "btn danger", type: "button" }, `Remove ${p.name}`);
    go.addEventListener("click", async () => {
      go.disabled = true;
      try {
        const r = await del(`/api/probes/${p.id}${events.checked ? "?events=true" : ""}`);
        const d = r.details || {};
        const parts = [`${d.devices} device${d.devices === 1 ? "" : "s"}`, `${d.checks} check${d.checks === 1 ? "" : "s"}`, d.events ? `${d.events} event${d.events === 1 ? "" : "s"}` : null, d.windows ? `${d.windows} maintenance window${d.windows === 1 ? "" : "s"} updated` : null, d.logins ? `${d.logins} customer login${d.logins === 1 ? "" : "s"} updated` : null].filter(Boolean);
        toast(`Removed ${p.name}: ${parts.join(", ")}`, "success");
        clear(form);
        location.hash = "#/remote-sites";
      } catch (err) {
        toast(err.message || "Could not remove", "error");
        go.disabled = false;
      }
    });
    form.appendChild(h("div", { class: "card error" }, h("h2", {}, `Remove ${p.name}?`),
      h("p", {}, "This removes the site, its devices and checks, their graphs, its snooze and what is waiting to be sent to it, and takes it out of maintenance windows and customer logins. A customer login that only saw this site is disabled."),
      h("label", { class: "check" }, events, ` Also delete the alerts raised about this site (otherwise they stay in the history)`),
      h("p", { class: "hint" }, "The remote Netlens keeps running; switch off Settings → Report to a central Netlens there, or it will keep trying with the old token."),
      h("div", { class: "form-actions" }, go, h("button", { class: "btn", type: "button", onclick: () => clear(form) }, "Cancel"))));
    form.scrollIntoView({ block: "nearest" });
  }

  async function showDetail(id) {
    let data;
    try {
      data = await get(`/api/probes/${id}`);
    } catch (err) {
      location.hash = "#/remote-sites";
      return;
    }
    if (disposed) return;
    const p = data.probe;
    clear(top); clear(body);
    const admin = isAdmin();
    const tools = h("div", { class: "form-actions admin-only" });
    tools.append(
      h("button", { class: "btn primary", type: "button", disabled: !(p.view && p.view.allowed && p.view.connected),
        title: !(p.view && p.view.allowed) ? "This site has not allowed it: tick “Let the central Netlens show this site” in its Settings > Report to a central Netlens"
          : !p.view.connected ? "This site is not connected right now (it keeps the connection open itself)" : "Open this site with the same pages as this Netlens has (read only)",
        onclick: () => enterSite({ id: p.id, name: p.name }) }, "Open this site"),
      h("button", { class: "btn", type: "button", title: "Ask the remote Netlens to scan its network now (it must accept commands)", disabled: !p.enabled || p.state !== "connected",
        onclick: async () => {
          try { await post(`/api/probes/${id}/command`, { command: "scan" }); toast("Asked. The site starts the scan with its next report.", "success"); showDetail(id); } catch (err) { toast(err.message || "Could not send the command", "error"); }
        } }, data.pending_commands.includes("scan") ? "Scan requested…" : "Scan now"),
      h("button", { class: "btn", type: "button", onclick: async () => {
        const name = window.prompt("New name", p.name);
        if (!name || name.trim() === p.name) return;
        try { await patch(`/api/probes/${id}`, { name }); toast("Renamed", "success"); showList(); } catch (err) { toast(err.message || "Could not rename", "error"); }
      } }, "Rename"),
      h("button", { class: "btn", type: "button", onclick: async () => {
        const customer = window.prompt("Customer (leave empty for none)", p.customer || "");
        if (customer === null || customer.trim() === (p.customer || "")) return;
        try { await patch(`/api/probes/${id}`, { customer }); toast("Saved", "success"); showList(); } catch (err) { toast(err.message || "Could not save", "error"); }
      } }, p.customer ? `Customer: ${p.customer}` : "Set customer"),
      h("button", { class: "btn", type: "button", title: "A page about this site for the customer (devices, checks, open points)",
        onclick: () => previewHtml(`${p.customer ? p.customer + " / " : ""}${p.name}`, `/api/documentation/site/${id}`, `/api/documentation/site/${id}?download=true`).catch((err) => toast(err.message || "Could not show the preview", "error")) }, "Documentation"),
      h("button", { class: "btn", type: "button", onclick: async () => {
        try { await patch(`/api/probes/${id}`, { enabled: !p.enabled }); toast(p.enabled ? "Paused: reports are refused" : "Resumed", "success"); showList(); } catch (err) { toast(err.message || "Could not change", "error"); }
      } }, p.enabled ? "Pause" : "Resume"),
      h("button", { class: "btn", type: "button", onclick: async () => {
        if (!window.confirm("Make a new token? The remote Netlens stops reporting until you enter the new one there.")) return;
        try { const r = await post(`/api/probes/${id}/token`, {}); clear(form); form.appendChild(setupSteps(p.name, r.token)); form.scrollIntoView({ block: "nearest" }); } catch (err) { toast(err.message || "Could not make a token", "error"); }
      } }, "New token"),
      h("button", { class: "btn danger", type: "button", onclick: () => removeForm(p) }, "Remove"));
    top.append(h("div", { class: "up-head" }, h("div", {}, h("p", {}, h("a", { href: "#/remote-sites" }, "← Remote sites")), h("h1", {}, p.name),
      h("p", { class: "hint" }, p.last_seen ? `Last report ${timeAgo(p.last_seen)} (${fmtTime(p.last_seen)})${p.version ? ` · Netlens ${p.version}` : ""}${p.last_ip ? ` · from ${p.last_ip}` : ""}` : "Has not reported yet")),
    admin ? tools : null));
    if (data.snoozed_until) body.appendChild(h("div", { class: "card" }, h("strong", {}, "Alerts for this site are snoozed"), ` for another ${untilText(data.snoozed_until)}: its events are recorded but not sent. `, wakeButton(data.snooze)));
    else if (admin) body.appendChild(h("p", { class: "hint" }, "Planned work at this site? ", snoozeMenu(data.snooze), " holds back all of its alerts for a while."));
    if (p.skew_s !== null && p.skew_s !== undefined && Math.abs(p.skew_s) > 120) body.appendChild(h("div", { class: "card error" }, h("strong", {}, "The clock of this site is off. "), `It is ${Math.abs(p.skew_s) >= 3600 ? `${Math.round(Math.abs(p.skew_s) / 360) / 10} hours` : `${Math.round(Math.abs(p.skew_s) / 60)} minutes`} ${p.skew_s > 0 ? "ahead of" : "behind"} this Netlens. Its graphs can be shifted, and measurements that are too far from the real time are not kept. Check the time and time zone of that machine.`));
    if (p.state === "silent") body.appendChild(h("div", { class: "card error" }, h("strong", {}, "This site has stopped reporting. "), "The devices below show how they were when it last reported; nothing at that location is being watched until it reports again."));
    body.appendChild(h("div", { class: "up-tiles" },
      tile("Devices online", `${p.devices.online} / ${p.devices.total}`, p.devices.core_down ? `${p.devices.core_down} always-on device${p.devices.core_down === 1 ? "" : "s"} offline` : "all always-on devices answer", p.devices.core_down ? "bad" : p.devices.online === p.devices.total ? "ok" : "warn"),
      tile("Service checks", `${p.services.total - p.services.down} / ${p.services.total}`, p.services.down ? `${p.services.down} down` : "all up", p.services.down ? "bad" : "ok"),
      tile("Health", String(p.problems.count), p.problems.count ? (p.problems.critical ? `${p.problems.critical} critical` : `${p.problems.count} warning${p.problems.count === 1 ? "" : "s"}`) : "within limits", p.problems.critical ? "bad" : p.problems.count ? "warn" : "ok")));
    const bits = [];
    if (data.scan && data.scan.finished) bits.push(`Last scan ${timeAgo(data.scan.finished)}${data.scan.hosts !== null && data.scan.hosts !== undefined ? ` (${data.scan.hosts} devices found)` : ""}${data.scan.running ? ", one is running now" : ""}`);
    if (p.backups && p.backups.configured) bits.push(`Backups: ${p.backups.protected}/${p.backups.guests} guests protected${p.backups.failed ? `, ${p.backups.failed} failed` : ""}${p.backups.late ? `, ${p.backups.late} late` : ""}${p.backups.newest ? `, newest ${timeAgo(p.backups.newest)}` : ""}`);
    if (data.monitors && data.monitors.length) bits.push(`${data.monitors.length} device${data.monitors.length === 1 ? "" : "s"} monitored for health (${data.monitors.filter((m) => m.ok === false).length} cannot be read)`);
    if (bits.length) body.appendChild(h("p", { class: "hint" }, bits.join(" · ")));
    if (p.vulns && p.vulns.configured) {
      const v = p.vulns, c = v.counts;
      body.appendChild(h("div", { class: "card" }, h("h2", {}, "Vulnerabilities"),
        h("p", {}, ["critical", "high", "medium", "low"].filter((s) => c[s]).map((s) => h("span", { class: "vuln-count" }, h("span", { class: `vuln-sev vuln-${s}` }, s[0].toUpperCase() + s.slice(1)), ` ${c[s]}`)),
          v.exploited ? h("span", { class: "vuln-exploited" }, `${v.exploited} known to be exploited`) : null),
        v.top.length ? h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Device", "Critical", "High"].map((x) => h("th", {}, x)))), h("tbody", {}, v.top.map((d) => h("tr", {}, h("td", {}, d.device), h("td", {}, String(d.critical || "")), h("td", {}, String(d.high || "")))))) : null,
        v.critical.length ? h("ul", { class: "d-list" }, v.critical.map((f) => h("li", {}, f.device, h("span", { class: "d-note" }, f.title + (f.cve.length ? ` (${f.cve.join(", ")})` : ""))))) : null,
        h("p", { class: "hint" }, `The scanner at the site reports this${v.last_scan ? `; last scan ${timeAgo(v.last_scan)}` : ""}. Only counts and the most serious findings are sent here.`)));
    }
    if (data.problems.length) {
      const card = h("div", { class: "card" }, h("h2", {}, "Needs attention"));
      for (const q of data.problems) {
        card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, h("span", { class: `hl-badge ${q.level === "critical" ? "bad" : "warn"}` }, q.level === "critical" ? "Critical" : "Warning"), " ", shortName(q.device || "")),
          h("span", {}, `${q.title}${q.label ? ` · ${q.label}` : ""}: ${q.value === null ? "" : q.unit === "%" ? `${Math.round(q.value)}%` : `${Math.round(q.value * 10) / 10} ${q.unit || ""}`}`)));
      }
      body.appendChild(card);
    }
    // services
    if (data.services.length) {
      const table = h("table", { class: "data" });
      table.appendChild(h("thead", {}, h("tr", {}, ["", "Check", "Target", "Response", "Checked", ""].map((t) => h("th", {}, t)))));
      const tb = h("tbody");
      for (const s of data.services) {
        const row = h("tr", {}, h("td", {}, h("span", { class: `svc-dot svc-${s.state || "unknown"}` })),
          h("td", {}, s.name, s.state === "down" && s.detail ? h("div", { class: "hint" }, s.detail) : null), h("td", { class: "mono" }, s.target || ""),
          h("td", {}, s.ms === null ? "–" : `${Math.round(s.ms)} ms`), h("td", {}, s.checked ? timeAgo(s.checked) : "–"));
        const graphRow = h("tr", { class: "rs-graph", hidden: true }, h("td", { colspan: 6 }));
        const btn = h("button", { class: "btn", type: "button" }, "Graph");
        btn.addEventListener("click", async () => {
          graphRow.hidden = !graphRow.hidden;
          if (!graphRow.hidden && !graphRow.firstChild.firstChild) {
            const card = await buildPerformanceCard("remote_service", s.id, { title: `${s.name}: history` });
            graphRow.firstChild.appendChild(card || h("p", { class: "hint" }, "No measurements yet."));
          }
        });
        row.appendChild(h("td", {}, btn));
        tb.append(row, graphRow);
      }
      table.appendChild(tb);
      body.appendChild(h("div", { class: "card" }, h("h2", {}, "Service checks"), h("div", { class: "table-wrap" }, table)));
    }
    // devices
    const monitorByKey = new Map((data.monitors || []).map((m) => [m.device_key, m]));
    let filter = "";
    if (admin) {
      try {
        const managed = await buildManagedCard(p, data.devices, data.config_state || { accepts: false, site_rev: 0 });
        const count = managed.querySelectorAll(".kv").length;
        const fold = h("details", { class: "card admin-only managed-fold" }, h("summary", {}, h("strong", {}, "Managed from here"), h("span", { class: "hint" }, count ? ` · ${count} check${count === 1 ? "" : "s and monitors"} set up` : " · nothing set up yet")), managed);
        fold.open = count > 0 || managedDirty;
        body.appendChild(fold);
      } catch (err) {
        /* an older server: nothing to manage */
      }
    }
    try { body.appendChild(await buildAvailabilityCard(p)); } catch (err) { /* an older server: no figures */ }
    if (admin) body.appendChild(buildSiteSettingsCard(p, () => showDetail(id)));
    const devCard = h("div", { class: "card" }, h("h2", {}, "Devices"));
    const devTools = h("div", { class: "up-tools" });
    const devTable = h("div", { class: "table-wrap" });
    const drawDevices = () => {
      clear(devTable);
      const q = filter.trim().toLowerCase();
      const table = h("table", { class: "data" });
      table.appendChild(h("thead", {}, h("tr", {}, ["", "Name", "Address", "Type", "Vendor", "Health", "Last seen", ""].map((t) => h("th", {}, t)))));
      const tb = h("tbody");
      for (const d of data.devices.filter((d) => !q || `${d.name} ${d.ip || ""} ${d.vendor || ""} ${d.type || ""}`.toLowerCase().includes(q))) {
        const m = monitorByKey.get(d.key);
        const health = m ? (m.ok === false ? h("span", { class: "error", title: m.error || "" }, "cannot be read")
          : m.latest && m.latest.cpu !== undefined && m.latest.cpu !== null ? `${Math.round(m.latest.cpu)}% cpu${m.latest.mem != null ? `, ${Math.round(m.latest.mem)}% mem` : ""}` : "monitored") : "";
        const row = h("tr", {}, h("td", {}, statusDot(d.online)), h("td", {}, shortName(d.name), d.always_on ? h("span", { class: "hint" }, " (always on)") : null, (p.muted || []).includes(d.key) ? h("span", { class: "hint" }, " (muted)") : null),
          h("td", { class: "mono" }, d.ip || ""), h("td", {}, d.type || ""), h("td", {}, d.vendor || ""), h("td", {}, health), h("td", {}, d.last_seen ? timeAgo(d.last_seen) : ""));
        const graphRow = h("tr", { class: "rs-graph", hidden: true }, h("td", { colspan: 8 }));
        const btn = h("button", { class: "btn", type: "button" }, "Graphs");
        btn.addEventListener("click", async () => {
          graphRow.hidden = !graphRow.hidden;
          if (!graphRow.hidden && !graphRow.firstChild.firstChild) {
            graphRow.firstChild.appendChild(h("p", { class: "hint" }, [d.mac ? `MAC ${d.mac}` : null, d.os ? `System ${d.os}` : null, d.ports && d.ports.length ? `Open ports ${d.ports.join(", ")}` : null,
              d.first_seen ? `First seen ${fmtTime(d.first_seen)}` : null, m && m.error ? `Health: ${m.error}` : null].filter(Boolean).join(" · ")));
            const card = await buildPerformanceCard("remote", d.id, { title: `${shortName(d.name)}: history` });
            graphRow.firstChild.appendChild(card || h("p", { class: "hint" }, "No measurements yet. They appear after a few reports."));
          }
        });
        const muted = (p.muted || []).includes(d.key);
        const mute = h("button", { class: "btn admin-only", type: "button", title: muted ? "This device raises no offline alert. Click to alert again." : "Stop the offline alerts of this device" }, muted ? "Unmute" : "Mute");
        mute.addEventListener("click", async () => {
          const next = muted ? p.muted.filter((k) => k !== d.key) : [...(p.muted || []), d.key];
          try { await patch(`/api/probes/${id}`, { muted: next }); toast(muted ? "Alerts back on" : "Muted: no offline alerts for this device", "success"); showDetail(id); } catch (err) { toast(err.message || "Could not change", "error"); }
        });
        const canOpen = admin && p.view && p.view.allowed && p.view.connected;
        const open = h("button", { class: "btn", type: "button", disabled: !canOpen,
          title: canOpen ? "Open this device in the site's own interface (same pages as a local device)" : "Needs the site to allow viewing and be connected (see Open this site)" }, "Open");
        open.addEventListener("click", async () => {
          open.disabled = true;
          try {
            // the site numbers its devices itself: find this one in the site's own list by MAC address or address
            const list = await get(`/api/site-view/${p.id}/api/devices`);
            const mac = (d.mac || "").toLowerCase();
            const found = list.find((x) => (mac && (x.mac || "").toLowerCase() === mac) || (!mac && d.ip && x.primary_ip === d.ip));
            if (!found) throw new Error("The site does not list this device (any more).");
            enterSite({ id: p.id, name: p.name }, `#/device/${found.id}`);
          } catch (err) { toast(err.message || "Could not open the device", "error"); open.disabled = false; }
        });
        row.appendChild(h("td", {}, btn, " ", canOpen ? open : null, canOpen ? " " : null, admin ? mute : null));
        tb.append(row, graphRow);
      }
      table.appendChild(tb);
      devTable.appendChild(table);
    };
    devTools.appendChild(h("input", { type: "text", placeholder: "Filter by name, address or vendor", "aria-label": "Filter devices", oninput: (e) => { filter = e.target.value; drawDevices(); } }));
    devCard.append(devTools, devTable);
    drawDevices();
    body.appendChild(devCard);
    if (data.events.length) {
      body.appendChild(h("div", { class: "card" }, h("h2", {}, "Recent events"),
        h("ul", { class: "d-attention" }, data.events.map((e) => h("li", {}, h("span", { class: "hint" }, `${fmtTime(e.ts)} `), e.detail || e.kind, e.maintenance ? h("span", { class: "hint" }, ` (${e.maintenance})`) : null)))));
    }
  }

  async function refresh() {
    if (disposed || form.firstChild) return;      // a form or token that is open is left alone
    try {
      await showList();
    } catch (err) {
      if (!disposed) toast("Failed to load the remote sites", "error");
    }
  }

  const onSnoozed = () => { if (!disposed && queryId()) showDetail(queryId()); };
  document.addEventListener("netlens:snoozed", onSnoozed);
  await showList();
  timer = setInterval(() => { if (!disposed && !form.firstChild && !managedDirty && !body.querySelector(".rs-add :focus") && !body.querySelector("tr.rs-graph:not([hidden])")) refresh(); }, REFRESH_MS);
  return () => { disposed = true; if (timer) clearInterval(timer); document.removeEventListener("netlens:snoozed", onSnoozed); };
}
