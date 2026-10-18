import { get, post, patch, put, del } from "../api.js";
import { h, clear, toast, statusDot, shortName, timeAgo, isAdmin, fmtTime } from "../util.js";
import { pageHead, emptyState } from "../ui.js";
import { buildPerformanceCard } from "../cards/performance.js";

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

let managedDirty = false;      // the "Managed from here" card has changes that are not saved: the page must not redraw itself
const KIND_TITLE = { http: "Website (HTTP/HTTPS)", tcp: "Port (TCP)", dns: "DNS lookup", cert: "Certificate" };

// "Managed from here": the checks and monitors this Netlens sets up at the remote site (the site must accept configuration).
async function buildManagedCard(probe, devices, state) {
  const card = h("div", { class: "card" });
  let cfg = await get(`/api/probes/${probe.id}/config`);
  let draft = JSON.parse(JSON.stringify(cfg));
  let dirty = false;
  managedDirty = false;

  function status() {
    if (!state.accepts) return h("p", { class: "hint" }, "This site does not accept configuration yet. On the remote Netlens tick Settings → Report to a central Netlens → “Accept configuration from the central Netlens”.");
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
        h("span", {}, `${KIND_TITLE[s.kind] || s.kind} · ${s.host}${s.port ? `:${s.port}` : ""}${s.path || ""}`, " ",
          h("button", { class: "btn", type: "button", onclick: () => { draft.services.splice(i, 1); dirty = true; draw(); } }, "Remove"))));
    }
    const name = h("input", { type: "text", placeholder: "Name" }), kind = h("select", {}, Object.entries(KIND_TITLE).map(([k, t]) => h("option", { value: k }, t)));
    const host = h("input", { type: "text", placeholder: "Host or address" }), port = h("input", { type: "number", placeholder: "Port" }), path = h("input", { type: "text", placeholder: "Path or name (/ , example.com)" });
    const addService = h("button", { class: "btn", type: "button" }, "Add the check");
    addService.addEventListener("click", () => {
      if (!name.value.trim() || !host.value.trim()) { toast("Give the check a name and a host", "error"); return; }
      const item = { name: name.value.trim(), kind: kind.value, host: host.value.trim(), path: path.value.trim(), interval_s: 60, timeout_s: 5 };
      if (port.value) item.port = Number(port.value);
      draft.services.push(item);
      dirty = true;
      draw();
    });
    card.appendChild(h("div", { class: "rs-add" }, name, kind, host, port, path, addService));

    card.appendChild(h("h3", {}, "Health monitors"));
    if (!draft.monitors.length) card.appendChild(h("p", { class: "hint" }, "None."));
    for (const [i, m] of draft.monitors.entries()) {
      const dev = devices.find((d) => d.key === m.device_key);
      card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, dev ? dev.name : m.device_key),
        h("span", {}, `${m.method.toUpperCase()}${m.version ? ` ${m.version}` : ""} · every ${m.interval_s} s`, " ",
          h("button", { class: "btn", type: "button", onclick: () => { draft.monitors.splice(i, 1); dirty = true; draw(); } }, "Remove"))));
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
      h("a", { class: "btn", href: `/api/documentation/site/${id}`, target: "_blank", rel: "noopener", title: "A page about this site for the customer (devices, checks, open points)" }, "Documentation"),
      h("button", { class: "btn", type: "button", onclick: async () => {
        try { await patch(`/api/probes/${id}`, { enabled: !p.enabled }); toast(p.enabled ? "Paused: reports are refused" : "Resumed", "success"); showList(); } catch (err) { toast(err.message || "Could not change", "error"); }
      } }, p.enabled ? "Pause" : "Resume"),
      h("button", { class: "btn", type: "button", onclick: async () => {
        if (!window.confirm("Make a new token? The remote Netlens stops reporting until you enter the new one there.")) return;
        try { const r = await post(`/api/probes/${id}/token`, {}); clear(form); form.appendChild(setupSteps(p.name, r.token)); form.scrollIntoView({ block: "nearest" }); } catch (err) { toast(err.message || "Could not make a token", "error"); }
      } }, "New token"),
      h("button", { class: "btn danger", type: "button", onclick: async () => {
        if (!window.confirm(`Remove ${p.name} and everything it reported (devices, checks and graphs)?`)) return;
        try { await del(`/api/probes/${id}`); toast("Removed", "success"); location.hash = "#/remote-sites"; } catch (err) { toast(err.message || "Could not remove", "error"); }
      } }, "Remove"));
    top.append(h("div", { class: "up-head" }, h("div", {}, h("p", {}, h("a", { href: "#/remote-sites" }, "← Remote sites")), h("h1", {}, p.name),
      h("p", { class: "hint" }, p.last_seen ? `Last report ${timeAgo(p.last_seen)} (${fmtTime(p.last_seen)})${p.version ? ` · Netlens ${p.version}` : ""}${p.last_ip ? ` · from ${p.last_ip}` : ""}` : "Has not reported yet")),
    admin ? tools : null));
    if (p.state === "silent") body.appendChild(h("div", { class: "card error" }, h("strong", {}, "This site has stopped reporting. "), "The devices below show how they were when it last reported; nothing at that location is being watched until it reports again."));
    body.appendChild(h("div", { class: "up-tiles" },
      tile("Devices online", `${p.devices.online} / ${p.devices.total}`, p.devices.core_down ? `${p.devices.core_down} always-on device${p.devices.core_down === 1 ? "" : "s"} offline` : "all always-on devices answer", p.devices.core_down ? "bad" : p.devices.online === p.devices.total ? "ok" : "warn"),
      tile("Service checks", `${p.services.total - p.services.down} / ${p.services.total}`, p.services.down ? `${p.services.down} down` : "all up", p.services.down ? "bad" : "ok"),
      tile("Health", String(p.problems.count), p.problems.count ? (p.problems.critical ? `${p.problems.critical} critical` : `${p.problems.count} warning${p.problems.count === 1 ? "" : "s"}`) : "within limits", p.problems.critical ? "bad" : p.problems.count ? "warn" : "ok")));
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
        const row = h("tr", {}, h("td", {}, statusDot(d.online)), h("td", {}, shortName(d.name), d.always_on ? h("span", { class: "hint" }, " (always on)") : null),
          h("td", { class: "mono" }, d.ip || ""), h("td", {}, d.type || ""), h("td", {}, d.vendor || ""), h("td", {}, health), h("td", {}, d.last_seen ? timeAgo(d.last_seen) : ""));
        const graphRow = h("tr", { class: "rs-graph", hidden: true }, h("td", { colspan: 8 }));
        const btn = h("button", { class: "btn", type: "button" }, "Graphs");
        btn.addEventListener("click", async () => {
          graphRow.hidden = !graphRow.hidden;
          if (!graphRow.hidden && !graphRow.firstChild.firstChild) {
            const card = await buildPerformanceCard("remote", d.id, { title: `${shortName(d.name)}: history` });
            graphRow.firstChild.appendChild(card || h("p", { class: "hint" }, "No measurements yet. They appear after a few reports."));
          }
        });
        row.appendChild(h("td", {}, btn));
        tb.append(row, graphRow);
      }
      table.appendChild(tb);
      devTable.appendChild(table);
    };
    devTools.appendChild(h("input", { type: "text", placeholder: "Filter by name, address or vendor", "aria-label": "Filter devices", oninput: (e) => { filter = e.target.value; drawDevices(); } }));
    devCard.append(devTools, devTable);
    drawDevices();
    body.appendChild(devCard);
  }

  async function refresh() {
    if (disposed || form.firstChild) return;      // a form or token that is open is left alone
    try {
      await showList();
    } catch (err) {
      if (!disposed) toast("Failed to load the remote sites", "error");
    }
  }

  await showList();
  timer = setInterval(() => { if (!disposed && !form.firstChild && !managedDirty && !body.querySelector(".rs-add :focus") && !body.querySelector("tr.rs-graph:not([hidden])")) refresh(); }, REFRESH_MS);
  return () => { disposed = true; if (timer) clearInterval(timer); };
}
