import { get, post, patch, del } from "../api.js";
import { h, clear, toast, statusDot, shortName, timeAgo, isAdmin, fmtTime } from "../util.js";
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
    top.append(h("div", { class: "up-head" }, h("div", {}, h("h1", {}, "Remote sites"),
      h("p", { class: "hint" }, "Other locations that run Netlens and report here: devices, service checks, health and alerts of each in one place.")), add));
    if (!probes.length) {
      body.appendChild(h("div", { class: "card" }, h("h2", {}, "No remote sites yet"),
        h("p", {}, "Run Netlens at the other location (a branch office, a second home, a customer), then add it here to get a token. It reports to this Netlens every minute and always connects out, so nothing at that location has to be reachable from the internet."),
        h("p", { class: "hint" }, "Each site keeps working on its own if the connection drops, and this page tells you when a site stops reporting.")));
      return;
    }
    const grid = h("div", { class: "rs-grid" });
    for (const p of probes) {
      const tone = !p.enabled ? "off" : p.problems.critical || p.state === "silent" || p.devices.core_down ? "bad" : p.problems.count || p.services.down || p.state === "waiting" ? "warn" : "ok";
      grid.appendChild(h("a", { class: `rs-card tone-${tone}`, href: `#/remote-sites?id=${p.id}` },
        h("div", { class: "rs-name" }, h("strong", {}, p.name), h("span", { class: `hl-badge ${STATE_TONE[p.state] === "ok" ? "" : STATE_TONE[p.state]}` }, p.enabled ? STATE_TEXT[p.state] : "Paused")),
        h("div", { class: "rs-stats" },
          h("span", {}, h("strong", {}, `${p.devices.online}/${p.devices.total}`), " devices online"),
          h("span", {}, h("strong", {}, String(p.services.down)), ` of ${p.services.total} checks down`),
          h("span", {}, h("strong", {}, String(p.problems.count)), " health problems")),
        h("div", { class: "hint" }, p.last_seen ? `Last report ${timeAgo(p.last_seen)}${p.version ? ` · Netlens ${p.version}` : ""}` : "Has not reported yet")));
    }
    body.appendChild(grid);
  }

  function newSiteForm() {
    clear(form);
    const name = h("input", { type: "text", placeholder: "Branch office", maxlength: "60", required: true });
    const go = h("button", { class: "btn primary", type: "submit" }, "Create");
    form.appendChild(h("form", { class: "card edit-form", onsubmit: async (e) => {
      e.preventDefault();
      go.disabled = true;
      try {
        const r = await post("/api/probes", { name: name.value.trim() });
        clear(form);
        form.appendChild(setupSteps(r.probe.name, r.token));
        showList();
      } catch (err) {
        toast(err.message || "Could not add the site", "error");
        go.disabled = false;
      }
    } }, h("h2", {}, "Add a remote site"), h("div", { class: "field" }, h("label", {}, "Name of the location"), name),
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
      tile("Health", String(p.problems.count), p.problems.count ? `${p.problems.critical} critical` : "within limits", p.problems.critical ? "bad" : p.problems.count ? "warn" : "ok")));
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
  timer = setInterval(() => { if (!disposed && !form.firstChild && !body.querySelector("tr.rs-graph:not([hidden])")) refresh(); }, REFRESH_MS);
  return () => { disposed = true; if (timer) clearInterval(timer); };
}
