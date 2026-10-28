import { get, put, post, api } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

// Settings → Host agents: hosts that cannot be reached from Netlens push their readings through a standard collector (OpenTelemetry Collector or Telegraf).
// Enterprise. Nothing here sends anything TO a host: the collector connects to Netlens with a client certificate.

const STATE = { active: ["ok", "enrolled"], pending: ["warn", "waiting for enrolment"], revoked: ["bad", "revoked"] };

function copyBox(text, label) {
  const pre = h("pre", { class: "code-block", style: "white-space:pre-wrap;word-break:break-all;margin:.3em 0" }, text);
  const btn = h("button", { class: "btn", type: "button" }, "Copy");
  btn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); toast("Copied", "success"); } catch { toast("Select the text and copy it", "error"); }
  });
  return h("div", {}, label ? h("div", { class: "hint" }, label) : null, pre, btn);
}

function enrolCommands(r) {
  const server = r.server || "NETLENS-ADDRESS";
  const url = `https://${server}:${r.enrol_port}/enrol`;
  const linux = [
    "# on the host, as root; ca.pem is the certificate downloaded from this page",
    "install -d -m 0750 /etc/netlens-agent && cd /etc/netlens-agent",
    "openssl ecparam -name prime256v1 -genkey -noout -out agent.key && chmod 600 agent.key",
    "openssl req -new -key agent.key -subj \"/CN=$(hostname)\" -out agent.csr",
    `curl --fail --cacert ca.pem -H "Authorization: Bearer ${r.token}" --data-binary @agent.csr ${url} -o agent.crt`,
  ].join("\n");
  const windows = [
    "# in an elevated PowerShell; ca.pem is the certificate downloaded from this page, openssl.exe is OpenSSL for Windows",
    "New-Item -ItemType Directory -Force C:\\ProgramData\\netlens-agent | Out-Null; cd C:\\ProgramData\\netlens-agent",
    "openssl ecparam -name prime256v1 -genkey -noout -out agent.key",
    "icacls agent.key /inheritance:r /grant:r \"SYSTEM:(R)\" \"BUILTIN\\Administrators:(F)\"",
    "openssl req -new -key agent.key -subj \"/CN=$env:COMPUTERNAME\" -out agent.csr",
    `curl.exe --fail --cacert ca.pem -H "Authorization: Bearer ${r.token}" --data-binary "@agent.csr" ${url} -o agent.crt`,
  ].join("\n");
  return [copyBox(linux, "Linux, BSD and other Unix"), copyBox(windows, "Windows Server")];
}

export async function buildIngestCard() {
  const card = h("div", { class: "card admin-only" });
  let info = await get("/api/ingest");
  let devices = [];
  try { devices = await get("/api/devices"); } catch { devices = []; }
  let shown = null; // the one-time token of the agent that was just made (it is never shown again)

  const devName = (d) => d.custom_name || d.hostname || d.primary_ip || `device ${d.id}`;

  function pill(a) {
    if (a.silent && a.state === "active") return h("span", { class: "tag bad", title: "No data for a while: the host, the network or the collector may be the cause" }, "silent");
    const [kind, text] = STATE[a.state] || ["warn", a.state];
    return h("span", { class: `tag ${kind}` }, text);
  }

  async function act(fn, ok) {
    try { const r = await fn(); if (ok) toast(ok, "success"); return r; } catch (err) { toast(err.message || "Failed", "error"); return null; }
  }

  function draw() {
    clear(card);
    const p = info.policy;
    card.appendChild(h("h2", {}, "Host agents (locked-down hosts)"));
    card.appendChild(h("p", { class: "hint" },
      "A host that allows no inbound access and no stored login can still be monitored: a standard collector on the host (OpenTelemetry Collector or Telegraf) pushes its readings to Netlens over HTTPS with a client certificate. Netlens only listens and answers: it never sends a command, a setting or an update to a host. Readings are stored like those of any other monitored host, with the same limits, alerts and graphs. Part of the Enterprise edition and the free trial."));
    if (!info.allowed) card.appendChild(h("p", { class: "warn-text" }, "Part of the Enterprise edition and the free trial (Settings → Licence)."));

    // ---------------------------------------------------------------- settings (the one Save of this page)
    const enabled = h("input", { type: "checkbox" });
    enabled.checked = p.enabled;
    const names = h("input", { type: "text", value: (p.server_names || []).join(", "), placeholder: "netlens.example.com, 10.0.0.5", style: "max-width:36rem" });
    const bind = h("input", { type: "text", value: p.bind, style: "width:12em" });
    const port = h("input", { type: "number", min: "1024", max: "65535", value: String(p.port), style: "width:7em" });
    const eport = h("input", { type: "number", min: "1024", max: "65535", value: String(p.enrol_port), style: "width:7em" });
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      const r = await act(() => put("/api/ingest", { enabled: enabled.checked, server_names: names.value.split(",").map((x) => x.trim()).filter(Boolean), bind: bind.value.trim(), port: Number(port.value), enrol_port: Number(eport.value) }), "Saved");
      if (r) info = r;
      draw();
    });
    card.append(
      h("label", { class: "check" }, enabled, " Receive readings from host agents"),
      h("div", { class: "field" }, h("label", {}, "Name or address the collectors connect to"), names,
        h("div", { class: "hint" }, "It goes into the server certificate: every name that a collector uses to reach Netlens must be listed (comma separated).")),
      h("div", { class: "field" }, h("label", {}, "Listen on"), bind, h("div", { class: "hint" }, "0.0.0.0 means every network interface. Use one address to listen on the interface that the hosts can reach only.")),
      h("div", { class: "field" }, h("label", {}, "Port for readings"), port, h("div", { class: "hint" }, "4318 is the standard port for OTLP over HTTP. A client certificate is required: without one the connection ends before anything is read.")),
      h("div", { class: "field" }, h("label", {}, "Port for enrolment"), eport, h("div", { class: "hint" }, "Only open while an enrolment window is running (below).")),
      h("div", { class: "form-actions" }, save));

    // ---------------------------------------------------------------- status and certificates
    const st = info.status || {};
    const listening = Object.keys(st.listening || {});
    const errors = Object.values(st.errors || {});
    card.appendChild(h("h3", {}, "Status"));
    card.appendChild(h("p", { class: errors.length ? "error" : "hint" },
      errors.length ? errors.join(" ") : listening.includes("ingest") ? `Listening on ${p.bind}:${p.port}${listening.includes("enrol") ? ` and ${p.bind}:${p.enrol_port} (enrolment window open)` : ""}.` : (p.enabled ? "Not listening yet (this can take a few seconds)." : "Switched off: nothing listens.")));
    const sc = info.server_certificate;
    if (sc) card.appendChild(h("p", { class: "hint" }, `Server certificate: ${sc.source === "uploaded" ? "uploaded by you" : "made by Netlens"} for ${(sc.names || []).join(", ") || "-"}, valid until ${sc.expires.slice(0, 10)}.`));
    if (info.ca_fingerprint) card.appendChild(h("p", { class: "hint", style: "overflow-wrap:anywhere;word-break:break-all" }, `Netlens ingest CA (SHA-256): ${info.ca_fingerprint.match(/.{1,2}/g).join(":")}`));
    const dl = h("button", { class: "btn", type: "button" }, "Download the CA certificate (ca.pem)");
    dl.addEventListener("click", async () => {
      const text = await act(() => api("/api/ingest/ca.pem"));
      if (typeof text !== "string") return;
      const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" })), download: "netlens-ingest-ca.pem" });
      document.body.appendChild(a); a.click(); a.remove();
    });
    card.appendChild(h("div", { class: "btn-row" }, dl));

    // ---------------------------------------------------------------- enrolment window
    card.appendChild(h("h3", {}, "Enrolment"));
    card.appendChild(h("p", { class: "hint" }, "Hosts get their certificate during an enrolment window: open it, enrol the hosts, and it closes by itself. Outside a window the enrolment port is closed."));
    if (info.window_open) {
      const close = h("button", { class: "btn", type: "button" }, "Close the window now");
      close.addEventListener("click", async () => { const r = await act(() => api("/api/ingest/window", { method: "DELETE" })); if (r) info = r; draw(); });
      card.appendChild(h("p", {}, h("span", { class: "tag ok" }, "open"), ` until ${p.enrol_until.replace("T", " ").replace("Z", " UTC")} `, close));
    } else {
      const minutes = h("input", { type: "number", min: "5", max: "240", value: "30", style: "width:5em" });
      const open = h("button", { class: "btn", type: "button" }, "Open an enrolment window");
      open.disabled = !p.enabled || !info.allowed;
      open.addEventListener("click", async () => { const r = await act(() => post("/api/ingest/window", { minutes: Number(minutes.value) })); if (r) info = r; draw(); });
      card.appendChild(h("div", { class: "btn-row" }, minutes, " minutes ", open));
    }

    // ---------------------------------------------------------------- the one-time token that was just made
    if (shown) {
      const box = h("div", { class: "card", style: "border:1px solid var(--accent, #4a90d9)" },
        h("h3", {}, shown.agent.identity ? "Agent added" : `Enrolment token for ${shown.agent.name}`));
      if (shown.token) {
        box.append(h("p", { class: "warn-text" }, `Shown once. It works one time and ends in ${shown.token_hours} hours. Open an enrolment window first. Run the commands on the host:`),
          copyBox(shown.token, "Token"), ...enrolCommands(shown),
          h("p", { class: "hint" }, "Then configure the collector with ca.pem, agent.crt and agent.key (see the documentation for OpenTelemetry Collector and Telegraf)."));
      } else {
        box.append(h("p", { class: "hint" }, "This agent uses a certificate from your own CA; no token is needed. The collector connects with that certificate."));
      }
      const done = h("button", { class: "btn", type: "button" }, "Done");
      done.addEventListener("click", () => { shown = null; draw(); });
      box.appendChild(h("div", { class: "btn-row" }, done));
      card.appendChild(box);
    }

    // ---------------------------------------------------------------- agents
    card.appendChild(h("h3", {}, "Agents"));
    if (!info.agents.length) card.appendChild(h("p", { class: "hint" }, "No agent yet."));
    for (const a of info.agents) {
      const row = h("div", { class: "card", style: "margin:.4em 0" });
      row.appendChild(h("div", {}, h("strong", {}, a.name), " ", pill(a), " ",
        h("span", { class: "hint" }, `${a.targets.map((t) => t.name).join(", ") || "-"} · ${a.mode === "own_ca" ? `your CA (${a.identity})` : "Netlens certificate"}`)));
      row.appendChild(h("div", { class: "hint" },
        `Last data ${a.last_seen ? timeAgo(a.last_seen) : "never"}${a.last_ip ? ` from ${a.last_ip}` : ""} · ${a.accepted} readings accepted, ${a.dropped} dropped, ${a.rejected} requests refused` +
        (a.cert_days_left !== null && a.cert_days_left !== undefined ? ` · certificate ${a.cert_days_left < 0 ? "expired" : `${a.cert_days_left} days left`}` : "") +
        (a.token_pending ? ` · token valid until ${a.token_expires.slice(0, 16).replace("T", " ")} UTC` : "")));
      const buttons = h("div", { class: "btn-row" });
      if (a.mode === "netlens_ca") {
        const tok = h("button", { class: "btn", type: "button", title: "Makes a new one-time token. The current certificate stops working at once." }, a.state === "pending" ? "New token" : "Enrol again");
        tok.addEventListener("click", async () => {
          if (a.state === "active" && !confirm(`Enrol ${a.name} again? Its current certificate stops working at once.`)) return;
          const r = await act(() => post(`/api/ingest/agents/${a.id}/token`, {}));
          if (r) { shown = r; info = await get("/api/ingest"); draw(); }
        });
        buttons.appendChild(tok);
      }
      if (a.state === "revoked" && a.mode === "own_ca") {
        const back = h("button", { class: "btn", type: "button" }, "Allow again");
        back.addEventListener("click", async () => { await act(() => post(`/api/ingest/agents/${a.id}/reinstate`, {}), "Allowed"); info = await get("/api/ingest"); draw(); });
        buttons.appendChild(back);
      } else if (a.state !== "revoked") {
        const rev = h("button", { class: "btn", type: "button", title: "The certificate is refused from the next request on." }, "Revoke");
        rev.addEventListener("click", async () => {
          if (!confirm(`Revoke ${a.name}? It can no longer send data.`)) return;
          await act(() => post(`/api/ingest/agents/${a.id}/revoke`, {}), "Revoked"); info = await get("/api/ingest"); draw();
        });
        buttons.appendChild(rev);
      }
      const del = h("button", { class: "btn danger", type: "button" }, "Delete");
      del.addEventListener("click", async () => {
        if (!confirm(`Delete ${a.name}? Its readings stay; the host stops being monitored through it.`)) return;
        await act(() => api(`/api/ingest/agents/${a.id}`, { method: "DELETE" }), "Deleted"); info = await get("/api/ingest"); draw();
      });
      buttons.appendChild(del);
      row.appendChild(buttons);
      card.appendChild(row);
    }

    // ---------------------------------------------------------------- add an agent
    const free = devices.filter((d) => !info.agents.some((a) => a.targets.some((t) => t.device_id === d.id)));
    const name = h("input", { type: "text", placeholder: "web01", style: "max-width:20rem" });
    const pick = h("select", { multiple: "multiple", size: "6", style: "min-width:20rem" }, ...free.map((d) => h("option", { value: String(d.id) }, devName(d))));
    const hostNames = h("textarea", { rows: "3", placeholder: "only for a gateway (several hosts): one per line, device name = name used in the data\nweb01 = web01.example.com", style: "max-width:36rem" });
    const identity = h("input", { type: "text", placeholder: "dns:web01.example.com (only for certificates from your own CA)", style: "max-width:36rem" });
    const interval = h("input", { type: "number", min: "10", max: "3600", value: "60", style: "width:6em" });
    const add = h("button", { class: "btn", type: "button" }, "Add the agent");
    add.disabled = !info.allowed;
    add.addEventListener("click", async () => {
      const ids = [...pick.selectedOptions].map((o) => Number(o.value));
      const map = {};
      for (const line of hostNames.value.split("\n")) { const m = line.split("="); if (m.length === 2) map[m[0].trim().toLowerCase()] = m[1].trim(); }
      const targets = ids.map((id) => { const d = devices.find((x) => x.id === id); const key = devName(d).toLowerCase(); return ids.length > 1 ? { device_id: id, host_name: map[key] || "" } : { device_id: id }; });
      const r = await act(() => post("/api/ingest/agents", { name: name.value.trim(), targets, identity: identity.value.trim(), interval_s: Number(interval.value) }));
      if (r) { shown = r; info = await get("/api/ingest"); draw(); }
    });
    card.append(h("h3", {}, "Add an agent"),
      h("p", { class: "hint" }, "Link the agent to the device it reports for. One device: every reading it sends is for that device. A gateway collector that sends for several hosts needs the name it uses in its data for each device."),
      h("div", { class: "field" }, h("label", {}, "Name"), name),
      h("div", { class: "field" }, h("label", {}, "Device(s) it reports for"), pick),
      h("div", { class: "field" }, h("label", {}, "Names in the data (gateway only)"), hostNames),
      h("div", { class: "field" }, h("label", {}, "Identity in your own certificate (optional)"), identity),
      h("div", { class: "field" }, h("label", {}, "Sends every (seconds)"), interval, h("div", { class: "hint" }, "A host that is silent for three times this long is reported.")),
      h("div", { class: "btn-row" }, add));

    // ---------------------------------------------------------------- your own CA and server certificate
    card.appendChild(h("h3", {}, "Your own certificate authority"));
    card.appendChild(h("p", { class: "hint" }, `Instead of certificates made by Netlens, collectors can use certificates from your company CA: paste the CA certificate(s) here and give each agent its identity. ${info.own_ca ? `${info.own_ca} CA certificate${info.own_ca === 1 ? "" : "s"} trusted.` : "None yet."} A certificate from your CA is matched to an agent by its identity (a DNS name or URI in the certificate, or its CN); revoking an agent here stops it even though the certificate itself is still valid.`));
    const ca = h("textarea", { rows: "4", placeholder: "-----BEGIN CERTIFICATE-----", style: "max-width:36rem;font-family:monospace" });
    const caSave = h("button", { class: "btn", type: "button" }, "Trust these CA certificates");
    caSave.addEventListener("click", async () => { const r = await act(() => put("/api/ingest/own-ca", { pem: ca.value }), "Saved"); if (r) { info = r; draw(); } });
    card.append(h("div", { class: "field" }, ca), h("div", { class: "btn-row" }, caSave));

    card.appendChild(h("h3", {}, "Server certificate"));
    card.appendChild(h("p", { class: "hint" }, "Netlens makes its own server certificate from the names above. To use one from your company CA, paste the certificate (with its chain) and the private key (PEM, no password)."));
    const sc1 = h("textarea", { rows: "3", placeholder: "certificate PEM", style: "max-width:36rem;font-family:monospace" });
    const sc2 = h("textarea", { rows: "3", placeholder: "private key PEM", style: "max-width:36rem;font-family:monospace" });
    const scSave = h("button", { class: "btn", type: "button" }, "Use this certificate");
    scSave.addEventListener("click", async () => { const r = await act(() => put("/api/ingest/server-certificate", { certificate: sc1.value, key: sc2.value }), "Saved"); if (r) { info = r; draw(); } });
    const scGen = h("button", { class: "btn", type: "button" }, "Use a certificate made by Netlens");
    scGen.addEventListener("click", async () => { const r = await act(() => put("/api/ingest/server-certificate", { use_generated: true }), "Saved"); if (r) { info = r; draw(); } });
    card.append(h("div", { class: "field" }, sc1), h("div", { class: "field" }, sc2), h("div", { class: "btn-row" }, scSave, scGen));
  }

  draw();
  return card;
}
