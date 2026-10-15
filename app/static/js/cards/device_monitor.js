import { get, put, post, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const PORTS = { snmp: "161", ssh: "22", winrm: "5986" };
const INTERVALS = [[30, "every 30 seconds"], [60, "every minute"], [120, "every 2 minutes"], [300, "every 5 minutes"], [600, "every 10 minutes"], [1800, "every 30 minutes"]];

function field(label, input, hint) {
  const wrap = h("div", { class: "field" }, h("label", {}, label), input);
  if (hint) wrap.appendChild(h("p", { class: "hint" }, hint));
  return wrap;
}

const fmtValue = (v) => {
  const n = v.value;
  if (v.unit === "%") return `${n.toFixed(n >= 100 ? 0 : 1)}%`;
  if (v.unit === "s") return n >= 86400 ? `${(n / 86400).toFixed(1)} days` : `${Math.round(n / 3600)} h`;
  if (v.unit === "B") return n >= 1e12 ? `${(n / 1e12).toFixed(1)} TB free` : `${(n / 1e9).toFixed(1)} GB free`;
  if (v.unit === "bps") return n >= 1e6 ? `${(n / 1e6).toFixed(1)} Mbit/s` : `${(n / 1e3).toFixed(0)} kbit/s`;
  if (v.unit === "state") return n >= 1 ? "yes" : "no";
  return `${Math.round(n * 10) / 10}${v.unit ? ` ${v.unit}` : ""}`;
};
const NAMES = {
  cpu_pct: "Processor", load1: "Load", mem_pct: "Memory in use", swap_pct: "Swap in use", disk_pct: "Disk used", disk_free_b: "Disk free", net_rx_bps: "Received",
  net_tx_bps: "Sent", temp_c: "Temperature", uptime_s: "Running for", supply_pct: "Supply", battery_pct: "UPS battery", battery_minutes: "UPS runtime", on_battery: "On battery power", storage_status: "Storage",
};

let formOpen = false;
// While the set-up form is open the device page must not refresh itself, or what was typed would vanish
export function isMonitorFormOpen() {
  return formOpen;
}

// Health monitoring of one device: how it is read (SNMP or SSH), what it answers, and the form to set it up.
export async function buildDeviceMonitorCard(device, { onChange = null } = {}) {
  formOpen = false;
  const card = h("div", { class: "card admin-only monitor-card" });
  let info = null;

  async function load() {
    info = await get(`/api/devices/${device.id}/monitor`);
    draw();
  }

  function groupsText(groups) {
    const titles = info.groups || {};
    return groups.map((g) => titles[g] || g).join(", ");
  }

  function draw() {
    formOpen = false;
    clear(card);
    card.appendChild(h("h2", {}, "Health monitoring"));
    const m = info.monitor;
    if (!m) {
      card.append(
        h("p", { class: "hint" }, "Read this device's processor, memory, disks, network traffic, temperature and UPS battery now and then, draw graphs and warn when something runs out. Nothing is installed on the device: Netlens asks over SNMP (switches, NAS, printers, UPS, Windows with the SNMP service) or SSH (Linux)."),
        h("button", { class: "btn primary", type: "button", onclick: () => showForm(null) }, "Set up health monitoring"));
      return;
    }
    const status = h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Status"),
      m.last_ok === null ? h("span", { class: "hint" }, "waiting for the first reading")
        : m.last_ok ? h("span", {}, `Reading works (${timeAgo(m.last_ts)})`) : h("span", { class: "error" }, m.last_error || "The last reading failed"));
    card.append(
      status,
      h("div", { class: "kv" }, h("span", { class: "kv-label" }, "How"), h("span", {}, `${m.method.toUpperCase()} to ${m.address}:${m.port}, ${INTERVALS.find(([s]) => s === m.interval_s)?.[1] || `every ${m.interval_s} seconds`}`)),
      h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Reads"), h("span", {}, m.groups.length ? groupsText(m.groups) : "not known yet")),
      h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Warnings"), h("span", {}, m.alerts ? "on (limits are in Monitoring → Health)" : "off")),
      m.secret_unreadable ? h("p", { class: "error" }, "The stored login cannot be read (the encryption key is missing). Edit it and enter the login again.") : null);
    const bad = (info.state || []).filter((s) => s.level !== "ok");
    for (const s of bad) card.appendChild(h("p", { class: s.level === "critical" ? "error" : "hint" }, `${s.level === "critical" ? "Critical" : "Warning"}: ${NAMES[s.metric] || s.metric}${s.label ? ` (${s.label})` : ""} is ${Math.round(s.value * 10) / 10}`));
    const run = h("button", { class: "btn", type: "button" }, "Read now");
    run.addEventListener("click", async () => {
      run.disabled = true;
      try {
        const r = await post(`/api/devices/${device.id}/monitor/run`, {});
        toast(r.ok ? `Read ${r.points} values` : r.error, r.ok ? "success" : "error");
      } catch (err) {
        toast(err.message || "Could not read", "error");
      }
      await load();
    });
    const remove = h("button", { class: "btn danger", type: "button" }, "Remove");
    remove.addEventListener("click", async () => {
      if (!window.confirm("Stop reading this device's health? The graphs already recorded stay.")) return;
      try { await del(`/api/devices/${device.id}/monitor`); toast("Health monitoring removed", "success"); } catch (err) { toast(err.message || "Could not remove", "error"); }
      await load();
    });
    card.append(limitsBox(), h("div", { class: "form-actions" }, run, h("button", { class: "btn", type: "button", onclick: () => showForm(m) }, "Edit"), remove));
  }

  // The limits of this device alone: empty boxes follow the general limits (Monitoring -> Health)
  const LIMIT_ROWS = [["cpu_pct", "Processor busy (%)"], ["mem_pct", "Memory in use (%)"], ["disk_pct", "Disk full (%)"], ["temp_c", "Temperature (°C)"],
    ["supply_pct", "Supply left (%)"], ["battery_pct", "UPS battery (%)"], ["if_util_pct", "Port busy (%)"], ["if_err_ps", "Port errors (per second)"]];
  function limitsBox() {
    const box = h("details", { class: "limits-box" }, h("summary", {}, "Limits for this device"));
    box.addEventListener("toggle", async () => {
      if (!box.open || box.dataset.ready) return;
      box.dataset.ready = "1";
      let data;
      try {
        data = await get(`/api/devices/${device.id}/limits`);
      } catch (err) {
        box.appendChild(h("p", { class: "error" }, "The limits could not be loaded"));
        return;
      }
      const table = h("div", { class: "limits-table" }, h("span", { class: "limits-head" }, ""), h("span", { class: "limits-head" }, "Warn at"), h("span", { class: "limits-head" }, "Critical at"));
      const inputs = {};
      for (const [metric, title] of LIMIT_ROWS) {
        const mine = data.overrides[metric] || {};
        const base = data.general[metric] || {};
        const warn = h("input", { type: "number", step: "any", placeholder: base.warn == null ? "" : String(base.warn), value: mine.warn == null ? "" : String(mine.warn) });
        const crit = h("input", { type: "number", step: "any", placeholder: base.crit == null ? "" : String(base.crit), value: mine.crit == null ? "" : String(mine.crit) });
        inputs[metric] = { warn, crit };
        table.append(h("span", {}, title), warn, crit);
      }
      const save = h("button", { class: "btn primary", type: "button" }, "Save");
      save.addEventListener("click", async () => {
        const rules = {};
        for (const [metric, f] of Object.entries(inputs)) {
          const item = {};
          if (f.warn.value !== "") item.warn = Number(f.warn.value);
          if (f.crit.value !== "") item.crit = Number(f.crit.value);
          if (Object.keys(item).length) rules[metric] = item;
        }
        try {
          await put(`/api/devices/${device.id}/limits`, { rules });
          toast(Object.keys(rules).length ? "Limits for this device saved" : "This device follows the general limits", "success");
          if (onChange) onChange();
        } catch (err) {
          toast(err.message || "Could not save the limits", "error");
        }
      });
      box.append(h("p", { class: "hint" }, "Leave a box empty to use the general limit shown in grey. Changes apply to the warnings and to the lines in the graphs."), table, h("div", { class: "form-actions" }, save));
    });
    return box;
  }

  function showForm(m) {
    formOpen = true;
    clear(card);
    card.appendChild(h("h2", {}, "Health monitoring"));
    const method = h("select", { name: "method" }, h("option", { value: "snmp" }, "SNMP (switch, NAS, printer, UPS, Windows ...)"), h("option", { value: "ssh" }, "SSH (Linux, or Windows with OpenSSH)"), h("option", { value: "winrm" }, "WinRM (Windows, built in)"));
    const hasPort = (n) => (device.ports || []).some((p) => p.port === n && (!p.state || p.state === "open"));
    method.value = m ? m.method : hasPort(5986) || hasPort(5985) ? "winrm" : hasPort(22) ? "ssh" : "snmp";
    const address = h("input", { type: "text", name: "address", value: m ? m.address : device.primary_ip || "", required: true });
    const port = h("input", { type: "number", min: "1", max: "65535", placeholder: PORTS[method.value], value: m ? String(m.port) : "" });
    const community = h("input", { type: "password", autocomplete: "off", placeholder: m && m.has_community ? "(kept, type to change)" : "public" });
    const version = h("select", {}, h("option", { value: "2c" }, "2c (normal)"), h("option", { value: "3" }, "3 (user name and passwords, more secure)"), h("option", { value: "1" }, "1 (old devices)"));
    version.value = m && m.version ? m.version : "2c";
    const v3user = h("input", { type: "text", autocomplete: "off", value: m && m.version === "3" && m.username ? m.username : "" });
    const authProto = h("select", {}, h("option", { value: "" }, "none"), ...["SHA", "SHA256", "SHA512", "MD5"].map((p) => h("option", { value: p }, p)));
    authProto.value = m && m.auth_proto ? m.auth_proto : "SHA";
    const authPw = h("input", { type: "password", autocomplete: "new-password", placeholder: m && m.has_auth_password ? "(kept, type to change)" : "at least 8 characters" });
    const privProto = h("select", {}, h("option", { value: "" }, "none (not encrypted)"), h("option", { value: "AES" }, "AES"), h("option", { value: "DES" }, "DES (old devices)"));
    privProto.value = m && m.priv_proto ? m.priv_proto : "AES";
    const privPw = h("input", { type: "password", autocomplete: "new-password", placeholder: m && m.has_priv_password ? "(kept, type to change)" : "at least 8 characters" });
    const username = h("input", { type: "text", autocomplete: "off", value: m && m.username ? m.username : "" });
    const password = h("input", { type: "password", autocomplete: "new-password", placeholder: m && m.has_password ? "(kept, type to change)" : "" });
    const platform = h("select", {}, h("option", { value: "auto" }, "Detect automatically"), h("option", { value: "linux" }, "Linux / Unix"), h("option", { value: "windows" }, "Windows"));
    platform.value = m && m.platform ? m.platform : "auto";
    const wUser = h("input", { type: "text", autocomplete: "off", value: m && m.method === "winrm" && m.username ? m.username : "" });
    const wPass = h("input", { type: "password", autocomplete: "new-password", placeholder: m && m.method === "winrm" && m.has_password ? "(kept, type to change)" : "" });
    const wAuth = h("select", {}, h("option", { value: "ntlm" }, "NTLM (default; local and domain users)"), h("option", { value: "basic" }, "Basic (only when you turned it on in WinRM)"));
    wAuth.value = m && m.auth ? m.auth : "ntlm";
    const wVerify = h("input", { type: "checkbox" });
    wVerify.checked = !!(m && m.verify_tls);
    const key = h("textarea", { rows: "3", placeholder: m && m.has_private_key ? "(kept, paste to change)" : "-----BEGIN OPENSSH PRIVATE KEY-----", spellcheck: "false" });
    const interval = h("select", {}, INTERVALS.map(([s, t]) => h("option", { value: String(s) }, t)));
    interval.value = String(m ? m.interval_s : 60);
    const alerts = h("input", { type: "checkbox" });
    alerts.checked = m ? m.alerts : true;
    const communityField = field("Community", community, "The read community string set on the device. Many devices use “public”. Read-only access is all that is needed.");
    const v3Box = h("div", {}, field("SNMPv3 user name", v3user, "A read-only user created on the device."), field("Authentication", authProto), field("Authentication password", authPw),
      field("Encryption", privProto), field("Encryption password", privPw));
    const snmpBox = h("div", {}, field("SNMP version", version), communityField, v3Box);
    const sshBox = h("div", {}, field("User name", username, "An ordinary account is enough; nothing is changed on the host."), field("Password", password), field("Private key (instead of a password)", key),
      field("System", platform, "Windows needs the OpenSSH server (Settings → Optional features) and a user that may read performance data. Nothing is installed."));
    const winBox = h("div", {},
      field("User name", wUser, "A Windows account in the group Remote Management Users (a domain user is DOMAIN\\name). It only reads."),
      field("Password", wPass), field("Login method", wAuth),
      h("label", {}, wVerify, " Verify the TLS certificate (leave off for the self-signed one WinRM makes)"),
      h("details", {}, h("summary", {}, "How to switch WinRM over HTTPS on"), h("pre", { class: "remote-code" },
        "# PowerShell as administrator on the Windows computer\nEnable-PSRemoting -Force -SkipNetworkProfileCheck\n$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\\LocalMachine\\My -NotAfter (Get-Date).AddYears(10)\nNew-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force\nNew-NetFirewallRule -DisplayName 'Netlens WinRM HTTPS' -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow\n# let 'Remote Management Users' open a shell (WinRM only lets administrators in by default)\n$sddl = (Get-Item WSMan:\\localhost\\Service\\RootSDDL).Value\nif ($sddl -notmatch ';;;RM\\)') { $dacl, $sacl = $sddl -split 'S:', 2; Set-Item WSMan:\\localhost\\Service\\RootSDDL -Value ($dacl + '(A;;GXGR;;;RM)S:' + $sacl) -Force }\nRestart-Service WinRM -Force")));
    const result = h("div", { class: "monitor-result" });
    const show = () => {
      snmpBox.hidden = method.value !== "snmp"; sshBox.hidden = method.value !== "ssh"; winBox.hidden = method.value !== "winrm"; port.placeholder = PORTS[method.value];
      communityField.hidden = version.value === "3"; v3Box.hidden = version.value !== "3";
    };
    method.addEventListener("change", show);
    version.addEventListener("change", show);
    show();

    const body = () => {
      const out = { method: method.value, address: address.value.trim(), interval_s: Number(interval.value), alerts: alerts.checked };
      if (port.value) out.port = Number(port.value);
      if (method.value === "winrm") {
        out.username = wUser.value.trim();
        out.auth = wAuth.value;
        out.verify_tls = wVerify.checked;
        if (wPass.value) out.password = wPass.value;
      } else if (method.value === "snmp") {
        out.version = version.value;
        if (version.value === "3") {
          out.username = v3user.value.trim();
          out.auth_proto = authProto.value;
          out.priv_proto = authProto.value ? privProto.value : "";
          if (authPw.value) out.auth_password = authPw.value;
          if (privPw.value) out.priv_password = privPw.value;
        } else if (community.value) {
          out.community = community.value;
        }
      } else {
        out.username = username.value.trim();
        out.platform = platform.value;
        if (password.value) out.password = password.value;
        if (key.value.trim()) out.private_key = key.value.trim();
      }
      return out;
    };

    const test = h("button", { class: "btn", type: "button" }, "Test");
    test.addEventListener("click", async () => {
      test.disabled = true;
      clear(result);
      result.appendChild(h("p", { class: "hint" }, "Reading… (a few seconds)"));
      try {
        const r = await post(`/api/devices/${device.id}/monitor/test`, body());
        clear(result);
        if (!r.ok) {
          result.appendChild(h("p", { class: "error" }, r.error));
        } else {
          result.appendChild(h("p", {}, `It works. Found: ${r.found_titles.join(", ")}.`));
          if (r.new_host_key) result.appendChild(h("p", { class: "hint" }, `The host key (${r.fingerprint}) will be remembered the first time it is read, like for the web terminal.`));
          const list = h("div", { class: "monitor-values" });
          for (const v of r.values.slice(0, 18)) list.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, `${NAMES[v.metric] || v.metric}${v.label ? ` · ${v.label}` : ""}`), h("span", {}, fmtValue(v))));
          result.appendChild(list);
        }
      } catch (err) {
        clear(result);
        result.appendChild(h("p", { class: "error" }, err.message || "The test failed"));
      }
      test.disabled = false;
    });
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        await put(`/api/devices/${device.id}/monitor`, body());
        toast("Saved. The first reading follows in a moment.", "success");
        try { await post(`/api/devices/${device.id}/monitor/run`, {}); } catch (err) { /* the status line shows what went wrong */ }
        formOpen = false;
        if (onChange) onChange();      // redraw the page so the graphs appear straight away
        else await load();
      } catch (err) {
        toast(err.message || "Could not save", "error");
        save.disabled = false;
      }
    });
    const form = h("form", { class: "edit-form", onsubmit: (e) => e.preventDefault() },
      field("How to ask", method), field("Address", address, "Where to ask. It is the device's address unless it has a separate management address."),
      field("Port", port, "Leave empty for the usual one (5986 is WinRM over https; 5985 is plain http, only on your own network)."), snmpBox, sshBox, winBox, field("How often", interval),
      h("label", {}, alerts, " Warn me when a value gets too high or too low (limits under Monitoring → Health)"),
      h("div", { class: "form-actions" }, test, save, h("button", { class: "btn", type: "button", onclick: () => draw() }, "Cancel")), result);
    card.appendChild(form);
  }

  await load();
  return card;
}
