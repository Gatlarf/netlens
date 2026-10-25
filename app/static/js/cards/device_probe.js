import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const GB = 1024 ** 3;
const size = (n) => (n >= GB ? `${(n / GB).toFixed(1)} GB` : n >= 1024 ** 2 ? `${Math.round(n / 1024 ** 2)} MB` : `${Math.round(n / 1024)} kB`);
const mbit = (n) => `${(n / 1e6).toFixed(1)} Mbit/s`;
const SOURCES = [["static", "The login of the health monitor"], ["netlens_ca", "A certificate from the Netlens CA (valid for minutes)"], ["vault_ssh", "A certificate from Vault / OpenBao"]];
const INTERVALS = [[1, "every hour"], [3, "every 3 hours"], [6, "every 6 hours"], [12, "every 12 hours"], [24, "every day"]];
const SYMPTOMS = ["It is slow", "It ran out of memory", "Network timeouts", "A service keeps restarting", "The disk is full", "It restarted by itself", "Something changed"];
const clock = (t) => (t ? new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "");

function table(rows, head) {
  if (!rows.length) return null;
  return h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, head.map((t) => h("th", {}, t)))), h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c)))))));
}

// What each probe saw, as small tables next to the findings
const DETAILS = {
  storage: (d) => d.mounts.slice(0, 3).flatMap((m) => [h("h3", {}, `${m.mount}${m.size ? ` ${Math.round((100 * m.used) / m.size)}% full (${size(m.used)} of ${size(m.size)})` : ""}`),
    table(m.dirs.filter((x) => x.path !== m.mount).slice(0, 8).map((x) => [x.path, size(x.bytes)]), ["Folder", "Size"]),
    m.files.length ? h("p", { class: "hint" }, "Big files: " + m.files.slice(0, 4).map((f) => `${f.path} (${size(f.bytes)})`).join(", ")) : null]),
  cpu: (d) => [table(d.procs.slice(0, 8).map((p) => [p.container ? `${p.name} (${p.container})` : p.name, `${p.cpu.toFixed(0)}%`]), ["Process", "Processor (100% = one core)"]),
    d.load && d.load.length ? h("p", { class: "hint" }, `Load ${d.load.join(" / ")} on ${d.cpus || "?"} cores`) : null],
  memory: (d) => [h("p", { class: "hint" }, d.total ? `${d.used_pct}% of ${size(d.total)} used; swap ${size(d.swap_used)} of ${size(d.swap_total)}` : ""),
    table(d.procs.slice(0, 8).map((p) => [p.container ? `${p.name} (${p.container})` : p.name, size(p.rss)]), ["Process", "Memory"]),
    d.oom && d.oom.length ? h("p", { class: "error" }, `The kernel killed processes for lack of memory: ${d.oom.length} time(s)`) : null],
  network: (d) => [table(d.interfaces.slice(0, 6).map((n) => [n.name, mbit(n.rx_bps), mbit(n.tx_bps), `${n.rx_err_total + n.tx_err_total}`]), ["Interface", "In", "Out", "Errors (total)"]),
    d.remote.length ? h("p", { class: "hint" }, "Most connections from: " + d.remote.slice(0, 4).map((r) => `${r.ip} (${r.count})`).join(", ")) : null,
    d.ping.length ? h("p", { class: "hint" }, d.ping.map((p) => `${p.kind}: ${p.loss}% loss${p.rtt ? `, ${p.rtt} ms` : ""}`).join("; ") + (d.dns ? `; DNS ${d.dns.ok ? d.dns.ms + " ms" : "fails"}` : "")) : null],
  apps: (d) => [table(d.containers.slice(0, 12).map((c) => [c.name, c.state, c.restarts, c.health || "", c.oom ? "out of memory" : c.exit ? `exit ${c.exit}` : ""]), ["Container", "State", "Restarts", "Health", "Last end"]),
    d.failed_units.length ? h("p", { class: "error" }, "Failed services: " + d.failed_units.map((u) => u.unit).join(", ")) : null,
    d.errors.length ? h("p", { class: "hint" }, "Errors in the log (1 h): " + d.errors.slice(0, 5).map((e) => `${e.unit} ${e.count}`).join(", ")) : null],
  changes: (d) => [table(d.events.slice(0, 12).map((e) => [clock(e.at), e.text]), ["When", "What changed"])],
  schedule: (d) => [table(d.jobs.filter((j) => j.last).sort((a, b) => b.last - a.last).slice(0, 12).map((j) => [j.name, clock(j.last), clock(j.next)]), ["Job", "Last ran", "Next"]),
    d.runs.length ? h("p", { class: "hint" }, `${d.runs.length} cron runs in the last day`) : null],
  hardware: (d) => [table(d.disks.map((x) => [x.dev, x.health, x.detail]), ["Disk", "Health", "Details"]),
    d.raid.length ? h("p", { class: d.raid.some((r) => r.degraded) ? "error" : "hint" }, d.raid.map((r) => `${r.name}: ${r.detail}`).join("; ")) : null,
    d.errors.length ? h("p", { class: "error" }, `${d.errors.length} hardware or disk errors in the kernel log`) : null],
  security: (d) => [d.failed.length ? h("p", { class: "hint" }, `${d.failed_total} failed sign-ins in 24 h, most from ` + d.failed.slice(0, 3).map((f) => `${f.ip} (${f.count})`).join(", ")) : null,
    d.updates && (d.updates.pending || d.updates.security) ? h("p", { class: "hint" }, `${d.updates.pending} updates waiting, ${d.updates.security} for security`) : null],
};

// Host probes: read-only looks at a host (storage, processor, memory, network, applications, changes, scheduled jobs, hardware, security) and the digital engineer that chains them into a cause.
// True while someone is typing in this card or a diagnosis/install is running: the device page must not rebuild itself then
export function isProbeBusy() {
  return [...document.querySelectorAll(".probe-card")].some((c) => c.dataset.dirty === "1" || c.dataset.working === "1" || (c.contains(document.activeElement) && /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)));
}

// mode "health": what the probes found (device page, Health). mode "setup": the settings and the install of the probe on the host (Settings → Host probes).
export async function buildDeviceProbeCard(device, mode = "health") {
  const setup = mode === "setup";
  const card = h("div", { class: "card admin-only probe-card" });
  for (const ev of ["input", "change"]) card.addEventListener(ev, () => { card.dataset.dirty = "1"; });
  let info = null;
  let open = "diagnosis";

  async function load() {
    info = await get(`/api/devices/${device.id}/hostprobe`);
    draw();
  }

  function findingsList(items) {
    return h("ul", { class: "plain" }, items.map((f) => h("li", { class: f.level === "cause" || f.level === "warn" ? "warn-text" : "" }, f.text, f.unusual ? h("span", { class: "badge", style: "margin-left:.4rem" }, "different from normal") : null)));
  }

  // The report that was kept under an id: other systems fetch it with that id; people can have it mailed
  function reportBox(r) {
    if (!r.report_id) return null;
    const open = h("a", { class: "btn", href: `/api/analysis/${r.report_id}/html`, target: "_blank", rel: "noopener" }, "Open the report");
    const send = h("button", { class: "btn", type: "button" }, "Send it by e-mail / alert channels");
    send.addEventListener("click", async () => {
      send.disabled = true;
      try { const x = await post(`/api/analysis/${r.report_id}/send`, {}); toast(x.sent.length ? `Sent through ${x.sent.join(", ")}` : "Not sent", x.sent.length ? "success" : "error"); if (x.failed.length) toast(x.failed.map((f) => `${f.channel}: ${f.error}`).join("; "), "error"); } catch (err) { toast(err.message || "Could not send", "error"); }
      send.disabled = false;
    });
    return h("div", {}, h("p", { class: "hint" }, `Report ${r.report_ref}. Other systems fetch it with this id (GET /api/analysis/${r.report_id}, or the assistant tool get_analysis_report).`), h("div", { class: "form-actions" }, open, send));
  }

  function diagnosisBox() {
    const box = h("div", { class: "field" });
    const symptom = h("input", { type: "text", list: `symptoms-${device.id}`, placeholder: "What is wrong? (or leave empty)", style: "max-width: 28rem" });
    const list = h("datalist", { id: `symptoms-${device.id}` }, SYMPTOMS.map((t) => h("option", { value: t })));
    const out = h("div", {});
    async function ask(live) {
      card.dataset.working = "1"; card.dataset.dirty = "0";
      out.replaceChildren(h("p", { class: "hint" }, live ? "Looking at the host… (up to a minute or two)" : "Thinking…"));
      try {
        const r = await post(`/api/devices/${device.id}/hostprobe/diagnose`, { symptom: symptom.value, live });
        show(out, r);
        if (live) { info = await get(`/api/devices/${device.id}/hostprobe`); }
      } catch (err) { out.replaceChildren(h("p", { class: "error" }, err.message || "Could not diagnose")); }
      finally { card.dataset.working = "0"; }
    }
    const live = h("button", { class: "btn primary", type: "button", onclick: () => ask(true) }, "Diagnose now");
    const snap = h("button", { class: "btn", type: "button", onclick: () => ask(false) }, "From the latest looks");
    box.append(h("label", {}, "Find the cause"), h("div", { class: "form-actions" }, symptom, list, live, snap),
      h("p", { class: "hint" }, "The engineer picks the probes the problem calls for, looks at the host (read-only, every look is in the audit log) and chains what it finds."), out);
    if (info.diagnosis && info.diagnosis.findings.length) show(out, info.diagnosis);
    return box;
  }

  function show(out, r) {
    out.replaceChildren();
    if (r.ran) out.appendChild(h("p", { class: "hint" }, "Looked at: " + Object.entries(r.ran).map(([p, x]) => `${p}${x.ok ? "" : " (failed: " + x.error + ")"}`).join(", ")));
    if (!r.findings.length) { out.appendChild(h("p", { class: "hint" }, r.missing && r.missing.length ? `No look yet at: ${r.missing.join(", ")}. Press "Diagnose now".` : "Nothing unusual was found.")); return; }
    for (const c of (r.chains || []).slice(0, 2)) out.appendChild(h("p", { class: "error" }, h("strong", {}, "Probable cause: "), c.text));
    out.appendChild(findingsList(r.findings.filter((f) => !f.text.startsWith("Probable cause: ") || !(r.chains || []).length)));
    const rb = reportBox(r);
    if (rb) out.appendChild(rb);
    if (r.missing && r.missing.length) out.appendChild(h("p", { class: "hint" }, `Not looked at yet: ${r.missing.join(", ")}.`));
  }

  async function probeView(name) {
    const box = h("div", {}, h("p", { class: "hint" }, "Loading…"));
    try {
      const r = await get(`/api/devices/${device.id}/hostprobe/${name}`);
      box.replaceChildren();
      if (!r.latest) { box.appendChild(h("p", { class: "hint" }, "No look yet.")); } else {
        box.appendChild(h("p", { class: "hint" }, `Looked ${timeAgo(r.latest.taken)} (${r.latest.mode === "locked" ? "locked-down script" : "script sent directly"}).`));
        if (r.findings.length) box.appendChild(findingsList(r.findings));
        for (const part of (DETAILS[name] ? DETAILS[name](r.latest.data) : [])) if (part) box.appendChild(part);
      }
      const run = h("button", { class: "btn", type: "button" }, "Look now");
      run.addEventListener("click", async () => {
        run.disabled = true; run.textContent = "Looking…";
        try { info = await post(`/api/devices/${device.id}/hostprobe/run?probe=${name}`, {}); toast(info.ok ? "Done" : info.error, info.ok ? "success" : "error"); } catch (err) { toast(err.message || "Could not look", "error"); }
        draw();
      });
      box.appendChild(h("div", { class: "form-actions" }, run));
    } catch (err) { box.replaceChildren(h("p", { class: "error" }, err.message || "Could not load")); }
    return box;
  }

  // Put the probe on the host, or update or remove it, with an administrator login that is used once and not stored
  function installBox() {
    const label = info.installed_version ? (info.update_available ? `The script on the host is version ${info.installed_version}; this Netlens has ${info.script_version}. Update it.` : `The script on the host is up to date (version ${info.installed_version}).`) : "Install the probe on the host so that it can run nothing else (recommended), or let Netlens send the script each time.";
    const box = h("details", { class: "limits-box" }, h("summary", {}, info.update_available ? "Install or update on the host ⚠" : "Install or update on the host"));
    const user = h("input", { type: "text", placeholder: "administrator account", autocomplete: "off", value: info.monitor_user || "" });
    const pass = h("input", { type: "password", placeholder: "password (also used for sudo)", autocomplete: "new-password" });
    const key = h("textarea", { rows: 3, placeholder: "or a private key (optional)", class: "mono" });
    const sshd = h("input", { type: "checkbox" });
    const out = h("div", {});
    async function go(action) {
      card.dataset.working = "1";
      out.replaceChildren(h("p", { class: "hint" }, action === "check" ? "Checking…" : "Working… (a few seconds)"));
      try {
        const r = await post(`/api/devices/${device.id}/hostprobe/install`, { action, username: user.value, password: pass.value, private_key: key.value, enable_sshd: sshd.checked });
        pass.value = ""; key.value = "";
        out.replaceChildren(h("ul", { class: "plain" }, r.log.map((l) => h("li", { class: l.startsWith("Error") ? "error" : "" }, l))),
          r.error ? h("p", { class: "error" }, r.error) : null,
          r.verified ? h("p", { class: r.verified.ok ? "hint" : "error" }, r.verified.ok ? `Verified: Netlens logged in as the probe account with a one-time certificate and ran a probe (script version ${r.verified.script_version}).` : `The install worked but the check failed: ${r.verified.error}`) : null,
          r.created_ca ? h("p", { class: "hint" }, "The Netlens certificate authority was created for this.") : null);
        if (r.probes) info = r;                                   // keep the log on screen: no redraw
      } catch (err) { out.replaceChildren(h("p", { class: "error" }, err.message || "Failed")); }
      finally { card.dataset.working = "0"; card.dataset.dirty = "0"; }
    }
    const buttons = [["check", "Check (changes nothing)", ""], ["install", info.installed_version ? "Install / update" : "Install", " primary"], ["remove", "Remove from the host", " danger"]];
    box.append(h("p", { class: "hint" }, label), h("p", { class: "hint" }, "Needs an administrator login on the host once. It is used for this action only: never stored, never logged. Netlens backs up and tests the SSH server configuration before it takes effect, and puts the old one back if the test fails."),
      h("div", { class: "field" }, h("label", {}, "Administrator account"), user), h("div", { class: "field" }, h("label", {}, "Password"), pass), h("div", { class: "field" }, h("label", {}, "Private key"), key),
      h("div", { class: "field" }, h("label", { class: "check-row" }, sshd, " Windows: also install the OpenSSH server if it is missing"), h("p", { class: "hint" }, "The locked-down probe needs it. Netlens then lets only the probe account sign in (with one-time certificates, no passwords) and only this Netlens reach port 22. Without it, a Windows host monitored over WinRM keeps running the probes with its stored login.")),
      h("div", { class: "form-actions" }, buttons.map(([a, t, c]) => h("button", { class: `btn${c}`, type: "button", onclick: () => { if (a === "remove" && !window.confirm("Remove the probe, its sudo rule and the Netlens CA key from the host?")) return; go(a); } }, t))), out);
    box.open = true;
    return box;
  }

  function draw() {
    clear(card);
    if (!setup) card.appendChild(h("h2", {}, "Host probes"));
    if (!setup) card.appendChild(h("p", { class: "hint" }, "Information only: the probes read and report. Netlens never changes anything on the host with them. What to do about a finding is for you, or for an automation system that has the right to change things and fetches the analysis by its id."));
    if (!info.monitor || !["ssh", "winrm"].includes(info.monitor)) {
      if (setup) card.appendChild(h("p", { class: "hint" }, "This device has no health monitoring over SSH or WinRM yet. Add it on the device page (Health): that supplies the address and the login."));
      else card.appendChild(h("p", { class: "hint" }, "Read-only looks at this host (what uses the processor, memory, disk and network, which applications fail, what changed, what was scheduled, hardware and security) and an engineer that chains them into a cause. It needs health monitoring over SSH or WinRM first (the card above): that supplies the address and the login."));
      return;
    }
    const cfg = info.config;
    const on = h("input", { type: "checkbox", checked: cfg.enabled });
    const every = h("select", {}, INTERVALS.map(([v, t]) => h("option", { value: v, selected: v === cfg.interval_h }, t)));
    const source = h("select", {}, SOURCES.map(([v, t]) => h("option", { value: v, selected: v === cfg.provider }, t)));
    const user = h("input", { type: "text", value: cfg.username, placeholder: "netlens-ro", autocomplete: "off" });
    const boxes = Object.entries(info.probes).map(([name, p]) => h("label", { class: "check-row" }, h("input", { type: "checkbox", "data-probe": name, checked: cfg.probes.includes(name) }), " ", p.title));
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      try {
        info = await put(`/api/devices/${device.id}/hostprobe`, { enabled: on.checked, interval_h: Number(every.value), provider: source.value, username: user.value,
          probes: boxes.map((l) => l.firstChild).filter((i) => i.checked).map((i) => i.dataset.probe) });
        toast("Saved", "success"); card.dataset.dirty = "0"; draw();
      } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    const settings = h("div", { class: "limits-box" }, h("p", { class: "hint" }, cfg.enabled ? "Probing is on for this host." : "Probing is off for this host."),
      h("div", { class: "field" }, h("label", { class: "check-row" }, on, " Look at this host now and then, and at once when a reading goes over its limit")),
      h("div", { class: "field" }, h("label", {}, "Which probes"), h("div", { class: "event-boxes" }, boxes)),
      h("div", { class: "field" }, h("label", {}, "Storage is looked at"), every, h("p", { class: "hint" }, "The other probes once a day, and at once when a reading goes over its limit (memory pressure looks at memory and applications, for example).")),
      h("div", { class: "field" }, h("label", {}, "Log in with"), source, h("p", { class: "hint" }, "A certificate is made for each look and stops working after a few minutes; the host only has to trust the Netlens CA. Set it up under Settings → Host probes.")),
      h("div", { class: "field" }, h("label", {}, "User name on the host (certificates)"), user), h("div", { class: "form-actions" }, save));
    if (setup) { card.appendChild(settings); card.appendChild(installBox()); return; }
    if (!cfg.enabled) { card.appendChild(h("p", { class: "hint" }, "Probing is off for this host. Turn it on under Settings → Host probes → Hosts.")); return; }
    card.appendChild(diagnosisBox());
    for (const u of info.hidden || []) card.appendChild(h("p", { class: "error" }, u.text + "."));
    const stale = Object.values(info.probes).some((p) => p.mode === "locked") && info.latest && info.latest.data && info.latest.data.script_version && info.latest.data.script_version < info.script_version;
    if (stale) card.appendChild(h("p", { class: "hint" }, "The script installed on the host is older than this Netlens expects. Install the new one: Settings → Host probes → Prepare a host."));
    const tabs = h("div", { class: "btn-row" }, Object.entries(info.probes).map(([name, p]) => {
      const b = h("button", { class: `btn${open === name ? " primary" : ""}`, type: "button", title: p.error ? `Last try failed: ${p.error}` : p.taken ? `Looked ${timeAgo(p.taken)}` : "Not looked at yet" }, p.title + (p.error ? " ⚠" : ""));
      b.addEventListener("click", () => { open = open === name ? "diagnosis" : name; draw(); });
      return b;
    }));
    card.appendChild(tabs);
    if (open !== "diagnosis") probeView(open).then((v) => card.appendChild(v));
  }

  try { await load(); } catch (err) { card.appendChild(h("p", { class: "error" }, err.message || "Could not load")); }
  return card;
}
