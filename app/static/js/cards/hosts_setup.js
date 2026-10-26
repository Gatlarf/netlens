import { get, post } from "../api.js";
import { h, clear, toast, timeAgo, statusDot } from "../util.js";

const LEVELS = [
  ["basic", "Basic monitoring (processor, memory, disks, network, services)", false],
  ["probes", "Basic monitoring + read-only probes (the digital engineer)", true],
  ["update", "Update the probe script on hosts that have an older one", true],
  ["unprobe", "Take the probes off, keep the basic monitoring", true],
  ["remove", "Remove everything: the probes and the monitoring", true],
];

// Settings → Hosts: choose hosts, choose what they get, apply to all at once.
export async function buildHostsSetupCard() {
  const card = h("div", { class: "card admin-only" });
  let data = await get("/api/hosts");
  let logins = (await get("/api/credentials")).credentials;
  const chosen = new Set();
  let filter = "";
  let results = null;
  let busy = false;
  const form = { level: "basic", credential: "", adminCredential: "", adminUser: "", adminPass: "", sshd: false };

  const reach = (x) => (x.can_monitor ? x.can_monitor.toUpperCase() : "–");
  const monText = (x) => {
    if (!x.monitor) return h("span", { class: "hint" }, "not monitored");
    if (x.monitor.other) return h("span", { class: "hint" }, `monitored over ${x.monitor.method.toUpperCase()}`);
    const state = x.monitor.ok === false ? h("span", { class: "error", title: x.monitor.error || "" }, "cannot log in") : x.monitor.ok ? "working" : "waiting";
    return h("span", {}, state, " ", h("span", { class: "hint" }, x.monitor.via === "locked" ? " via the locked-down probe account (one-time certificates)" : `${x.monitor.method.toUpperCase()}${x.monitor.login ? ` · stored login ${x.monitor.login}` : ""}`));
  };
  const probeText = (x) => {
    const p = x.probes;
    if (!p.enabled && !p.installed_version) return h("span", { class: "hint" }, "off");
    return h("span", {}, p.installed_version ? `script v${p.installed_version}` : p.mode === "direct" ? "direct (no script on the host)" : "on", p.update_available ? h("span", { class: "tag unknown-tag", style: "margin-left:.4rem" }, "update") : null,
      p.last ? h("span", { class: "hint" }, ` · looked ${timeAgo(p.last)}`) : null);
  };

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Hosts"));
    card.appendChild(h("p", { class: "hint" }, "Set up or remove the monitoring of many hosts in one go. Basic monitoring reads the usual figures with a login from Settings → Credentials. " +
      "The probes are read-only looks for finding causes: they are put on the host with an administrator login that is used once and never stored. Nothing is changed on a host by the probes themselves."));

    const q = filter.trim().toLowerCase();
    const shown = data.hosts.filter((x) => !q || `${x.name} ${x.ip}`.toLowerCase().includes(q));
    const search = h("input", { type: "search", placeholder: "Filter hosts", value: filter });
    search.addEventListener("input", () => { filter = search.value; draw(); const s = card.querySelector('input[type="search"]'); if (s) { s.focus(); s.setSelectionRange(s.value.length, s.value.length); } });
    const all = h("input", { type: "checkbox", checked: shown.length > 0 && shown.every((x) => chosen.has(x.id)) });
    all.addEventListener("change", () => { for (const x of shown) (all.checked ? chosen.add(x.id) : chosen.delete(x.id)); draw(); });
    const pickOnly = (label, test) => h("button", { class: "btn linklike", type: "button", onclick: () => { chosen.clear(); for (const x of data.hosts.filter(test)) chosen.add(x.id); draw(); } }, label);
    card.appendChild(h("div", { class: "toolbar" }, search, " Select: ", pickOnly("not monitored", (x) => !x.monitor && x.can_monitor), pickOnly("monitored", (x) => x.monitor && !x.monitor.other),
      pickOnly("with an old probe", (x) => x.probes.update_available), pickOnly("none", () => false)));

    const rows = shown.map((x) => {
      const box = h("input", { type: "checkbox", checked: chosen.has(x.id) });
      box.addEventListener("change", () => { box.checked ? chosen.add(x.id) : chosen.delete(x.id); draw(); });
      const result = results && results.find((r) => r.device_id === x.id);
      return h("tr", { class: result ? (result.ok ? "" : "hl-bad") : "" }, h("td", {}, box), h("td", {}, statusDot(x.online), " ", h("a", { href: `#/device/${x.id}` }, x.name), h("div", { class: "mono hint" }, x.ip)),
        h("td", {}, reach(x)), h("td", {}, monText(x)), h("td", {}, probeText(x)),
        h("td", {}, result ? h("strong", { class: result.ok ? "" : "error", title: result.error || result.steps.join("\n") }, result.ok ? "Done" : "Failed") : null));
    });
    card.appendChild(h("div", { class: "table-wrap" }, h("table", { class: "data" },
      h("thead", {}, h("tr", {}, h("th", {}, all), ["Host", "Reached over", "Basic monitoring", "Probes", "Result"].map((t) => h("th", {}, t)))), h("tbody", {}, rows))));

    // what they get
    const level = h("select", {}, LEVELS.map(([v, t]) => h("option", { value: v, selected: v === form.level }, t)));
    level.addEventListener("change", () => { form.level = level.value; draw(); });
    const needsMonitorLogin = form.level === "basic" || form.level === "probes";
    const needsAdmin = LEVELS.find((l) => l[0] === form.level)[2];
    const option = (list, value, none) => [h("option", { value: "" }, none), ...list.map((c) => h("option", { value: c.id, selected: c.id === value }, `${c.name}${c.username ? ` (${c.username})` : ""}`))];
    const lacking = data.hosts.filter((x) => chosen.has(x.id) && !x.monitor);
    const mon = h("select", {}, option(logins, form.credential, lacking.length ? "Choose a login…" : "Keep each host's own login"));
    mon.addEventListener("change", () => { form.credential = mon.value; });
    const adm = h("select", {}, option(logins, form.adminCredential, "Type an administrator login"));
    adm.addEventListener("change", () => { form.adminCredential = adm.value; draw(); });
    const aUser = h("input", { type: "text", autocomplete: "off", value: form.adminUser, placeholder: "administrator account" });
    const aPass = h("input", { type: "password", autocomplete: "new-password", value: form.adminPass, placeholder: "password (also used for sudo)" });
    aUser.addEventListener("input", () => { form.adminUser = aUser.value; });
    aPass.addEventListener("input", () => { form.adminPass = aPass.value; });
    const sshd = h("input", { type: "checkbox", checked: form.sshd });
    sshd.addEventListener("change", () => { form.sshd = sshd.checked; });

    const apply = h("button", { class: "btn primary", type: "button", disabled: busy || chosen.size === 0 }, busy ? "Working… (this can take a minute per host)" : `Apply to ${chosen.size} host${chosen.size === 1 ? "" : "s"}`);
    apply.addEventListener("click", async () => {
      if ((form.level === "basic" || form.level === "probes") && !form.credential && data.hosts.some((x) => chosen.has(x.id) && !x.monitor)) {
        toast(`${lacking.length} chosen host${lacking.length === 1 ? " has" : "s have"} no health monitor yet (${lacking.slice(0, 3).map((x) => x.name).join(", ")}${lacking.length > 3 ? ", …" : ""}): choose the login for the basic monitoring first`, "error");
        return;
      }
      if (form.level === "remove" && !window.confirm(`Remove the probes and the monitoring of ${chosen.size} host(s)?`)) return;
      busy = true; results = null; draw();
      try {
        const res = await post("/api/hosts/apply", { device_ids: [...chosen], level: form.level, credential_id: form.credential, admin_credential_id: form.adminCredential,
          admin_username: form.adminUser, admin_password: form.adminPass, enable_sshd: form.sshd });
        results = res.results;
        form.adminPass = "";
        toast(res.failed ? `${res.done} done, ${res.failed} failed` : `${res.done} host${res.done === 1 ? "" : "s"} done`, res.failed ? "error" : "success");
        data = await get("/api/hosts");
      } catch (err) { toast(err.message || "Could not apply", "error"); }
      busy = false; draw();
    });
    card.appendChild(h("section", { class: "probe-section" }, h("h3", {}, "What the chosen hosts get"),
      h("div", { class: "field" }, h("label", {}, "Level"), level),
      needsMonitorLogin ? h("div", { class: "field" }, h("label", {}, "Login for the basic monitoring"), mon,
        h("p", { class: "hint" }, "A stored login (Settings → Credentials; add one there first if the list is empty). Needed for every host that has no monitor yet. A host is reached over SSH when its SSH port is open, otherwise over WinRM (use a Windows account for those).")) : null,
      needsAdmin ? h("div", { class: "field" }, h("label", {}, "Administrator login for the host (used once)"), adm,
        form.adminCredential ? null : h("div", {}, aUser, aPass),
        h("p", { class: "hint" }, "Only used to put the probe on the host (or take it off). A typed login is never stored or logged; a stored one is used for this run and the use is logged.")) : null,
      needsAdmin ? h("div", { class: "field" }, h("label", { class: "check-row" }, sshd, " Windows: also install the OpenSSH server if it is missing"),
        h("p", { class: "hint" }, "The locked-down probe needs it. Only the probe account may sign in, with one-time certificates, and only this Netlens may reach port 22.")) : null,
      h("div", { class: "form-actions" }, apply)));

    // what was done, host by host, kept out of the table so that the table stays one line per host
    if (results) {
      card.appendChild(h("section", { class: "probe-section" }, h("h3", {}, "What was done"),
        h("p", { class: "hint" }, "Every action is also in the audit log (Settings → Audit log)."),
        ...results.map((r) => h("div", { class: "field" }, h("strong", { class: r.ok ? "" : "error" }, `${r.name}: ${r.ok ? "done" : "failed"}`),
          r.error ? h("p", { class: "error" }, r.error) : null,
          h("ul", { class: "plain hint" }, r.steps.map((t) => h("li", {}, t)))))));
    }
  }
  draw();
  return card;
}
